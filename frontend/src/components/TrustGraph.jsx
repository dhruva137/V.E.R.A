/* The trust graph: every asset and what relies on it, laid out by force, coloured by Mosca slack.
 *
 * Data is /dependencies unchanged (a projection of the scored estate, not a second model). Node size is how
 * many assets transitively depend on it; colour is its slack against its DST milestone (late / tight / on
 * track / not quantum-vulnerable), always with the legend in words. Solid edges were read from certificates
 * and endpoints; dashed ones are inferred. Hover shows a node's neighbourhood, click opens the asset, drag
 * and wheel pan and zoom. The ranked table under the graph is the keyboard and screen-reader view.
 * d3-force is bundled; nothing is fetched.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from 'd3-force';
import { select } from 'd3-selection';
import { zoom, zoomIdentity } from 'd3-zoom';

const W = 1100;
const H = 620;

const SLACK = [
  { key: 'late', label: 'Late for its DST milestone', tone: 'bad' },
  { key: 'tight', label: 'Under 12 months of slack', tone: 'warn' },
  { key: 'ok', label: 'On track', tone: 'ok' },
  { key: 'safe', label: 'Not quantum-vulnerable', tone: 'neutral' },
];

function slackKey(n) {
  if (!n.quantum_vulnerable) return 'safe';
  if (n.slack_months == null) return 'tight';
  if (n.slack_months < 0) return 'late';
  if (n.slack_months < 12) return 'tight';
  return 'ok';
}

const radius = (n) => 3.5 + Math.sqrt(n.dependents || 0) * 2.2;

function layout(nodes, edges) {
  const ns = nodes.map((n) => ({ ...n }));
  const ids = new Set(ns.map((n) => n.id));
  const es = edges.filter((e) => ids.has(e.source) && ids.has(e.target)).map((e) => ({ ...e }));
  const systems = [...new Set(ns.map((n) => n.system || 'shared'))];
  const angle = new Map(systems.map((s, i) => [s, (2 * Math.PI * i) / systems.length]));
  const sim = forceSimulation(ns)
    .force('link', forceLink(es).id((d) => d.id).distance((e) => (e.kind === 'trust-anchor' ? 70 : 38)).strength(0.35))
    .force('charge', forceManyBody().strength(-38))
    .force('collide', forceCollide().radius((d) => radius(d) + 2))
    .force('x', forceX((d) => W / 2 + Math.cos(angle.get(d.system || 'shared')) * 260).strength(0.06))
    .force('y', forceY((d) => H / 2 + Math.sin(angle.get(d.system || 'shared')) * 190).strength(0.06))
    .force('center', forceCenter(W / 2, H / 2))
    .stop();
  for (let i = 0; i < 320; i += 1) {                  // settle once, then render still: no looping motion
    sim.tick();
    ns.forEach((n) => {                                 // keep every node (and its label start) on the canvas
      const r = radius(n) + 8;
      n.x = Math.max(r, Math.min(W - r - 120, n.x));
      n.y = Math.max(r, Math.min(H - r, n.y));
    });
  }
  return { nodes: ns, edges: es };
}

export default function TrustGraph({ data, onOpen }) {
  const [system, setSystem] = useState('all');
  const [observedOnly, setObservedOnly] = useState(false);
  const [vulnerableOnly, setVulnerableOnly] = useState(false);
  const [hover, setHover] = useState(null);
  const svgRef = useRef(null);
  const gRef = useRef(null);

  const systems = useMemo(() => [...new Set(data.nodes.map((n) => n.system).filter(Boolean))].sort(), [data]);
  const filtered = useMemo(() => {
    const keep = data.nodes.filter((n) => (system === 'all' || n.system === system || !n.system)
      && (!vulnerableOnly || n.quantum_vulnerable || n.dependents > 0));
    const ids = new Set(keep.map((n) => n.id));
    const edges = data.edges.filter((e) => ids.has(e.source) && ids.has(e.target)
      && (!observedOnly || data.edge_kinds[e.kind]?.derivation === 'observed'));
    const linked = new Set(edges.flatMap((e) => [e.source, e.target]));
    return { nodes: keep.filter((n) => linked.has(n.id) || n.dependents > 0 || system !== 'all'), edges };
  }, [data, system, observedOnly, vulnerableOnly]);
  const g = useMemo(() => layout(filtered.nodes, filtered.edges), [filtered]);
  const neighbours = useMemo(() => {
    if (!hover) return null;
    const s = new Set([hover.id]);
    g.edges.forEach((e) => {
      if (e.source.id === hover.id) s.add(e.target.id);
      if (e.target.id === hover.id) s.add(e.source.id);
    });
    return s;
  }, [hover, g]);

  useEffect(() => {
    const svg = select(svgRef.current);
    const z = zoom().scaleExtent([0.5, 6]).on('zoom', (ev) => select(gRef.current).attr('transform', ev.transform));
    svg.call(z).on('dblclick.zoom', null);
    svg.call(z.transform, zoomIdentity);
    return () => svg.on('.zoom', null);
  }, [g]);

  const counts = useMemo(() => {
    const c = { late: 0, tight: 0, ok: 0, safe: 0 };
    g.nodes.forEach((n) => { c[slackKey(n)] += 1; });
    return c;
  }, [g]);
  // Labels for the most relied-on anchors, nudged apart vertically so none sits on another.
  const labelY = useMemo(() => {
    const chosen = [...g.nodes].sort((a, b) => b.dependents - a.dependents).slice(0, 4).sort((a, b) => a.y - b.y);
    const out = new Map();
    let last = -Infinity;
    chosen.forEach((n) => {
      const y = Math.max(n.y + 4, last + 14);
      out.set(n.id, y - n.y);
      last = y;
    });
    return out;
  }, [g]);

  return (
    <div className="trust-graph">
      <div className="row-wrap trust-graph-controls">
        <label className="field-inline">
          <span className="small soft">System</span>
          <select className="select" value={system} onChange={(e) => setSystem(e.target.value)}>
            <option value="all">All systems</option>
            {systems.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label className="check small"><input type="checkbox" checked={observedOnly} onChange={(e) => setObservedOnly(e.target.checked)} />
          Only relationships read from evidence</label>
        <label className="check small"><input type="checkbox" checked={vulnerableOnly} onChange={(e) => setVulnerableOnly(e.target.checked)} />
          Hide assets that are safe and relied on by nothing</label>
        <span className="grow" />
        <span className="xsmall muted">{g.nodes.length} assets · {g.edges.length} relationships · scroll to zoom, drag to pan</span>
      </div>
      <div className="trust-graph-canvas">
        <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} role="img"
          aria-label={`Trust graph of ${g.nodes.length} assets: ${counts.late} late for their milestone, ${counts.tight} with under 12 months of slack. The table below lists the same anchors.`}>
          <g ref={gRef}>
            {g.edges.map((e, i) => {
              const dim = neighbours && !(neighbours.has(e.source.id) && neighbours.has(e.target.id));
              const observed = data.edge_kinds[e.kind]?.derivation === 'observed';
              return (
                <line key={i} x1={e.source.x} y1={e.source.y} x2={e.target.x} y2={e.target.y}
                  className={`tg-edge ${observed ? 'tg-observed' : 'tg-inferred'}`} opacity={dim ? 0.06 : 1} />
              );
            })}
            {g.nodes.map((n) => {
              const dim = neighbours && !neighbours.has(n.id);
              return (
                <g key={n.id} transform={`translate(${n.x},${n.y})`} className="tg-node" opacity={dim ? 0.18 : 1}
                  onMouseEnter={() => setHover(n)} onMouseLeave={() => setHover(null)} onClick={() => onOpen(n.id)}>
                  <circle r={radius(n) + 6} className="tg-hit" />
                  <circle r={radius(n)} className={`tg-dot tg-${slackKey(n)}`} />
                  {(labelY.has(n.id) || hover?.id === n.id) && (
                    <text x={radius(n) + 4} y={labelY.get(n.id) ?? 4} className="tg-label">{n.name.length > 34 ? `${n.name.slice(0, 33)}…` : n.name}</text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
        {hover && (
          <div className="tg-tip" role="status">
            <strong>{hover.name}</strong>
            <span>{hover.class_label}{hover.algorithm ? ` · ${hover.algorithm}` : ''}</span>
            <span>{SLACK.find((s) => s.key === slackKey(hover)).label}
              {hover.slack_months != null && hover.quantum_vulnerable ? ` (${Math.round(hover.slack_months)} months)` : ''}</span>
            <span>{hover.dependents} assets rely on it · {hover.system || 'shared'}</span>
          </div>
        )}
      </div>
      <ul className="tg-legend" aria-label="Legend">
        {SLACK.map((s) => (
          <li key={s.key}><span className={`tg-swatch tg-${s.key}`} aria-hidden />{s.label} <span className="muted num">{counts[s.key]}</span></li>
        ))}
        <li><span className="tg-line tg-observed" aria-hidden />Read from evidence</li>
        <li><span className="tg-line tg-inferred" aria-hidden />Inferred</li>
        <li className="muted">Size: how many assets rely on it</li>
      </ul>
    </div>
  );
}
