/* The dependency focus map: one asset at a time, what it relies on (left) and what relies on it (right).
 *
 * The whole-estate graph answers "what is the shape of everything", which nobody asks. An owner asks about one
 * asset: if I replace this, what else must move, and does any of it miss its DST milestone? So the map centres
 * one asset, draws its upstream and downstream from GET /api/dependencies, and re-centres on any node you click.
 * Edge provenance (observed or inferred) is shown on every link. Assets in the same registered system are listed
 * as context, marked "declared", because the estate register says so rather than the scan.
 */
import { useLayoutEffect, useMemo, useRef, useState } from 'react';
import { ArrowRight, Crosshair, ExternalLink, Search } from 'lucide-react';
import { Badge, Button } from './ui';
import { fmt, slack } from '../lib/format';
import { openAsset } from '../lib/router';

const SHOW = 10;

function tone(n) {
  if (!n) return 'neutral';
  if (n.slack_months < 0) return 'late';
  if (n.quantum_vulnerable) return n.slack_months < 12 ? 'tight' : 'ok';
  return 'safe';
}

function Node({ node, relation, derivation, onFocus, refCb }) {
  return (
    <button ref={refCb} type="button" className={`dep-node dep-${tone(node)}`} onClick={() => onFocus(node.id)}
      title={`${node.name}: focus the map here`}>
      <span className="dep-node-name truncate">{node.name}</span>
      <span className="dep-node-meta">
        {relation}{derivation === 'inferred' ? ' · inferred' : ''}{node.dependents ? ` · ${fmt(node.dependents)} rely on it` : ''}
      </span>
    </button>
  );
}

function Column({ title, empty, items, nodes, onFocus, refs }) {
  const [all, setAll] = useState(false);
  const shown = all ? items : items.slice(0, SHOW);
  return (
    <div className="dep-col">
      <div className="dep-col-title">{title} <span className="muted">({fmt(items.length)})</span></div>
      {items.length ? shown.map((x, i) => (
        <Node key={`${x.id}-${x.kind}`} node={nodes.get(x.id)} relation={x.label} derivation={x.derivation}
          onFocus={onFocus} refCb={(el) => { refs.current[i] = el; }} />
      )) : <p className="small muted dep-empty">{empty}</p>}
      {items.length > SHOW && (
        <Button size="sm" variant="quiet" onClick={() => setAll(!all)}>{all ? 'Show fewer' : `Show all ${fmt(items.length)}`}</Button>
      )}
    </div>
  );
}

export default function DependencyFocus({ graph, focusId, onFocus, compact = false }) {
  const { nodes, up, down } = useMemo(() => {
    const byId = new Map(graph.nodes.map((n) => [n.id, n]));
    const upstream = new Map(); const downstream = new Map();
    for (const e of graph.edges) {
      const kind = graph.edge_kinds[e.kind] || { label: e.kind, derivation: 'inferred' };
      if (!upstream.has(e.source)) upstream.set(e.source, []);
      if (!downstream.has(e.target)) downstream.set(e.target, []);
      upstream.get(e.source).push({ id: e.target, kind: e.kind, label: kind.label, derivation: kind.derivation });
      downstream.get(e.target).push({ id: e.source, kind: e.kind, label: kind.label, derivation: kind.derivation });
    }
    return { nodes: byId, up: upstream, down: downstream };
  }, [graph]);
  const [query, setQuery] = useState('');
  const focus = nodes.get(focusId) || graph.nodes[0];
  const relies = (up.get(focus?.id) || []).filter((x) => nodes.has(x.id));
  const reliedOn = (down.get(focus?.id) || []).filter((x) => nodes.has(x.id))
    .sort((a, b) => (nodes.get(a.id).slack_months ?? 99) - (nodes.get(b.id).slack_months ?? 99));

  // Everything that would have to move if the focus were replaced: all transitive dependents.
  const impact = useMemo(() => {
    const seen = new Set(); const queue = [focus?.id];
    while (queue.length) {
      for (const x of down.get(queue.shift()) || []) if (!seen.has(x.id)) { seen.add(x.id); queue.push(x.id); }
    }
    const list = [...seen].map((id) => nodes.get(id)).filter(Boolean);
    return { total: list.length, late: list.filter((n) => n.slack_months < 0).length };
  }, [focus?.id, down, nodes]);

  const peers = focus?.system
    ? graph.nodes.filter((n) => n.system === focus.system && n.id !== focus.id).length : 0;

  // Connector lines: measured from the rendered boxes, so they follow any wrap or resize.
  const box = useRef(null); const centre = useRef(null); const left = useRef([]); const right = useRef([]);
  const [paths, setPaths] = useState([]);
  useLayoutEffect(() => {
    const draw = () => {
      if (!box.current || !centre.current) return;
      const b = box.current.getBoundingClientRect(); const c = centre.current.getBoundingClientRect();
      const mid = (r) => r.top + r.height / 2 - b.top;
      const out = [];
      for (const el of left.current) {
        if (!el) continue;
        const r = el.getBoundingClientRect(); const x1 = r.right - b.left; const x2 = c.left - b.left;
        out.push({ d: `M${x1},${mid(r)} C${(x1 + x2) / 2},${mid(r)} ${(x1 + x2) / 2},${mid(c)} ${x2},${mid(c)}`, cls: el.className });
      }
      for (const el of right.current) {
        if (!el) continue;
        const r = el.getBoundingClientRect(); const x1 = c.right - b.left; const x2 = r.left - b.left;
        out.push({ d: `M${x1},${mid(c)} C${(x1 + x2) / 2},${mid(c)} ${(x1 + x2) / 2},${mid(r)} ${x2},${mid(r)}`, cls: el.className });
      }
      setPaths(out);
    };
    left.current = left.current.slice(0, SHOW * 10); right.current = right.current.slice(0, SHOW * 10);
    draw();
    const ro = new ResizeObserver(draw);
    if (box.current) ro.observe(box.current);
    return () => ro.disconnect();
  }, [focus?.id, relies.length, reliedOn.length]);

  const matches = query.trim().length > 1
    ? graph.nodes.filter((n) => n.name.toLowerCase().includes(query.toLowerCase())).slice(0, 8) : [];
  const anchors = graph.stats?.most_depended_on || [];

  if (!focus) return <p className="muted">Nothing to map yet.</p>;
  return (
    <div className="dep-focus">
      {!compact && (
        <div className="dep-pick">
          <div className="dep-search">
            <Search size={14} aria-hidden />
            <input className="input" placeholder="Focus any asset: type part of its name" value={query}
              onChange={(e) => setQuery(e.target.value)} aria-label="Find an asset to focus" />
            {matches.length > 0 && (
              <ul className="dep-matches" role="listbox">
                {matches.map((n) => (
                  <li key={n.id}><button type="button" className="link-btn" onClick={() => { onFocus(n.id); setQuery(''); }}>{n.name}</button></li>
                ))}
              </ul>
            )}
          </div>
          <div className="row-wrap">
            <span className="xsmall muted">Carries the most:</span>
            {anchors.slice(0, 5).map((a) => (
              <button key={a.id} type="button" className={`chip ${a.id === focus.id ? 'chip-on' : ''}`} onClick={() => onFocus(a.id)}>
                {a.name} <span className="muted">{fmt(a.dependents)}</span>
              </button>
            ))}
          </div>
        </div>
      )}
      <div className="dep-impact">
        <div><div className="dep-impact-n">{fmt(impact.total)}</div><div className="xsmall muted">assets must move if this is replaced</div></div>
        <div><div className={`dep-impact-n ${impact.late ? 'late' : ''}`}>{fmt(impact.late)}</div><div className="xsmall muted">of them already miss their DST milestone</div></div>
        <div><div className="dep-impact-n">{fmt(relies.length)}</div><div className="xsmall muted">things it relies on</div></div>
        {peers > 0 && <div><div className="dep-impact-n">{fmt(peers)}</div><div className="xsmall muted">other assets in system {focus.system} <Badge>declared</Badge></div></div>}
      </div>
      <div className="dep-map" ref={box}>
        <svg className="dep-lines" aria-hidden>
          {paths.map((p, i) => <path key={i} d={p.d} className={`dep-line ${p.cls.split(' ').find((c) => c.startsWith('dep-') && c !== 'dep-node') || ''}`} />)}
        </svg>
        <Column title="It relies on" empty="Nothing upstream was recorded: it depends on no other asset in this estate." items={relies}
          nodes={nodes} onFocus={onFocus} refs={left} />
        <div className="dep-centre-wrap">
          <div ref={centre} className={`dep-centre dep-${tone(focus)}`}>
            <Crosshair size={16} aria-hidden />
            <div className="strong">{focus.name}</div>
            <div className="xsmall">{focus.class_label}{focus.system ? ` · ${focus.system}` : ''}</div>
            <div className="xsmall">{focus.algorithm || '—'}{focus.pqc_replacement ? <> <ArrowRight size={11} aria-hidden /> {focus.pqc_replacement}</> : ''}</div>
            <div className="xsmall">{focus.slack_months != null ? slack(focus.slack_months) : ''}</div>
            <Button size="sm" icon={ExternalLink} onClick={() => openAsset(focus.id)}>Open asset</Button>
          </div>
        </div>
        <Column title="Relies on it" empty="Nothing relies on it: it can be replaced on its own." items={reliedOn}
          nodes={nodes} onFocus={onFocus} refs={right} />
      </div>
      <div className="dep-legend xsmall muted">
        <span><i className="dep-sw dep-late" /> misses its DST milestone</span><span><i className="dep-sw dep-tight" /> under a year of slack</span>
        <span><i className="dep-sw dep-ok" /> vulnerable, time to spare</span><span><i className="dep-sw dep-safe" /> not quantum-vulnerable</span>
        <span>Click any asset to re-centre the map on it.</span>
      </div>
    </div>
  );
}
