/* Risk: when each primitive breaks, where policy and evidence disagree, and what hangs off what.
 *
 *   Quantum exposure   Mosca per primitive (X + Y > Z), with a what-if on the
 *                      doubling time that never changes the stored scores
 *   Policy drift       rules D1-D8: declared versus observed, side by side
 *   Dependencies       trust anchors ranked by how much of the estate relies on them
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import DependencyFocus from '../components/DependencyFocus';
import TrustGraph from '../components/TrustGraph';
import { ExternalLink, RotateCcw } from 'lucide-react';
import {
  Badge, Button, Callout, Card, Figure, Load, MoscaBadge, PageHead, SeverityBadge, Skeleton, Stacked, Tabs, useSort,
} from '../components/ui';
import { useResource } from '../lib/data';
import { fmt, fmt1, pct } from '../lib/format';
import { useT } from '../lib/prefs';
import { openAsset, useQueryParams } from '../lib/router';
import { AfterMigration, ScoreAnalysis } from './RiskExtras';

const CAT = ['certain', 'likely', 'possible', 'clear'];
const CAT_TONE = { certain: 'bad', likely: 'warn', possible: 'warn', clear: 'ok' };

/* When each primitive's CRQC band falls, against today and the DST milestones. */
function Horizon({ primitives, clock, milestones }) {
  const box = useRef(null);
  const [W, setW] = useState(900);
  useEffect(() => {
    const node = box.current;
    if (!node) return undefined;
    const observer = new ResizeObserver(() => setW(node.clientWidth));
    observer.observe(node);
    setW(node.clientWidth);
    return () => observer.disconnect();
  }, []);
  const now = clock?.now_year || 2026.7;
  const from = Math.floor(now);
  const to = Math.max(from + 16, ...primitives.map((p) => Math.ceil(p.z_calendar.optimistic + 1)));
  const rowH = 30;
  const left = Math.min(260, W * 0.3);
  const marks = [{ label: 'Today', year: now, strong: true }, ...milestones.map((m) => ({ label: `${m.label} ${m.year}`, year: m.year }))];
  const top = 16 * marks.length + 12;
  const H = top + primitives.length * rowH + 28;
  const x = (year) => left + ((year - from) / (to - from)) * (W - left - 12);
  const ticks = [];
  for (let y = from; y <= to; y += 2) ticks.push(y);
  return (
    <div ref={box}>
      <svg width={W} height={H} role="img" style={{ display: 'block' }}
        aria-label={`CRQC arrival band per primitive, ${from} to ${to}. ${primitives.map((p) => `${p.label}: ${fmt1(p.z_calendar.pessimistic)} to ${fmt1(p.z_calendar.optimistic)}, median ${fmt1(p.z_calendar.median)}`).join('; ')}`}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={x(t)} x2={x(t)} y1={top - 4} y2={H - 22} stroke="var(--line)" />
            <text x={x(t)} y={H - 6} textAnchor="middle" fontSize="12" fill="var(--text-3)">{t}</text>
          </g>
        ))}
        {marks.map((m, i) => (
          <g key={m.label}>
            <line x1={x(m.year)} x2={x(m.year)} y1={12 + i * 16} y2={H - 22} stroke={m.strong ? 'var(--text)' : 'var(--primary)'}
              strokeWidth={m.strong ? 1.5 : 1} strokeDasharray={m.strong ? undefined : '3 3'} />
            <text x={x(m.year) + 4} y={12 + i * 16 + 4} fontSize="12" fill={m.strong ? 'var(--text)' : 'var(--primary-text)'}>{m.label}</text>
          </g>
        ))}
        {primitives.map((p, i) => {
          const y = top + i * rowH + rowH / 2;
          return (
            <g key={p.id}>
              <text x={left - 12} y={y + 4} textAnchor="end" fontSize="12.5" fill="var(--text)">
                <title>{p.label}</title>{p.label.length > 30 ? `${p.label.slice(0, 29)}…` : p.label}
              </text>
              <rect x={x(p.z_calendar.pessimistic)} y={y - 7} width={Math.max(2, x(p.z_calendar.optimistic) - x(p.z_calendar.pessimistic))}
                height="14" rx="4" fill="var(--warn-weak)" stroke="var(--warn)" />
              <line x1={x(p.z_calendar.median)} x2={x(p.z_calendar.median)} y1={y - 9} y2={y + 9} stroke="var(--warn-text)" strokeWidth="2.5" />
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function Exposure() {
  const [doubling, setDoubling] = useState(null);
  const risk = useResource(doubling ? `/risk?doubling=${doubling}` : '/risk');
  const regulatory = useResource('/regulatory');
  const [showAll, setShowAll] = useState(false);
  const rows = risk.data?.assets;
  const { sorted, header } = useSort(rows, { key: 'median_margin_years', dir: 'desc' });
  const persona = regulatory.data?.current_org_persona;
  const track = persona && regulatory.data?.deadlines?.[persona];
  const milestones = track ? [
    { label: 'Foundations', year: track.foundation }, { label: 'High-priority', year: track.high_priority }, { label: 'Full', year: track.full },
  ] : [];
  return (
    <Load resource={risk} skeleton={<Skeleton height="30rem" />}>
      {(r) => (
        <div className="stack-lg">
          <div className="grid-4">
            {CAT.map((c) => (
              <Figure key={c} label={<MoscaBadge category={c} />} value={fmt(r.totals[c])}
                detail={{ certain: 'X + Y exceeds even the latest CRQC estimate', likely: 'Exceeds the median estimate',
                  possible: 'Exceeds only the earliest estimate', clear: 'Migrates in time on every reading' }[c]} />
            ))}
          </div>
          <Card title="When each primitive breaks"
            description={`CRQC arrival band per primitive (earliest to latest estimate, median marked). Threat model ${r.threat_model_version}.`}
            actions={(
              <div className="row">
                <label htmlFor="doubling" className="small soft nowrap">Doubling time D</label>
                <input id="doubling" type="range" min="0.5" max="6" step="0.5" value={doubling || r.default_doubling_years}
                  onChange={(e) => setDoubling(Number(e.target.value) === r.default_doubling_years ? null : Number(e.target.value))}
                  aria-valuetext={`${doubling || r.default_doubling_years} years`} />
                <span className="small strong num" style={{ width: '3rem' }}>{fmt1(doubling || r.default_doubling_years)} yr</span>
                {doubling && <Button size="sm" variant="quiet" icon={RotateCcw} onClick={() => setDoubling(null)}>Reset</Button>}
              </div>
            )}>
            {r.what_if && <Callout tone="info" title="What-if view">The categories below use D = {fmt1(r.doubling_years)} years. Stored scores, exports and the Overview still use {fmt1(r.default_doubling_years)} years.</Callout>}
            <Horizon primitives={r.primitives} clock={r.clock} milestones={milestones} />
            <p className="xsmall muted">Band: survival ensemble from the Global Risk Institute Quantum Threat Timeline, shifted per primitive by its published logical-qubit estimate. Dashed lines: 1 January of each DST milestone year for {persona}, the date V.E.R.A. plans against.</p>
          </Card>
          <Card title="Primitives in use" pad={false}>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Primitive</th><th className="r">Logical qubits</th><th>Estimate from</th><th className="r">Median year</th><th className="r">Assets</th><th style={{ width: '24%' }}>Categories</th></tr></thead>
                <tbody>
                  {r.primitives.map((p) => (
                    <tr key={p.id}>
                      <td className="strong">{p.label}</td>
                      <td className="r num">{fmt(p.logical_qubits)}</td>
                      <td className="small">{p.url ? <a href={p.url} target="_blank" rel="noreferrer noopener">{p.source}<ExternalLink size={11} style={{ display: 'inline', marginLeft: 3 }} aria-hidden /></a> : p.source}</td>
                      <td className="r num">{fmt1(p.z_calendar.median)}</td>
                      <td className="r num">{fmt(p.assets)}</td>
                      <td><Stacked parts={CAT.map((c) => ({ label: c, value: p.by_category[c] || 0, tone: CAT_TONE[c] }))} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <Card title="Every asset's Mosca margin" description="Margin = CRQC median − (X + Y). Negative means the data or trust outlives the cryptography."
            pad={false} footer={sorted.length > 40 && <Button size="sm" variant="quiet" onClick={() => setShowAll(!showAll)}>{showAll ? 'Show the first 40' : `Show all ${fmt(sorted.length)}`}</Button>}>
            <div className="table-wrap">
              <table className="table">
                <thead><tr>{header('name', 'Asset')}{header('system', 'System')}{header('category', 'Category')}{header('x_years', 'X', { align: 'right' })}
                  {header('y_years', 'Y', { align: 'right' })}{header('median_margin_years', 'Margin', { align: 'right' })}{header('deadline_year', 'DST', { align: 'right' })}</tr></thead>
                <tbody>
                  {(showAll ? sorted : sorted.slice(0, 40)).map((a) => (
                    <tr key={a.id} data-clickable tabIndex={0} onClick={() => openAsset(a.id)} onKeyDown={(e) => e.key === 'Enter' && openAsset(a.id)}>
                      <td><div className="strong truncate" style={{ maxWidth: '28rem' }}>{a.name}</div><div className="xsmall muted">{a.primitive}</div></td>
                      <td>{a.system || '—'}</td>
                      <td><MoscaBadge category={a.category} /></td>
                      <td className="r num">{fmt1(a.x_years)}</td>
                      <td className="r num">{fmt1(a.y_years)}</td>
                      <td className="r num strong" style={{ color: a.median_margin_years > 0 ? 'var(--bad-text)' : undefined }}>
                        {a.median_margin_years > 0 ? `−${fmt1(a.median_margin_years)}` : `+${fmt1(-a.median_margin_years)}`} yr</td>
                      <td className="r num">{a.deadline_year}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}
    </Load>
  );
}

function Side({ title, side }) {
  return (
    <div className="stack" style={{ gap: 2 }}>
      <span className="xsmall muted">{title} · {side.plane}</span>
      <span className="small strong">{side.summary}</span>
      <code className="xsmall muted break">{side.location}</code>
    </div>
  );
}

function Drift() {
  const drift = useResource('/drift');
  const [rule, setRule] = useState(null);
  return (
    <Load resource={drift} skeleton={<Skeleton height="30rem" />}>
      {(d) => {
        const records = rule ? d.records.filter((r) => r.rule === rule) : d.records;
        return (
          <div className="stack-lg">
            <p className="soft">Drift is where what the organisation declared (configuration, the estate register, key stores) and
              what the scan observed disagree. Each rule compares two evidence planes.</p>
            <div className="row-wrap">
              <button type="button" className="btn btn-sm" aria-pressed={!rule} onClick={() => setRule(null)}>All {fmt(d.records.length)}</button>
              {d.summary.rules.map((r) => (
                <button key={r.id} type="button" className="btn btn-sm" aria-pressed={rule === r.id} onClick={() => setRule(rule === r.id ? null : r.id)}
                  title={r.title}>{r.id} <span className="muted">{fmt(d.summary.by_rule[r.id] || 0)}</span></button>
              ))}
            </div>
            {!records.length && <Callout tone="ok" title="No drift under this rule." />}
            {records.map((r) => (
              <Card key={r.id} title={`${r.rule} · ${r.title}`} description={r.subject} actions={<SeverityBadge level={r.severity} />}>
                <div className="stack">
                  <div className="grid-2">
                    <Side title="Declared" side={r.declared} />
                    <Side title="Observed" side={r.observed} />
                  </div>
                  <p className="small soft">{r.explain}</p>
                  <div className="row-wrap">
                    {r.declared?.asset_id && <Button size="sm" onClick={() => openAsset(r.declared.asset_id)}>Open what was declared</Button>}
                    {r.observed?.asset_id && <Button size="sm" onClick={() => openAsset(r.observed.asset_id)}>Open what was observed</Button>}
                    {!r.declared?.asset_id && !r.observed?.asset_id && (r.asset_ids || []).map((id, i) => (
                      <Button key={id} size="sm" onClick={() => openAsset(id)}>Open asset {i + 1}</Button>
                    ))}
                  </div>
                </div>
              </Card>
            ))}
            <Card title="The rules">
              <ul className="list-plain small">
                {d.summary.rules.map((r) => <li key={r.id}><strong>{r.id} · {r.title}</strong> <SeverityBadge level={r.severity} /></li>)}
              </ul>
            </Card>
          </div>
        );
      }}
    </Load>
  );
}

function Dependencies() {
  const graph = useResource('/dependencies');
  const [params, setParams] = useQueryParams();
  const [whole, setWhole] = useState(false);
  const readiness = useResource('/readiness');
  const anchors = useMemo(() => (graph.data?.nodes || []).filter((n) => n.dependents > 0)
    .sort((a, b) => b.dependents - a.dependents), [graph.data]);
  const total = graph.data?.nodes?.length || 1;
  return (
    <Load resource={graph} skeleton={<Skeleton height="30rem" />}>
      {(g) => (
        <div className="stack-lg">
          {readiness.data?.concentration?.top?.[0] && (
            <Callout tone={readiness.data.concentration.worst_pct >= 20 ? 'warn' : 'info'}
              title={`One anchor carries ${pct(readiness.data.concentration.worst_pct)} of the estate.`}>
              If {readiness.data.concentration.top[0].name} were forged or had to be replaced, {fmt(readiness.data.concentration.top[0].dependents)} assets
              would need re-issuing or re-trusting. Plan anchors first: everything under them moves with them.
            </Callout>
          )}
          <Card title="Dependency map" description="One asset at a time: what it relies on, what relies on it, and what has to move if it is replaced. Start from the anchor that carries the most, or search any asset."
            actions={<Button size="sm" variant="quiet" onClick={() => setWhole(!whole)}>{whole ? 'Hide the whole-estate graph' : 'Show the whole-estate graph'}</Button>}>
            <DependencyFocus graph={g} focusId={params.get('focus') || g.stats?.most_depended_on?.[0]?.id}
              onFocus={(id) => setParams({ focus: id })} />
          </Card>
          {whole && (
            <Card title="Whole-estate graph" description="Every asset and relationship at once. Colour is slack against the DST milestone; click a node to open it." pad={false}>
              <TrustGraph data={g} onOpen={openAsset} />
            </Card>
          )}
          <Card title="Trust anchors, by how much relies on them" description={`${fmt(g.stats.edges)} relationships: ${fmt(g.stats.observed_edges)} read from certificates and endpoints, ${fmt(g.stats.inferred_edges)} inferred.`} pad={false}>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Asset</th><th>Type</th><th>Algorithm</th><th className="r">Relied on by</th><th style={{ width: '18%' }}>Share of estate</th><th className="r">Evidence</th></tr></thead>
                <tbody>
                  {anchors.slice(0, 30).map((n) => (
                    <tr key={n.id} data-clickable tabIndex={0} onClick={() => openAsset(n.id)} onKeyDown={(e) => e.key === 'Enter' && openAsset(n.id)}>
                      <td className="strong">{n.name}</td>
                      <td className="small">{n.class_label}</td>
                      <td>{n.algorithm || '—'} {n.quantum_vulnerable && <Badge tone="warn">vulnerable</Badge>}</td>
                      <td className="r num strong">{fmt(n.dependents)}</td>
                      <td><div className="row"><div className="grow"><Stacked parts={[{ label: 'relies on it', value: n.dependents, tone: 'primary' }, { label: 'rest', value: total - n.dependents, tone: 'neutral' }]} /></div>
                        <span className="xsmall num" style={{ width: '3rem', textAlign: 'right' }}>{pct((100 * n.dependents) / total)}</span></div></td>
                      <td className="r num">{fmt1(n.confidence * 100)}%</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <Card title="How relationships are found">
            <ul className="list-plain small">
              {Object.entries(g.edge_kinds).map(([key, k]) => (
                <li key={key}><strong>{k.label}</strong> <Badge tone={k.derivation === 'observed' ? 'ok' : 'neutral'}>{k.derivation}</Badge>
                  <span className="soft"> {k.description}</span></li>
              ))}
            </ul>
          </Card>
        </div>
      )}
    </Load>
  );
}

export default function Risk({ route, hasScan }) {
  const t = useT();
  const tab = ['exposure', 'drift', 'dependencies', 'scores', 'after'].includes(route.segments[1]) ? route.segments[1] : 'exposure';
  const Body = { exposure: Exposure, drift: Drift, dependencies: Dependencies, scores: ScoreAnalysis, after: AfterMigration }[tab];
  return (
    <div className="page">
      <PageHead title={t('nav.risk')} description="When the cryptography breaks, where declared policy and the evidence disagree, and what relies on what." />
      <Tabs label="Risk views" active={tab} items={[
        { key: 'exposure', label: t('risk.exposure'), to: '/risk/exposure' },
        { key: 'drift', label: t('risk.drift'), to: '/risk/drift' },
        { key: 'dependencies', label: t('risk.dependencies'), to: '/risk/dependencies' },
        { key: 'scores', label: t('risk.scores'), to: '/risk/scores' },
        { key: 'after', label: t('risk.after'), to: '/risk/after' },
      ]} />
      {hasScan ? <Body /> : <Callout tone="info" title="Nothing scanned yet.">Run a scan first.</Callout>}
    </div>
  );
}
