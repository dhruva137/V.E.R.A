/* Risk, continued: how the scores are distributed and why the ranking can be
 * trusted, and what risk remains after migrating to post-quantum algorithms.
 *
 *   /heatmap           the estate on its two axes: harvest-now-decrypt-later x trust-now-forge-later
 *   /analytics         score, effort, key-size and verdict distributions, and the H x T scatter
 *   /axis-extremes     the top assets on each axis share no members: why two axes
 *   /sensitivity       rank invariance across survival families and weight changes
 *   /dashboard         composition by algorithm, source and class
 *   /mosca             Mosca categories by system
 *   /pqc-threats(/assessment)  risks that begin or remain after migration
 */

import { useMemo, useState } from 'react';
import { CircleCheck, OctagonX } from 'lucide-react';
import { Badge, Callout, Card, Figure, Load, MoscaBadge, Skeleton, Stacked } from '../components/ui';
import { useResource } from '../lib/data';
import { fmt, fmt1 } from '../lib/format';
import { openAsset } from '../lib/router';

export function Bars({ data, format = fmt, max: maxOverride, tone = 'var(--primary)', limit = 12 }) {
  const rows = Object.entries(data || {}).slice(0, limit);
  const max = maxOverride || Math.max(1, ...rows.map(([, v]) => (typeof v === 'number' ? v : v.count)));
  return (
    <ul className="list-plain" style={{ gap: 0 }}>
      {rows.map(([label, raw]) => {
        const v = typeof raw === 'number' ? raw : raw.count;
        return (
          <li key={label} style={{ display: 'grid', gridTemplateColumns: '9rem 1fr 3.5rem', gap: 'var(--s-3)', alignItems: 'center', padding: '5px 0', borderBottom: 0 }}>
            <span className="small truncate" title={label}>{label}</span>
            <span style={{ height: 10, background: 'var(--surface-3)', borderRadius: 4, overflow: 'hidden' }}>
              <span style={{ display: 'block', height: '100%', width: `${(100 * v) / max}%`, background: tone, borderRadius: 4 }} />
            </span>
            <span className="small num" style={{ textAlign: 'right' }}>{format(v)}</span>
          </li>
        );
      })}
    </ul>
  );
}

function Heatmap({ cells, names }) {
  const [pick, setPick] = useState(null);
  const size = Math.max(...cells.map((c) => Math.max(c.hndl_index, c.tnfl_index))) + 1;
  const max = Math.max(1, ...cells.map((c) => c.count));
  const at = (h, t) => cells.find((c) => c.hndl_index === h && c.tnfl_index === t);
  const hLabels = [...new Set([...cells].sort((a, b) => a.hndl_index - b.hndl_index).map((c) => c.hndl_bucket))];
  const tLabels = [...new Set([...cells].sort((a, b) => a.tnfl_index - b.tnfl_index).map((c) => c.tnfl_bucket))];
  const chosen = pick && at(pick[0], pick[1]);
  return (
    <div className="grid-main-side">
      <div>
        <div style={{ display: 'grid', gridTemplateColumns: `6.5rem repeat(${size}, 1fr)`, gap: 3 }} role="grid" aria-label="Assets by harvest-now and forge-later score">
          {Array.from({ length: size }, (_, row) => size - 1 - row).map((t) => (
            <div key={t} style={{ display: 'contents' }} role="row">
              <span className="xsmall muted" style={{ alignSelf: 'center', textAlign: 'right', paddingRight: 6 }}>T {tLabels[t]}</span>
              {Array.from({ length: size }, (_, h) => {
                const c = at(h, t);
                const n = c?.count || 0;
                return (
                  <button key={h} type="button" role="gridcell" disabled={!n}
                    aria-label={`H ${hLabels[h]}, T ${tLabels[t]}: ${n} assets`} onClick={() => setPick([h, t])}
                    style={{ height: '3.25rem', border: pick && pick[0] === h && pick[1] === t ? '2px solid var(--text)' : '1px solid var(--line)',
                      borderRadius: 6, cursor: n ? 'pointer' : 'default',
                      background: n ? `color-mix(in srgb, var(--primary) ${12 + (70 * n) / max}%, var(--surface))` : 'var(--surface-2)',
                      color: n / max > 0.55 ? '#fff' : 'var(--text)', fontWeight: 600 }}>
                    {n || ''}
                  </button>
                );
              })}
            </div>
          ))}
          <span />
          {hLabels.map((l) => <span key={l} className="xsmall muted" style={{ textAlign: 'center' }}>H {l}</span>)}
        </div>
        <p className="xsmall muted" style={{ marginTop: 'var(--s-2)' }}>Across: harvest-now-decrypt-later (H), confidentiality. Up: trust-now-forge-later (T), integrity. Select a cell to list its assets.</p>
      </div>
      <Card title={chosen ? `${fmt(chosen.count)} assets` : 'Select a cell'} description={chosen ? `H ${chosen.hndl_bucket}, T ${chosen.tnfl_bucket} · mean score ${fmt1(chosen.avg_qirs * 100)}` : 'Each cell counts assets in that score range.'}>
        {chosen && (
          <ul className="list-plain small" style={{ maxHeight: '18rem', overflowY: 'auto' }}>
            {chosen.asset_ids.map((id) => <li key={id}><button type="button" className="link-btn" style={{ textAlign: 'left' }} onClick={() => openAsset(id)}>{names[id] || id}</button></li>)}
          </ul>
        )}
      </Card>
    </div>
  );
}

function Scatter({ points }) {
  const W = 640; const H = 300; const pad = 36;
  const maxH = Math.max(0.05, ...points.map((p) => p.h)); const maxT = Math.max(0.05, ...points.map((p) => p.t));
  const x = (v) => pad + (v / maxH) * (W - pad - 12);
  const y = (v) => H - pad - (v / maxT) * (H - pad - 12);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label={`${points.length} assets by H (across) and T (up)`}>
      <line x1={pad} y1={H - pad} x2={W - 12} y2={H - pad} stroke="var(--line-strong)" />
      <line x1={pad} y1={12} x2={pad} y2={H - pad} stroke="var(--line-strong)" />
      <text x={W - 12} y={H - 10} textAnchor="end" fontSize="11" fill="var(--text-3)">H, confidentiality (max {fmt1(maxH)})</text>
      <text x={8} y={16} fontSize="11" fill="var(--text-3)">T, integrity (max {fmt1(maxT)})</text>
      {points.map((p) => (
        <circle key={p.id} cx={x(p.h)} cy={y(p.t)} r={3 + 6 * p.qirs} fillOpacity="0.55"
          fill={p.vulnerable ? 'var(--warn)' : 'var(--ok)'} stroke={p.vulnerable ? 'var(--warn-text)' : 'var(--ok-text)'}
          style={{ cursor: 'pointer' }} onClick={() => openAsset(p.id)}>
          <title>{p.name}: H {fmt1(p.h * 100)}, T {fmt1(p.t * 100)}</title>
        </circle>
      ))}
    </svg>
  );
}

export function ScoreAnalysis() {
  const heat = useResource('/heatmap');
  const analytics = useResource('/analytics');
  const extremes = useResource('/axis-extremes');
  const sensitivity = useResource('/sensitivity');
  const dashboard = useResource('/dashboard');
  const mosca = useResource('/mosca');
  const inventory = useResource('/inventory');
  const names = useMemo(() => Object.fromEntries((inventory.data?.rows || []).map((r) => [r.id, r.name])), [inventory.data]);
  return (
    <div className="stack-lg">
      <Card title="The estate on two axes" description="Harvest-now-decrypt-later and trust-now-forge-later are scored separately, because they need different fixes.">
        <Load resource={heat} skeleton={<Skeleton height="18rem" />}>{(cells) => <Heatmap cells={cells} names={names} />}</Load>
      </Card>
      <Load resource={extremes} skeleton={<Skeleton height="12rem" />}>
        {(ax) => (
          <Card title="Why one score is not enough" description={ax.interpretation}>
            <div className="grid-2">
              {[['Most exposed to harvest-now-decrypt-later', ax.top_hndl, 'h_score'], ['Most exposed to trust-now-forge-later', ax.top_tnfl, 't_score']].map(([title, rows, k]) => (
                <div key={title}><div className="strong small" style={{ marginBottom: 6 }}>{title}</div>
                  <ol style={{ paddingLeft: '1.2rem' }} className="small">
                    {rows.map((r) => <li key={r.id}><button type="button" className="link-btn" style={{ textAlign: 'left' }} onClick={() => openAsset(r.id)}>{r.name}</button>
                      <span className="muted"> · {fmt1(r[k] * 100)} · X {fmt1(k === 'h_score' ? r.x_c : r.x_i)} yr, Y {fmt1(r.y)} yr</span></li>)}
                  </ol>
                </div>
              ))}
            </div>
          </Card>
        )}
      </Load>
      <Load resource={analytics} skeleton={<Skeleton height="20rem" />}>
        {(a) => (
          <>
            <Card title="Every quantum-vulnerable asset" description="Across: confidentiality score. Up: integrity score. Dot size: overall score. Select a dot to open the asset.">
              <Scatter points={a.scatter} />
            </Card>
            <div className="grid-3">
              <Figure label="Scored mainly on confidentiality" value={fmt(a.axis_dominance.hndl_dominant)} detail="Data that must stay secret outlives the cryptography" />
              <Figure label="Scored mainly on integrity" value={fmt(a.axis_dominance.tnfl_dominant)} detail="Signatures and trust anchors that could be forged" />
              <Figure label="Behind the DST milestone" value={fmt(a.slack_summary.behind)} detail={`${fmt(a.slack_summary.on_track)} on track · ${fmt(a.slack_summary.critical)} critical`} />
            </div>
            <div className="grid-3">
              <Card title="Score distribution"><Bars data={a.risk_distribution} /></Card>
              <Card title="Migration effort"><Bars data={a.effort_distribution} tone="var(--info)" /></Card>
              <Card title="Key sizes"><Bars data={a.key_sizes} tone="var(--text-3)" /></Card>
            </div>
            <Card title="Risk by where it was found" pad={false}>
              <div className="table-wrap"><table className="table">
                <thead><tr><th>Found in</th><th className="r">Assets</th><th className="r">Vulnerable</th><th className="r">Mean score</th></tr></thead>
                <tbody>{Object.entries(a.source_risk).map(([k, v]) => <tr key={k}><td>{k}</td><td className="r num">{fmt(v.count)}</td><td className="r num">{fmt(v.vulnerable)}</td><td className="r num">{fmt1(v.avg_qirs * 100)}</td></tr>)}</tbody>
              </table></div>
            </Card>
          </>
        )}
      </Load>
      <Load resource={sensitivity} skeleton={<Skeleton height="12rem" />}>
        {(s) => {
          const inv = s.invariance;
          return (
            <Card title="Is the ranking stable?" description="The priority order was recomputed under seven unrelated CRQC timeline models and under changed weights."
              actions={inv.summary?.conditional_invariance_holds ? <Badge tone="ok" icon={CircleCheck}>Holds</Badge> : <Badge tone="bad" icon={OctagonX}>Does not hold</Badge>}>
              {inv.sufficient_data ? (
                <div className="stack">
                  <div className="grid-4">
                    <Figure label="Within a stratum (H)" value={fmt1(inv.summary.min_rho_hndl_stratified)} detail="minimum Spearman rho" />
                    <Figure label="Across the estate (H)" value={fmt1(inv.summary.min_rho_hndl_global)} detail="minimum Spearman rho" />
                    <Figure label="Across the estate (T)" value={fmt1(inv.summary.min_rho_tnfl_global)} detail="minimum Spearman rho" />
                    <Figure label="Pairs that can swap" value={`${fmt(inv.summary.worst_case_discordant_pairs)}`} detail={`of ${fmt(inv.summary.total_pairs)} pairs, worst case`} />
                  </div>
                  <p className="small soft">{inv.interpretation?.theorem}</p>
                  {inv.interpretation?.limit_of_the_theorem && <p className="small muted">Limit: {inv.interpretation.limit_of_the_theorem}</p>}
                  {s.weights?.interpretation && <p className="small soft">Weights: {s.weights.interpretation}</p>}
                </div>
              ) : <p className="muted">Not enough vulnerable assets to test.</p>}
            </Card>
          );
        }}
      </Load>
      <div className="grid-2">
        <Load resource={dashboard} skeleton={<Skeleton height="14rem" />}>
          {(d) => <Card title="Algorithms in use"><Bars data={d.by_algorithm} limit={14} /></Card>}
        </Load>
        <Load resource={mosca} skeleton={<Skeleton height="14rem" />}>
          {(m) => (
            <Card title="Mosca categories by system">
              <ul className="list-plain small">
                {Object.entries(m.by_system).map(([sys, cats]) => (
                  <li key={sys} style={{ display: 'grid', gridTemplateColumns: '9rem 1fr', gap: 'var(--s-3)', alignItems: 'center' }}>
                    <span className="truncate">{sys === 'unassigned' ? 'Not in the register' : sys}</span>
                    <Stacked parts={[{ label: 'Exposed', value: cats.certain || 0, tone: 'bad' }, { label: 'Likely', value: cats.likely || 0, tone: 'warn' },
                      { label: 'Possible', value: cats.possible || 0, tone: 'info' }, { label: 'Clear', value: cats.clear || 0, tone: 'ok' },
                      { label: 'Not applicable', value: cats.not_applicable || 0, tone: 'neutral' }]} />
                  </li>
                ))}
              </ul>
              <div className="row-wrap" style={{ marginTop: 'var(--s-3)' }}>{['certain', 'likely', 'possible', 'clear'].map((c) => <MoscaBadge key={c} category={c} />)}</div>
            </Card>
          )}
        </Load>
      </div>
    </div>
  );
}

export function AfterMigration() {
  const threats = useResource('/pqc-threats');
  const assessment = useResource('/pqc-threats/assessment');
  return (
    <div className="stack-lg">
      <Callout tone="info" title="Migration is not the end of the risk.">
        Post-quantum algorithms bring their own failure modes: implementation attacks, agility debt, hybrid misconfiguration. This register tracks
        the ones that apply to this estate, each with its evidence and a date to review it.
      </Callout>
      <Load resource={assessment} skeleton={<Skeleton height="8rem" />}>
        {(a) => (
          <div className="grid-3">
            <Figure label="Already post-quantum" value={fmt(a.already_post_quantum)} detail={`of ${fmt(a.estate_size)} assets`} />
            <Figure label="Still vulnerable" value={fmt(a.still_vulnerable)} detail="to migrate" />
            <Figure label="Threats that apply here" value={fmt(a.applicable_threats.length)} detail={`of ${fmt(a.register_size)} in the register`} />
          </div>
        )}
      </Load>
      <Load resource={threats} skeleton={<Skeleton height="20rem" />}>
        {(t) => (
          <div className="stack">
            {t.threats.map((x) => {
              const hit = assessment.data?.applicable_threats?.find((a) => a.threat === x.key);
              return (
                <Card key={x.key} title={x.title} description={`Applies to: ${x.applies_to}`}
                  actions={<>{hit && <Badge tone="warn">{fmt(hit.exposed_count)} assets here</Badge>}<Badge tone={x.review_overdue ? 'bad' : 'neutral'}>{x.review_overdue ? 'Review overdue' : `Review by ${x.review_by}`}</Badge></>}>
                  <div className="stack small">
                    <p>{x.summary}</p>
                    {hit?.why && <p className="soft"><strong>Here:</strong> {hit.why}</p>}
                    <p><strong>Mitigation:</strong> {x.mitigation}</p>
                    <p className="xsmall muted">Evidence: {Array.isArray(x.evidence) ? x.evidence.join('; ') : x.evidence}</p>
                  </div>
                </Card>
              );
            })}
          </div>
        )}
      </Load>
    </div>
  );
}
