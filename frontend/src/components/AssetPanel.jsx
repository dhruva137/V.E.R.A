/* The asset panel: where exactly it is, and what the fix is (the engineer's question).
 *
 * Opens over any screen from ?asset=<id>, so a link to one asset can be shared
 * and the screen behind keeps its filters and scroll position. Six sections,
 * each answered by the engine that owns it (GET /api/assets/{id}/panel).
 */

import { ArrowLeft, ExternalLink, FileText, GitBranch, History, KeyRound, Maximize2, Minimize2, ShieldAlert, Wrench } from 'lucide-react';
import { useResource } from '../lib/data';
import DependencyFocus from './DependencyFocus';
import { date, dateTime, fmt, fmt1, money, slack, years } from '../lib/format';
import { useT } from '../lib/prefs';
import { Link, openAsset, useQueryParams } from '../lib/router';
import {
  Badge, Button, Callout, Drawer, Kv, LocalTabs, Load, Meter, MoscaBadge, PageHead, SeverityBadge, Skeleton, StatusBadge,
  Tabs,
} from './ui';

const TABS = ['summary', 'evidence', 'risk', 'fix', 'dependencies', 'history'];
const PLANES = { declared: 'Declared (configuration)', built: 'Built (code, binaries, images)', held: 'Held (keystores, HSM, KMS)', observed: 'Observed (on the wire)' };

function Summary({ p }) {
  const s = p.summary;
  return (
    <div className="stack-lg">
      <div className="row-wrap">
        <StatusBadge status={s.status} />
        {s.detection && !s.algorithm
          /* Certified crypto whose algorithm is not yet named has no quantum verdict: not "safe", it needs a look. */
          ? <Badge tone="warn">Needs review: algorithm not yet named</Badge>
          : <><SeverityBadge level={s.risk_level} /><MoscaBadge category={p.risk.mosca?.category} /></>}
        {s.slack_months < 0 && p.fix.need && <Badge tone="bad">Misses its DST milestone</Badge>}
      </div>
      {s.reason && <p className="soft">{s.reason}</p>}
      <Kv rows={[
        ['Algorithm', s.algorithm ? `${s.algorithm}${s.key_size ? ` · ${s.key_size} bits` : ''}` : 'Not resolved'],
        ['Mode', s.mode ? `${s.mode.toUpperCase()}${s.padding ? ` · ${s.padding} padding` : ''}` : null],
        ['Version', s.version ? `${s.version}${s.version_source ? ` (from ${s.version_source})` : ''}` : null],
        ['What it is', s.class_label],
        ['System', s.system || 'Not in the estate register'],
        ['Owner', s.owner],
        ['Where', <code key="loc" className="break">{s.location}</code>],
        ['Exposure', s.exposure ? `${s.exposure}${s.exposure_basis ? ` (${s.exposure_basis})` : ''}` : null],
        ['Criticality', s.criticality],
        ['Data it protects', s.data_classes?.length ? s.data_classes.join(', ').replace(/_/g, ' ') : null],
        ['DST milestone', `${s.phase === 'high_priority' ? 'High-priority migration' : 'Full migration'}, ${s.deadline_year} (planned against 1 Jan ${s.deadline_year})`],
        ['Time', p.fix.need ? slack(s.slack_months) : 'Nothing to migrate'],
        ['Priority', s.priority_rank ? `#${s.priority_rank} in this estate` : null],
        ['Replace with', s.replacement],
        ['Expires', s.expiry_days !== null && s.expiry_days !== undefined ? `${fmt(s.expiry_days)} days (${s.expiry_band})` : null],
      ]} />
      {s.phase_reason && <p className="small muted">Why this milestone: {s.phase_reason}</p>}
      {s.detection && (
        <div className="card card-pad">
          <div className="row" style={{ marginBottom: 'var(--s-2)' }}>
            <ShieldAlert size={16} aria-hidden />
            <span className="strong small">Certified detection</span>
            <Badge tone="info">q = {s.detection.q_value?.toFixed(3)}</Badge>
          </div>
          <p className="small soft">Found with no symbol, import or constant table to go on. At a false-discovery level of
            α = {s.detection.alpha}, at most that share of such findings is expected to be wrong; this one is still selected
            at q = {s.detection.q_value?.toFixed(3)}.</p>
          <Kv rows={[
            ['Method', s.detection.method],
            ['Instruction set', s.detection.isa],
            ['Functions', `${fmt(s.detection.functions_selected)} selected of ${fmt(s.detection.functions_scored)} scored`],
            ['Selected', s.detection.selected_functions.slice(0, 5).map((f) => `${f.name || f.address} (q ${f.q_value.toFixed(3)})`).join(', ')],
          ]} />
        </div>
      )}
      {s.certificate && (
        <div className="card card-pad">
          <div className="strong small" style={{ marginBottom: 'var(--s-2)' }}>Certificate</div>
          <Kv rows={[['Subject', s.certificate.subject], ['Issuer', s.certificate.issuer],
            ['Valid from', date(s.certificate.not_before)], ['Valid to', date(s.certificate.not_after)], ['Serial', s.certificate.serial]]} />
        </div>
      )}
    </div>
  );
}

function Evidence({ p }) {
  const e = p.evidence;
  return (
    <div className="stack-lg">
      <div className="stack">
        <div className="row"><span className="strong">Confidence {fmt1(e.confidence * 100)}%</span>
          <span className="small muted">from {e.sources.join(', ') || 'no sensor'}</span></div>
        <Meter value={e.confidence} tone={e.confidence >= 0.6 ? 'ok' : 'warn'} label="Evidence confidence" />
        {e.flagged && <Callout tone="warn" title="Verify this asset">{e.flag_reason}</Callout>}
      </div>
      <div className="stack">
        <div className="strong">Evidence planes</div>
        {Object.entries(e.planes).map(([plane, value]) => (
          <div key={plane} className="row"><span className="grow small">{PLANES[plane] || plane}</span>
            <span className="small num">{fmt1(value * 100)}%</span></div>
        ))}
        {Object.keys(e.planes).length < 2 && <p className="small muted">Seen on one plane only. A second plane (for example the live endpoint) would confirm it.</p>}
      </div>
      <div className="stack">
        <div className="strong">Where it was found</div>
        <ul className="list-plain">
          {e.refs.map((ref, i) => (
            <li key={i} className="stack" style={{ gap: 'var(--s-1)' }}>
              <code className="small break">{ref.location}{ref.line ? `:${ref.line}` : ''}</code>
              <span className="xsmall muted">{ref.collector}{ref.layer ? ` · layer ${ref.layer.slice(0, 19)}` : ''}{ref.digest ? ` · ${ref.digest.slice(0, 19)}…` : ''}</span>
            </li>
          ))}
          {!e.refs.length && <li className="small muted">The collector recorded no file reference.</li>}
        </ul>
      </div>
      {e.drift.length > 0 && (
        <div className="stack">
          <div className="strong">Policy drift on this asset</div>
          {e.drift.map((d) => (
            <Callout key={d.id} tone={d.severity === 'critical' ? 'bad' : 'warn'} title={`${d.rule} · ${d.title}`}>{d.explain}</Callout>
          ))}
        </div>
      )}
      <p className="xsmall muted">Metadata only: V.E.R.A. records where key material is, never the key itself.</p>
    </div>
  );
}

function Risk({ p }) {
  const m = p.risk.mosca || {};
  const d = p.risk.derivation || {};
  if (!m.applicable) {
    return <Callout tone="ok" title="Mosca does not apply">{m.explanation || 'This asset does not rest on a problem a quantum computer breaks.'}</Callout>;
  }
  return (
    <div className="stack-lg">
      <div className="stack">
        <MoscaBadge category={m.category} />
        <p>{m.explanation}</p>
      </div>
      <div className="grid-3">
        <div className="card card-pad"><div className="small muted">X · how long it must hold</div>
          <div className="strong" style={{ fontSize: 'var(--fs-18)' }}>{years(m.axis === 'integrity' ? m.x_i : m.x_c)}</div>
          <div className="xsmall muted">{m.x_basis?.source}</div></div>
        <div className="card card-pad"><div className="small muted">Y · until migrated</div>
          <div className="strong" style={{ fontSize: 'var(--fs-18)' }}>{years(m.y_plan)}</div>
          <div className="xsmall muted">{m.y_plan > m.y_effort + 0.05
            ? `Finishing on the DST schedule; the work itself takes ${years(m.y_effort)}`
            : m.vendor_gated ? `Includes ${years(m.vendor_lead_years)} supplier lead time` : 'The migration effort for this class of asset'}</div></div>
        <div className="card card-pad"><div className="small muted">Z · years to a CRQC</div>
          <div className="strong nowrap" style={{ fontSize: 'var(--fs-18)' }}>{fmt1(m.z?.pessimistic)}–{fmt1(m.z?.optimistic)} yr</div>
          <div className="xsmall muted">Median {fmt1(m.z?.median)} yr, for this primitive</div></div>
      </div>
      <p className="small soft">X + Y = {years(m.horizon_years)}.{' '}
        {m.margin_years?.median > 0
          ? `That outlasts the median CRQC estimate by ${years(m.margin_years.median)}`
          : `That ends ${years(-(m.margin_years?.median ?? 0))} before the median CRQC estimate`}
        {m.starting_now_helps ? '; starting now changes the outcome.' : '.'}</p>
      {m.z_shift?.basis && <p className="xsmall muted">Primitive shift: {m.z_shift.basis}</p>}
      <div className="stack">
        <div className="strong">How the priority score was derived</div>
        <p className="xsmall muted">The priority score ranks assets against each other. It uses the migration effort for Y, not the DST schedule used above.</p>
        {[d.hndl, d.tnfl].filter(Boolean).map((part) => (
          <div key={part.formula} className="code-block">{part.formula}{'\n'}{part.horizon_expression}{'\n'}{part.substitution}</div>
        ))}
        <ul className="list-plain">
          {(d.inputs || []).map((input) => (
            <li key={input.symbol} className="row small"><code>{input.symbol}</code><span className="num">{input.value} {input.unit || ''}</span>
              <span className="muted grow">{input.meaning}</span></li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Fix({ p }) {
  const f = p.fix;
  if (!f.need) return <Callout tone="ok" title="Nothing to change">{f.why}</Callout>;
  const cost = f.cost_estimate;
  return (
    <div className="stack-lg">
      <div className="card card-pad stack" style={{ gap: 'var(--s-2)' }}>
        <div className="small muted">{f.need_label}</div>
        <div className="strong" style={{ fontSize: 'var(--fs-18)' }}>{f.recommended}</div>
        <p className="small soft">{f.why} {f.rationale}</p>
        {f.alternatives?.length > 0 && <p className="small">Alternatives: {f.alternatives.join(', ')}</p>}
      </div>
      <Kv rows={[
        ['Who can fix it', f.who_can_fix?.owner || f.who_can_fix?.key],
        ['What they do', f.who_can_fix?.action],
        ['Evidence', f.who_can_fix?.evidence],
        ['Effort', `${f.effort?.label} (${years(f.effort?.years)})`],
        ['Cost share', cost ? `${fmt1(cost.person_days)} person-days${cost.shared_with ? `, one change shared with ${cost.shared_with} other asset(s)` : ''}${cost.cost !== null ? ` · ${money(cost.cost)}` : ''}` : null],
      ]} />
      {f.prerequisites?.length > 0 && (
        <Callout tone="warn" title="Do this first">
          <ul style={{ paddingLeft: '1.1rem' }}>{f.prerequisites.map((x) => <li key={x.step}>{x.step}: {x.why}</li>)}</ul>
        </Callout>
      )}
      {f.cost?.latency && (
        <div className="stack">
          <div className="strong">Measured on this machine</div>
          <ul className="list-plain small">
            {(Array.isArray(f.cost.latency) ? f.cost.latency : []).map((l, i) => (
              <li key={i}>{l.algorithm} {l.operation}: {fmt1(l.microseconds)} µs</li>
            ))}
          </ul>
          {f.cost.latency_note && <p className="xsmall muted">{f.cost.latency_note}</p>}
        </div>
      )}
      <div className="stack">
        <div className="strong">Sources</div>
        <ul className="list-plain small">
          {(f.citations || []).map((c) => (
            <li key={c.id}>{c.label}{c.url && <> · <a href={c.url} target="_blank" rel="noreferrer noopener">{new URL(c.url).hostname}<ExternalLink size={12} style={{ display: 'inline', marginLeft: 4 }} aria-hidden /></a></>}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function Dependencies({ p }) {
  const graph = useResource('/dependencies');
  return (
    <Load resource={graph} skeleton={<Skeleton height="20rem" />}>
      {(g) => <DependencyFocus graph={g} focusId={p.id} onFocus={(id) => (id === p.id ? null : openAsset(id))} compact />}
    </Load>
  );
}

/* Every stage the engine applied to this asset, with the formula, the values substituted into it and the result
   (GET /api/engine/asset/{id}): the drill-down that lets an assessor re-derive any number on screen. */
function Trace({ id }) {
  const res = useResource(`/engine/asset/${id}`);
  return (
    <div className="stack">
      <div className="strong">How the engine processed this asset</div>
      <Load resource={res} skeleton={<Skeleton lines={4} />}>
        {(tr) => (
          <ol className="list-plain stack">
            {(tr.traversal || []).map((step, i) => (
              <li key={`${step.stage}-${i}`} className="stack" style={{ gap: 'var(--s-1)' }}>
                <div className="row small"><Badge tone="neutral">{step.stage}</Badge><span className="strong">{step.title}</span></div>
                {step.formula && <div className="code-block">{step.formula}{step.substitution ? `
${step.substitution}` : ''}{step.result ? `
= ${step.result}` : ''}</div>}
                {step.detail && <span className="xsmall muted">{step.detail}</span>}
              </li>
            ))}
          </ol>
        )}
      </Load>
    </div>
  );
}

function HistoryTab({ p }) {
  return (
    <div className="stack-lg">
      {p.history.length ? (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Scan</th><th>Algorithm</th><th>Verdict</th><th>Risk</th><th>Mosca</th><th className="r">Slack</th></tr></thead>
            <tbody>
              {p.history.map((h) => (
                <tr key={h.scan_id}><td className="nowrap">{dateTime(h.timestamp)}</td><td>{h.algorithm}{h.key_size ? ` ${h.key_size}` : ''}</td>
                  <td>{h.migrated ? 'migrated' : h.verdict}</td><td>{h.risk_level}</td><td>{h.mosca_category || '—'}</td>
                  <td className="r num">{fmt1(h.slack_months)} mo</td></tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : <p className="muted">This is the first scan of this estate that includes this asset.</p>}
      <Trace id={p.id} />
    </div>
  );
}

const ICONS = { summary: FileText, evidence: KeyRound, risk: ShieldAlert, fix: Wrench, dependencies: GitBranch, history: History };

export default function AssetPanel({ id, onClose }) {
  const t = useT();
  const [params, setParams] = useQueryParams();
  const panel = useResource(`/assets/${encodeURIComponent(id)}/panel`);
  const tab = TABS.includes(params.get('tab')) ? params.get('tab') : 'summary';
  const full = params.get('full') === '1';
  const title = panel.data?.summary?.name || 'Asset';
  const body = { summary: Summary, evidence: Evidence, risk: Risk, fix: Fix, dependencies: Dependencies, history: HistoryTab }[tab];
  return (
    <Drawer title={title} subtitle={panel.data?.summary?.system || panel.data?.summary?.class_label} onClose={onClose} full={full}
      headActions={(
        <Button variant="quiet" icon={full ? Minimize2 : Maximize2} aria-pressed={full}
          aria-label={full ? 'Show as a side panel' : 'Open full screen'} title={full ? 'Side panel' : 'Full screen'}
          onClick={() => setParams({ full: full ? null : '1' })} />
      )}
      tabs={<LocalTabs label="Asset sections" active={tab} onChange={(key) => setParams({ tab: key === 'summary' ? null : key })}
        items={TABS.map((key) => ({ key, label: t(`panel.${key}`), icon: ICONS[key] }))} />}>
      <div className="drawer-body">
        <Load resource={panel} skeleton={<Skeleton lines={8} />}>
          {(p) => {
            const Body = body;
            return <Body p={p} />;
          }}
        </Load>
      </div>
    </Drawer>
  );
}

/* The asset as a page of its own (#/asset/<id>/<section>): the default when an asset is opened, so it can be
   bookmarked, shared, opened in a new tab and navigated with Back like any other screen. */
export function AssetPage({ id, section }) {
  const t = useT();
  const panel = useResource(`/assets/${encodeURIComponent(id)}/panel`);
  const tab = TABS.includes(section) ? section : 'summary';
  const Body = { summary: Summary, evidence: Evidence, risk: Risk, fix: Fix, dependencies: Dependencies, history: HistoryTab }[tab];
  const s = panel.data?.summary;
  return (
    <div className="page">
      <Link to="/inventory" className="back-link small"><ArrowLeft size={14} aria-hidden /> Inventory</Link>
      <PageHead title={s?.name || 'Asset'}
        description={s ? [s.class_label, s.system || 'not in the estate register', s.location].filter(Boolean).join(' · ') : ''} />
      <Tabs label="Asset sections" active={tab}
        items={TABS.map((key) => ({ key, label: t(`panel.${key}`), to: `/asset/${encodeURIComponent(id)}/${key}` }))} />
      <div className="asset-page-body">
        <Load resource={panel} skeleton={<Skeleton lines={10} />}>{(p) => <Body p={p} />}</Load>
      </div>
    </div>
  );
}
