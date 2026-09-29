/* Plan: what to change to, what it costs, who acts, and when it lands.
 *
 *   Actions     every recommendation with its target, owner, effort and cost share
 *   Suppliers   vendors and cloud providers that must ship PQC first, with clause drafts
 *   Timeline    each migration against its DST milestone, starting today
 *
 * Cost is declared, not measured: person-days per change by need, times the day
 * rate the estate register declares. The assumptions are shown beside the figure.
 */

import { useMemo, useState } from 'react';
import { Copy, ExternalLink, TriangleAlert } from 'lucide-react';
import {
  Badge, Button, Callout, Card, Figure, Load, MoscaBadge, PageHead, Seg, Skeleton, Tabs, useSort, useToast,
} from '../components/ui';
import { useResource } from '../lib/data';
import { fmt, fmt1, money } from '../lib/format';
import { NEED, OWNER } from '../lib/labels';
import { useT } from '../lib/prefs';
import { openAsset, useQueryParams } from '../lib/router';
import { Simulate, Waves } from './PlanExtras';

/* Latency and wire size of the recommended primitive, exactly as measured on this host (bench/pqc_bench.json).
 * Nothing is estimated here: an algorithm without a measurement says so. */
function latencyText(latency) {
  if (!latency?.length) return 'not measured';
  return latency.map((l) => `${l.operation} ${l.microseconds >= 1000 ? `${(l.microseconds / 1000).toFixed(2)} ms` : `${Math.round(l.microseconds)} µs`}`).join(' · ');
}

function sizeText(sizes) {
  if (!sizes?.length) return '—';
  const s = sizes[0];
  return `${s.payload_label} ${fmt(s.payload_bytes)} B · pk ${fmt(s.public_key_bytes)} B`;
}

function Actions() {
  const [params, setParams] = useQueryParams();
  const profile = params.get('profile') === 'cnsa' ? 'cnsa' : 'commercial';
  const owner = params.get('owner');
  const need = params.get('need');
  const recs = useResource(`/recommendations?profile=${profile}`);
  const cost = useResource('/cost');
  const [limit, setLimit] = useState(60);
  const items = useMemo(() => (recs.data?.items || []).filter((r) => (!owner || r.who_can_fix.key === owner) && (!need || r.need === need))
    .map((r) => ({ ...r, owner_key: r.who_can_fix.key })), [recs.data, owner, need]);
  const { sorted, header } = useSort(items, { key: 'priority_rank', dir: 'asc' });
  return (
    <Load resource={recs} skeleton={<Skeleton height="30rem" />}>
      {(r) => {
        const c = r.cost;
        const currency = cost.data?.assumptions?.currency;
        return (
          <div className="stack-lg">
            <div className="grid-4">
              <Figure label="Changes to make" value={fmt(c.changes)} detail={`covering ${fmt(c.assets)} assets`}
                source="Assets grouped by need, system and file: one edit fixes all of them" />
              <Figure label="Effort" value={`${fmt1(c.person_days)}`} detail="person-days of the owning teams' work"
                source="Declared effort per change (assumptions below)" />
              <Figure label="Cost" value={c.cost !== null ? money(c.cost, currency) : 'Not set'}
                detail={c.cost !== null ? `at ${money(cost.data?.assumptions?.day_rate, currency)} per person-day` : 'Declare a day rate in the estate register'}
                source={cost.data?.assumptions?.day_rate_source || 'No day rate declared'} />
              <Figure label="Waiting on suppliers" value={`${fmt1(c.gated_person_days)}`} detail="person-days that cannot start until a vendor ships"
                source="Vendor- and provider-gated register" />
            </div>
            <Card title="Recommendations" pad={false}
              description={`${fmt(items.length)} of ${fmt(r.items.length)} shown. Targets follow ${profile === 'cnsa' ? 'CNSA 2.0 (sovereign and defence)' : 'NIST FIPS 203/204/205 (commercial)'}.`}
              actions={(
                <div className="row-wrap">
                  <Seg label="Profile" value={profile} onChange={(v) => setParams({ profile: v === 'commercial' ? null : v })}
                    options={[{ value: 'commercial', label: 'NIST' }, { value: 'cnsa', label: 'CNSA 2.0' }]} />
                  <select className="select" style={{ width: '12rem', height: '2rem' }} aria-label="Who acts" value={owner || ''}
                    onChange={(e) => setParams({ owner: e.target.value || null })}>
                    <option value="">Anyone acts</option>
                    {Object.entries(r.by_owner).map(([k, n]) => <option key={k} value={k}>{OWNER[k] || k} ({n})</option>)}
                  </select>
                  <select className="select" style={{ width: '13rem', height: '2rem' }} aria-label="Kind of change" value={need || ''}
                    onChange={(e) => setParams({ need: e.target.value || null })}>
                    <option value="">Every kind of change</option>
                    {Object.entries(r.by_need).map(([k, n]) => <option key={k} value={k}>{NEED[k] || k} ({n})</option>)}
                  </select>
                </div>
              )}
              footer={sorted.length > limit && <Button size="sm" variant="quiet" onClick={() => setLimit(limit + 100)}>Show {fmt(Math.min(100, sorted.length - limit))} more</Button>}>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr>{header('priority_rank', '#', { align: 'right' })}{header('asset', 'Asset')}{header('need', 'Change')}
                    {header('recommended', 'Move to')}<th title={r.items[0]?.cost?.latency_note || ''}>Latency, measured</th><th className="r">On the wire</th>
                    {header('owner_key', 'Who acts')}<th>Effort</th>
                    <th className="r">Share</th><th className="r">Cost</th><th>Mosca</th></tr></thead>
                  <tbody>
                    {sorted.slice(0, limit).map((x) => (
                      <tr key={x.asset_id} data-clickable tabIndex={0} onClick={() => openAsset(x.asset_id)} onKeyDown={(e) => e.key === 'Enter' && openAsset(x.asset_id)}>
                        <td className="r num muted">{x.priority_rank}</td>
                        <td><div className="strong truncate" style={{ maxWidth: '24rem' }}>{x.asset}</div><div className="xsmall muted">{x.system || 'Not in the register'} · {x.algorithm}</div></td>
                        <td className="small">{NEED[x.need] || x.need_label}{x.prerequisites?.length ? <div><Badge tone="warn" icon={TriangleAlert}>library first</Badge></div> : null}</td>
                        <td><span className="soft small">{x.algorithm}</span> <span aria-hidden>→</span> <span className="strong">{x.recommended}</span></td>
                        <td className="small num">{latencyText(x.cost?.latency)}</td>
                        <td className="r small num">{sizeText(x.cost?.sizes)}</td>
                        <td className="small">{OWNER[x.who_can_fix.key]}<div className="xsmall muted truncate" style={{ maxWidth: '12rem' }}>{x.who_can_fix.owner}</div></td>
                        <td className="small">{x.effort.label}</td>
                        <td className="r small num">{x.cost_estimate ? `${fmt1(x.cost_estimate.person_days)} d` : '—'}</td>
                        <td className="r small num">{x.cost_estimate?.cost != null ? money(x.cost_estimate.cost, currency) : '—'}</td>
                        <td><MoscaBadge category={x.mosca_category || 'not_applicable'} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            {Object.keys(r.prerequisites).length > 0 && (
              <Card title="Upgrade these libraries first" description="Code on these stacks cannot use ML-KEM or ML-DSA until the library under it is upgraded.">
                <ul className="list-plain small">
                  {Object.entries(r.prerequisites).map(([key, steps]) => (
                    <li key={key}><strong>{key.split('|')[0]}</strong> ({key.split('|')[1]}): {steps.map((s) => `${s.step}${s.version ? ` (now ${s.version})` : ''}`).join('; ')}</li>
                  ))}
                </ul>
              </Card>
            )}
            {cost.data && (
              <Card title="Cost assumptions" description={cost.data.method} pad={false}>
                <div className="table-wrap">
                  <table className="table">
                    <thead><tr><th>Kind of change</th><th className="r">Person-days per change</th><th>Why that much</th><th>Source</th><th className="r">Changes</th><th className="r">Total</th></tr></thead>
                    <tbody>
                      {Object.entries(cost.data.assumptions.effort_days).map(([k, days]) => {
                        const row = cost.data.by_need[k];
                        return (
                          <tr key={k}><td className="strong">{NEED[k]}</td><td className="r num">{fmt1(days)}</td>
                            <td className="small soft">{cost.data.assumptions.effort_basis[k]}</td>
                            <td className="small">{cost.data.assumptions.effort_source[k]}</td>
                            <td className="r num">{row ? fmt(row.changes) : '—'}</td>
                            <td className="r num">{row ? (row.cost !== null ? money(row.cost, currency) : `${fmt1(row.person_days)} d`) : '—'}</td></tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}
          </div>
        );
      }}
    </Load>
  );
}

function Suppliers() {
  const register = useResource('/vendor-gated');
  const clauses = useResource('/procurement-clauses');
  const toast = useToast();
  const copy = async (text) => {
    try { await navigator.clipboard.writeText(text); toast('Clause copied.'); } catch { toast('Copy failed: select the text instead.'); }
  };
  return (
    <Load resource={register} skeleton={<Skeleton height="30rem" />}>
      {(reg) => (
        <div className="stack-lg">
          <Callout tone="info" title="From FY 2027-28, vendor CBOMs are a procurement requirement.">
            The DST task force asks organisations to request a CBOM and a quantum-resilience roadmap from suppliers in FY 2026-27, and
            to make CBOM submission mandatory through procurement from FY 2027-28. The clauses below are drafts for legal review.
          </Callout>
          {!reg.register.length && <Callout tone="ok" title="No asset is waiting on a supplier." />}
          {reg.register.map((g) => {
            const clause = clauses.data?.clauses?.find((c) => c.supplier === g.who);
            return (
              <Card key={g.who} title={g.who} description={`${OWNER[g.kind] || g.kind} · ${fmt(g.count)} asset(s) · earliest milestone ${g.earliest_deadline}`}
                actions={<Badge tone="warn">Blocks migration</Badge>}>
                <div className="stack">
                  <p><strong>Ask:</strong> {g.action}</p>
                  <p className="small soft">{g.evidence}</p>
                  {g.capabilities?.length > 0 && <p className="small">Needed capability: {g.capabilities.join(', ')}</p>}
                  <div className="row-wrap">
                    {g.assets.slice(0, 8).map((a) => <Button key={a.id} size="sm" onClick={() => openAsset(a.id)}>{a.name}</Button>)}
                  </div>
                  {clause && (
                    <div className="stack" style={{ gap: 'var(--s-2)' }}>
                      <div className="row"><span className="strong small grow">Contract clause · {clause.status}</span>
                        <Button size="sm" icon={Copy} onClick={() => copy(clause.clause)}>Copy</Button></div>
                      <div className="code-block" style={{ fontFamily: 'var(--font-sans)', fontSize: 'var(--fs-13)' }}>{clause.clause}</div>
                      <p className="xsmall muted">{clause.deadline_basis}</p>
                      <ul className="list-plain xsmall">
                        {clause.citations.map((c) => <li key={c.id}>{c.label} · <a href={c.url} target="_blank" rel="noreferrer noopener">source<ExternalLink size={10} style={{ display: 'inline', marginLeft: 2 }} aria-hidden /></a></li>)}
                      </ul>
                    </div>
                  )}
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </Load>
  );
}

function Timeline() {
  const roadmap = useResource('/roadmap');
  const [onlyLate, setOnlyLate] = useState(true);
  return (
    <Load resource={roadmap} skeleton={<Skeleton height="30rem" />}>
      {(rows) => {
        const shown = (onlyLate ? rows.filter((r) => r.overruns_deadline) : rows).slice().sort((a, b) => a.slack_months - b.slack_months);
        const from = Math.floor(Math.min(...rows.map((r) => r.start_year)));
        const to = Math.ceil(Math.max(...rows.map((r) => Math.max(r.end_year, r.deadline_year))));
        const pos = (year) => `${(100 * (year - from)) / (to - from)}%`;
        const years = [];
        for (let y = from; y <= to; y += 1) years.push(y);
        return (
          <Card title="Each migration against its DST milestone"
            description="Each bar starts today and runs for the migration effort of that class of asset, plus any supplier lead time. The tick is 1 January of the milestone year that binds it, the date V.E.R.A. plans against."
            actions={<Seg label="Rows" value={onlyLate ? 'late' : 'all'} onChange={(v) => setOnlyLate(v === 'late')}
              options={[{ value: 'late', label: `Late (${fmt(rows.filter((r) => r.overruns_deadline).length)})` }, { value: 'all', label: `All (${fmt(rows.length)})` }]} />}
            pad={false}>
            <div style={{ padding: 'var(--s-3) var(--s-5)' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '18rem 1fr 6rem', gap: 'var(--s-3)', alignItems: 'end' }}>
                <span className="xsmall muted">Asset</span>
                <div style={{ position: 'relative', height: '1.25rem' }}>
                  {years.map((y) => <span key={y} className="xsmall muted" style={{ position: 'absolute', left: pos(y), transform: 'translateX(-50%)' }}>{y}</span>)}
                </div>
                <span className="xsmall muted" style={{ textAlign: 'right' }}>Slack</span>
              </div>
              <ul className="list-plain" style={{ marginTop: 'var(--s-2)' }}>
                {shown.slice(0, 80).map((r) => (
                  <li key={r.asset_id} style={{ display: 'grid', gridTemplateColumns: '18rem 1fr 6rem', gap: 'var(--s-3)', alignItems: 'center', padding: 'var(--s-2) 0' }}>
                    <button type="button" className="link-btn truncate small" style={{ textAlign: 'left', color: 'var(--text)', textDecoration: 'none' }}
                      onClick={() => openAsset(r.asset_id)} title={r.asset_name}>{r.asset_name}</button>
                    <div style={{ position: 'relative', height: '0.875rem', background: 'var(--surface-2)', borderRadius: 4 }}>
                      {years.map((y) => <span key={y} aria-hidden style={{ position: 'absolute', left: pos(y), top: 0, bottom: 0, width: 1, background: 'var(--line)' }} />)}
                      <span aria-hidden style={{ position: 'absolute', left: pos(r.start_year), width: `calc(${pos(r.end_year)} - ${pos(r.start_year)})`, top: 2, bottom: 2,
                        borderRadius: 3, background: r.overruns_deadline ? 'var(--bad)' : 'var(--primary)', opacity: 0.85 }} />
                      <span aria-hidden style={{ position: 'absolute', left: pos(r.deadline_year), top: -3, bottom: -3, width: 2, background: 'var(--text)' }} />
                    </div>
                    <span className="small num" style={{ textAlign: 'right', color: r.overruns_deadline ? 'var(--bad-text)' : undefined, fontWeight: r.overruns_deadline ? 600 : 400 }}>
                      {r.slack_months < 0 ? '−' : '+'}{fmt1(Math.abs(r.slack_months))} mo
                    </span>
                  </li>
                ))}
              </ul>
              {shown.length > 80 && <p className="small muted">Showing the 80 with the least slack. The inventory has every asset.</p>}
            </div>
          </Card>
        );
      }}
    </Load>
  );
}

export default function Plan({ route, hasScan }) {
  const t = useT();
  const tab = ['actions', 'suppliers', 'timeline', 'waves', 'simulate'].includes(route.segments[1]) ? route.segments[1] : 'actions';
  const Body = { actions: Actions, suppliers: Suppliers, timeline: Timeline, waves: Waves, simulate: Simulate }[tab];
  return (
    <div className="page">
      <PageHead title={t('nav.plan')} description="What to change to, what it costs, who has to act, and whether it lands before the milestone." />
      <Tabs label="Plan views" active={tab} items={[
        { key: 'actions', label: t('plan.actions'), to: '/plan/actions' },
        { key: 'suppliers', label: t('plan.suppliers'), to: '/plan/suppliers' },
        { key: 'timeline', label: t('plan.timeline'), to: '/plan/timeline' },
        { key: 'waves', label: t('plan.waves'), to: '/plan/waves' },
        { key: 'simulate', label: t('plan.simulate'), to: '/plan/simulate' },
      ]} />
      {hasScan ? <Body /> : <Callout tone="info" title="Nothing scanned yet.">Run a scan first.</Callout>}
    </div>
  );
}
