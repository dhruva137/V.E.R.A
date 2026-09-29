/* Overview: posture against the DST milestones, what to do next, and whether to trust it.
 *
 * Top to bottom: the verdict; four figures with their sources;
 * "Do next"; the DST milestone track; exposure by system; coverage and
 * evidence. One call (GET /api/overview), so the screen opens in one step.
 */

import {
  ArrowRight, CalendarClock, CircleCheck, CircleHelp, Download, OctagonX, Radar, TriangleAlert,
} from 'lucide-react';
import {
  Badge, Button, ButtonLink, Card, Callout, Empty, Figure, Load, Meter, MoscaBadge, PageHead, Skeleton, Stacked, useToast,
} from '../components/ui';
import { download } from '../lib/api';
import { useAuth } from '../lib/auth';
import { useResource } from '../lib/data';
import { date, dateTime, fmt, fmt1, money, pct } from '../lib/format';
import { useT } from '../lib/prefs';
import { Link, navigate, openAsset } from '../lib/router';
import { useScan } from '../lib/scan';
import CoverageStrip from '../components/CoverageStrip';

const OWNER = {
  self_managed: 'Owning team', vendor_firmware_gated: 'HSM vendor first', provider_gated: 'Cloud provider first',
  third_party: 'Third party',
};
const STATUS = {
  met: { tone: 'ok', icon: CircleCheck, label: 'Met' },
  in_progress: { tone: 'info', icon: CalendarClock, label: 'In progress' },
  at_risk: { tone: 'bad', icon: TriangleAlert, label: 'At risk' },
  missed: { tone: 'bad', icon: OctagonX, label: 'Missed' },
};

function Welcome() {
  const t = useT();
  const auth = useAuth();
  const scan = useScan();
  const toast = useToast();
  const start = async () => {
    try {
      await scan.start({ estate: 'demo' });
      navigate('/scan');
    } catch (e) {
      toast(e.message);
    }
  };
  return (
    <div className="page">
      <PageHead title={t('nav.overview')} description="Nothing has been scanned yet." />
      <Card pad={false}>
        <Empty title="Start with a scan"
          action={auth.can('scan') ? (
            <div className="row-wrap">
              <Button variant="primary" icon={Radar} onClick={start} busy={scan.running}>Scan the demo estate</Button>
              <ButtonLink to="/scan">Scan your own estate</ButtonLink>
            </div>
          ) : <p className="small muted">Ask an analyst to run the first scan. Your role can read results but not start scans.</p>}>
          V.E.R.A. reads source code, dependencies, binaries, container images, configuration, keystores, key managers and
          recorded network traffic, then ranks every cryptographic asset against the DST milestones. The demo estate is a
          synthetic bank with nine systems and takes about 30 seconds.
        </Empty>
      </Card>
    </div>
  );
}

/* A short imperative title. A cipher-suite string is not a name a person reads. */
function actionTitle(row) {
  const alg = row.algorithm && row.algorithm.length <= 18 && !row.algorithm.includes(':') ? row.algorithm : null;
  switch (row.need) {
    case 'key_exchange': return `Switch key exchange to ${row.fix}`;
    case 'kem_at_rest': return `Re-wrap ${alg ? `${alg} ` : ''}keys with ${row.fix}`;
    case 'signature_high_volume':
    case 'signature_long_lived': return `Move ${alg ? `${alg} ` : ''}signatures to ${row.fix}`;
    case 'replace_now': return `Replace ${alg || 'broken cryptography'} with ${row.fix}`;
    case 'symmetric':
    case 'hash': return `Move ${alg || 'this'} to ${row.fix}`;
    default: return row.fix;
  }
}

function Verdict({ o }) {
  const next = o.verdict.next_milestone;
  const behind = o.milestones.reduce((n, m) => n + (m.behind || 0), 0);
  return (
    <section className="card stack verdict" aria-label="Verdict">
      <span className="verdict-kicker">Quantum readiness verdict</span>
      <p className="verdict-sentence">{o.verdict.sentence}</p>
      <div className="row-wrap soft">
        {next && (
          <span className="row"><CalendarClock size={16} aria-hidden />
            <span>Next DST milestone: <strong>{next.label}</strong> by {next.year}, planned against {date(next.date)} · {fmt(next.days_left)} days left</span></span>
        )}
        {behind > 0 && <Badge tone="bad" icon={TriangleAlert}>{fmt(behind)} assets cannot make their milestone even if work starts today</Badge>}
      </div>
    </section>
  );
}

function Figures({ o }) {
  const t = useT();
  const route = { inventoried: '/inventory', vulnerable: '/inventory?status=vulnerable', exposed: '/risk/exposure', gated: '/plan/suppliers' };
  const tone = { inventoried: 'primary', vulnerable: 'warn', exposed: 'bad', gated: 'info' };
  return (
    <div className="grid-4">
      {o.figures.map((f) => (
        <Figure key={f.key} label={t(`fig.${f.key}`)} value={fmt(f.value)} detail={f.detail} source={f.source}
          tone={tone[f.key]} onClick={() => navigate(route[f.key])} />
      ))}
    </div>
  );
}

function DoNext({ o }) {
  const t = useT();
  return (
    <Card title={t('overview.doNext')} description="The highest-priority changes. One change that fixes several assets is one row."
      pad={false} actions={<ButtonLink to="/plan/actions" size="sm" icon={ArrowRight}>{t('overview.allActions')}</ButtonLink>}
      footer={o.cost.person_days ? (
        <span>All {fmt(o.cost.changes)} changes: {fmt1(o.cost.person_days)} person-days
          {o.cost.cost !== null ? ` · ${money(o.cost.cost, o.cost.currency)} at the declared rate` : ' · set a day rate in the estate register to see cost'}.
          {' '}{fmt1(o.cost.gated_person_days)} of those wait on a supplier.</span>
      ) : null}>
      <ol className="list-plain" style={{ padding: '0 var(--s-5)' }}>
        {o.do_next.map((row, i) => (
          <li key={row.asset_id} className="row" style={{ alignItems: 'flex-start', gap: 'var(--s-4)' }}>
            <span className="strong num" style={{ width: '1.5rem', color: 'var(--text-3)' }}>{i + 1}</span>
            <div className="grow stack" style={{ gap: 'var(--s-1)' }}>
              <div className="row-wrap">
                <button type="button" className="link-btn strong" style={{ textAlign: 'left' }} onClick={() => openAsset(row.asset_id)}>
                  {actionTitle(row)}
                </button>
                <MoscaBadge category={row.mosca_category} />
              </div>
              <span className="small soft">
                {row.count > 1 ? `${fmt(row.count)} assets in ` : ''}{row.system || 'not in the register'} · {row.need_label}. {row.why}
              </span>
              <span className="xsmall muted">
                {OWNER[row.owner?.key] || row.owner?.key}{row.owner?.owner ? `: ${row.owner.owner}` : ''} · {row.effort?.label}
                {row.person_days ? ` · ${fmt1(row.person_days)} person-days` : ''}{row.cost ? ` · ${money(row.cost)}` : ''}
                {row.deadline_year ? ` · milestone ${row.deadline_year}` : ''}
              </span>
            </div>
          </li>
        ))}
      </ol>
    </Card>
  );
}

function Milestones({ o }) {
  const t = useT();
  return (
    <Card title={t('overview.milestones')} description={`${o.persona} is on the ${o.milestones[0]?.year === 2027 ? 'critical-sector' : 'regular-enterprise'} track`}
      footer={<span>Source: {o.milestones[0]?.source}</span>}>
      <ol className="list-plain">
        {o.milestones.map((m) => {
          const s = STATUS[m.status] || STATUS.in_progress;
          return (
            <li key={m.phase} className="stack" style={{ gap: 'var(--s-2)' }}>
              <div className="row">
                <div className="grow">
                  <div className="strong">{m.label}</div>
                  <div className="small muted">{m.year}, planned against 1 Jan · {m.days_left >= 0 ? `${fmt(m.days_left)} days left` : `${fmt(-m.days_left)} days ago`}</div>
                </div>
                <Badge tone={s.tone} icon={s.icon}>{t(`ms.${m.status}`)}</Badge>
              </div>
              <div className="row">
                <div className="grow"><Meter value={(m.readiness_pct || 0) / 100} tone={m.status === 'at_risk' ? 'bad' : m.readiness_pct >= 90 ? 'ok' : ''}
                  label={`${m.label} readiness`} /></div>
                <span className="small strong num" style={{ width: '3.5rem', textAlign: 'right' }}>{pct(m.readiness_pct)}</span>
              </div>
              <div className="xsmall muted">{m.readiness_basis}{m.in_scope !== undefined ? ` (${fmt(m.migrated)} of ${fmt(m.in_scope)})` : ''}</div>
              {m.open.map((item) => <div key={item} className="small row" style={{ alignItems: 'flex-start' }}><TriangleAlert size={14} color="var(--warn-text)" aria-hidden style={{ marginTop: 3, flex: 'none' }} />{item}</div>)}
            </li>
          );
        })}
      </ol>
    </Card>
  );
}

function Systems({ o }) {
  const t = useT();
  return (
    <Card title={t('overview.systems')} description="From the estate register, with what the scan found in each system." pad={false}>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr><th>System</th><th>Owner</th><th>Criticality</th><th>Reach</th><th className="r">Assets</th>
              <th className="r">Vulnerable</th><th className="r">Exposed</th><th className="r">Late</th><th style={{ width: '22%' }}>Share</th></tr>
          </thead>
          <tbody>
            {o.systems.map((s) => (
              <tr key={s.system || 'none'} data-clickable onClick={() => navigate(`/inventory${s.system ? `?system=${encodeURIComponent(s.system)}` : '?system='}`)}>
                <td className="strong">{s.system || <span className="soft">Not in the register</span>}</td>
                <td>{s.owner || '—'}</td>
                <td>{s.criticality || '—'}</td>
                <td>{s.exposure === 'internet' ? 'Internet' : s.exposure === 'internal' ? 'Internal' : '—'}</td>
                <td className="r num">{fmt(s.assets)}</td>
                <td className="r num">{fmt(s.vulnerable)}</td>
                <td className="r num" style={{ color: s.exposed ? 'var(--bad-text)' : undefined, fontWeight: s.exposed ? 600 : 400 }}>{fmt(s.exposed)}</td>
                <td className="r num">{fmt(s.behind)}</td>
                <td><Stacked parts={[
                  { label: 'Exposed', value: s.exposed, tone: 'bad' },
                  { label: 'Other vulnerable', value: Math.max(0, s.vulnerable - s.exposed), tone: 'warn' },
                  { label: 'Not vulnerable', value: Math.max(0, s.assets - s.vulnerable), tone: 'neutral' },
                ]} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Coverage({ o }) {
  const c = o.coverage;
  const e = o.evidence;
  const check = (ok, text, to) => (
    <li className="row" style={{ alignItems: 'flex-start' }}>
      {ok === true ? <CircleCheck size={16} color="var(--ok)" aria-hidden style={{ flex: 'none', marginTop: 2 }} />
        : ok === false ? <OctagonX size={16} color="var(--bad)" aria-hidden style={{ flex: 'none', marginTop: 2 }} />
          : <CircleHelp size={16} color="var(--warn-text)" aria-hidden style={{ flex: 'none', marginTop: 2 }} />}
      <span className="grow">{text}</span>
      {to && <Link to={to} className="small nowrap">View</Link>}
    </li>
  );
  return (
    <div className="grid-2">
      <Card title="Coverage" description="What this scan read, and what it did not.">
        <ul className="list-plain small">
          {check(c.failed_runs === 0, `${fmt(c.runs - c.failed_runs)} of ${fmt(c.runs)} collector runs read cleanly${c.unreadable ? `; ${fmt(c.unreadable)} files could not be parsed` : ''}.`, '/scan')}
          {check(c.planes.length === 4 ? true : null, `Evidence planes seen: ${c.planes.join(', ')}. ${fmt(c.cross_plane_assets)} assets confirmed on more than one.`)}
          {check(c.not_run.length ? null : true, c.not_run.length
            ? `Not run in this scan: ${c.not_run.map((x) => x.label).join(', ')}. No target of that kind was given.`
            : 'Every collector ran.', '/scan')}
          {check(c.unresolved ? null : true, c.unresolved ? `${fmt(c.unresolved)} assets use an algorithm chosen at run time; review them rather than guess.` : 'Every algorithm was resolved.', '/inventory?status=unresolved')}
          {check(c.drift ? null : true, c.drift ? `${fmt(c.drift)} places where declared policy and the evidence disagree.` : 'Declared policy matches the evidence.', '/risk/drift')}
        </ul>
      </Card>
      <Card title="Evidence" description="What an assessor can verify without trusting this screen.">
        <ul className="list-plain small">
          {check(e.cbom.valid, `CBOM (CycloneDX ${e.cbom.spec}) ${e.cbom.valid ? 'validates' : 'does not validate'} against the official schema · ${fmt(e.cbom.components)} components.`, '/evidence/reports')}
          {check(e.certin.percent >= 100 ? true : null, `CERT-In minimum elements (Table 9): ${pct(e.certin.percent)} present (${fmt(e.certin.present)} of ${fmt(e.certin.required)}).`, '/evidence/certin')}
          {check(e.manifest?.alg === 'ML-DSA-65' ? true : null, `Evidence manifest signed with ${e.manifest?.alg || 'nothing yet'}.`, '/evidence/integrity')}
          {check(e.audit.valid, `Audit chain ${e.audit.valid ? 'verifies' : `breaks at entry ${e.audit.first_broken}`} · ${fmt(e.audit.entries)} entries.`, '/evidence/integrity')}
        </ul>
      </Card>
    </div>
  );
}

export default function Overview({ hasScan, scanInfo }) {
  const t = useT();
  const auth = useAuth();
  const toast = useToast();
  const overview = useResource(hasScan ? '/overview' : null);
  if (!hasScan) return <Welcome />;
  return (
    <div className="page">
      <PageHead title={t('nav.overview')}
        description={scanInfo ? `${scanInfo.estate}${scanInfo.synthetic ? ' (synthetic)' : ''} · scanned ${dateTime(scanInfo.timestamp)}` : null}
        actions={(
          <>
            <Button icon={Download} onClick={() => download('/report/ntro').catch((e) => toast(e.message))}>{t('overview.report')}</Button>
            {auth.can('scan') && <ButtonLink to="/scan" variant="primary" icon={Radar}>{t('common.scanAgain')}</ButtonLink>}
          </>
        )} />
      <Load resource={overview} skeleton={<div className="stack-lg"><Skeleton height="6rem" /><div className="grid-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} height="8.5rem" />)}</div><Skeleton height="20rem" /></div>}>
        {(o) => (
          <div className="stack-lg">
            <Verdict o={o} />
            <Figures o={o} />
          <CoverageStrip surfaces={o.coverage?.surfaces} />
            <div className="grid-main-side">
              <DoNext o={o} />
              <Milestones o={o} />
            </div>
            <Systems o={o} />
            <Coverage o={o} />
            {o.estate.synthetic && (
              <Callout tone="info" title="Synthetic estate">
                These numbers describe the bundled demo bank, generated for testing. Scan a real estate register to assess an
                organisation.
              </Callout>
            )}
          </div>
        )}
      </Load>
    </div>
  );
}
