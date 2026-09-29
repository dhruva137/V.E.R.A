/* Evidence: what an assessor can check without trusting this screen.
 *
 *   Reports and exports   CBOM (CycloneDX 1.7 / 1.6), SARIF, the signed manifest, the PDF reports
 *   CERT-In conformance   the CBOM against CERT-In's minimum elements (BOM guidelines v2.0, Table 9)
 *   Integrity             verify the manifest signature; walk the hash-chained audit log
 *   Changes               what moved between two scans, and why scores moved
 *   Method                the threat model, its sources, and the measured benchmarks
 */

import { useState } from 'react';
import { CircleCheck, Download, ExternalLink, FileJson, FileText, OctagonX, ShieldCheck } from 'lucide-react';
import {
  Badge, Button, Callout, Card, Figure, Kv, Load, Meter, PageHead, Skeleton, Tabs, useToast,
} from '../components/ui';
import { download, get, post } from '../lib/api';
import { useResource } from '../lib/data';
import { date, dateTime, fmt, fmt1, pct } from '../lib/format';
import { useT } from '../lib/prefs';
import { openAsset, useQueryParams } from '../lib/router';
import {
  AssistantLog, ClassInputs, Compliance, EnginePipeline, PublicKey, SarifStatus, SurvivalCurve, WireSizes,
} from './EvidenceExtras';
import Detector from './Detector';

function Export({ icon: Icon, title, format, who, children, onDownload }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try { await onDownload(); } catch (e) { toast(e.message); } finally { setBusy(false); }
  };
  return (
    <Card>
      <div className="stack" style={{ gap: 'var(--s-2)', height: '100%' }}>
        <div className="row"><Icon size={18} aria-hidden /><span className="strong grow">{title}</span><Badge>{format}</Badge></div>
        <div className="small soft">{children}</div>
        <p className="xsmall muted">For: {who}</p>
        <div style={{ marginTop: 'auto' }}><Button icon={Download} busy={busy} onClick={run}>Download</Button></div>
      </div>
    </Card>
  );
}

function Reports() {
  const validation = useResource('/cbom/validate');
  return (
    <div className="stack-lg">
      <div className="grid-3">
        <Export icon={FileJson} title="Cryptographic bill of materials" format="CycloneDX 1.7" who="auditors, CERT-In, procurement, other tools"
          onDownload={() => download('/cbom', 'vera-cbom-1.7.cdx.json')}>
          Every algorithm, key, certificate, protocol and crypto library, with dependencies. Byte-identical for the same scan.
        </Export>
        <Export icon={FileJson} title="CBOM for older consumers" format="CycloneDX 1.6" who="tools that do not read 1.7 yet"
          onDownload={() => download('/cbom?spec=1.6', 'vera-cbom-1.6.cdx.json')}>
          The same inventory without the 1.7-only registry fields.
        </Export>
        <Export icon={FileText} title="NTRO / CII assessment report" format="PDF" who="assessors and the board"
          onDownload={() => download('/report/ntro')}>
          The executive page through to the signed evidence: posture, milestones, priorities, suppliers and method.
        </Export>
        <Export icon={FileJson} title="Findings for CI and code review" format="SARIF 2.1.0" who="engineering pipelines"
          onDownload={() => download('/sarif', 'vera.sarif')}>
          One rule per finding class; critical and high are errors. Upload it to code scanning in CI.
          <SarifStatus />
        </Export>
        <Export icon={ShieldCheck} title="Signed evidence manifest" format="JSON · ML-DSA-65" who="anyone verifying the exports"
          onDownload={async () => {
            const blob = new Blob([JSON.stringify(await get('/manifest'), null, 2)], { type: 'application/json' });
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'vera-manifest.json'; a.click();
          }}>
          Hashes of every input, the CBOM and the SARIF, the threat model and the policy, signed with a post-quantum key.
        </Export>
        <Export icon={FileText} title="Board summary" format="PDF" who="leadership" onDownload={() => download('/report/pdf')}>
          A short summary of exposure and what to fund first.
        </Export>
        <Export icon={FileJson} title="Every asset, full record" format="JSON" who="engineers and other tools"
          onDownload={async () => {
            const blob = new Blob([JSON.stringify(await get('/assets?limit=5000'), null, 2)], { type: 'application/json' });
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'vera-assets.json'; a.click();
          }}>
          Every field the engine holds for each asset: evidence references, scoring inputs, verdict, milestone and slack.
        </Export>
      </div>
      <PublicKey />
      <Card title="CBOM validation" description="Checked offline against the official CycloneDX schema, plus reference and crypto-asset rules." pad={false}>
        <Load resource={validation} skeleton={<div className="card-body"><Skeleton /></div>}>
          {(v) => (
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Check</th><th>Result</th><th className="r">Problems</th></tr></thead>
                <tbody>
                  {v.checks.map((c) => (
                    <tr key={c.id}><td>{c.description}</td>
                      <td>{c.passed ? <Badge tone="ok" icon={CircleCheck}>Pass</Badge> : <Badge tone="bad" icon={OctagonX}>Fail</Badge>}</td>
                      <td className="r num">{fmt(c.violation_count)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Load>
      </Card>
    </div>
  );
}

function CertIn() {
  const conformance = useResource('/certin-conformance');
  return (
    <Load resource={conformance} skeleton={<Skeleton height="30rem" />}>
      {(c) => (
        <div className="stack-lg">
          <div className="grid-3">
            <Figure label="Required elements present" value={pct(c.percent)} detail={`${fmt(c.present)} of ${fmt(c.required)} across ${fmt(c.components)} components`}
              source="CERT-In BOM guidelines v2.0, Table 9" />
            <Figure label="Standard" value="v2.0" detail="Technical Guidelines on SBOM, QBOM & CBOM, AIBOM and HBOM, 9 July 2025" />
            <Figure label="Document checked" value={`CycloneDX ${c.cbom_spec}`} detail="The exported file itself, not the scan" />
          </div>
          <Callout tone="info" title="How to read this">
            An element is <strong>missing</strong> when it could exist but the source did not record it; each gap has its reason, so it
            can be closed at the source. <strong>Not applicable</strong> means no value can exist (no OID is registered for a TLS
            version) and is left out of the percentage.
          </Callout>
          {c.by_type.map((type) => (
            <Card key={type.asset_type} title={type.label} description={`${fmt(type.components)} components`} pad={false}>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Element</th><th style={{ width: '22%' }}>Present</th><th>What is missing, and why</th></tr></thead>
                  <tbody>
                    {type.elements.map((e) => (
                      <tr key={e.element}>
                        <td className="strong">{e.element}<div className="xsmall muted mono">{e.path}</div></td>
                        <td>{e.percent === null ? <span className="small muted">Not applicable</span> : (
                          <div className="stack" style={{ gap: 4 }}>
                            <div className="row"><span className="small num strong">{pct(e.percent)}</span><span className="xsmall muted">{fmt(e.present)}/{fmt(e.applicable)}</span></div>
                            <Meter value={e.percent / 100} tone={e.percent === 100 ? 'ok' : e.percent >= 80 ? '' : 'warn'} label={`${e.element} present`} />
                          </div>
                        )}</td>
                        <td className="small">
                          {e.missing_reasons.map((m) => <div key={m.reason}>{fmt(m.count)} · {m.reason}</div>)}
                          {e.not_applicable > 0 && <div className="muted">{fmt(e.not_applicable)} not applicable: {e.na_reason}</div>}
                          {!e.missing_reasons.length && !e.not_applicable && <span className="muted">Complete</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          ))}
          <p className="xsmall muted">Source: <a href={c.url} target="_blank" rel="noreferrer noopener">{c.standard}</a></p>
        </div>
      )}
    </Load>
  );
}

function Integrity() {
  const chain = useResource('/audit/chain?limit=60');
  const toast = useToast();
  const [verdict, setVerdict] = useState(null);
  const [manifest, setManifest] = useState(null);
  const [busy, setBusy] = useState(false);
  const verify = async () => {
    setBusy(true);
    try {
      const m = manifest || await get('/manifest');
      setManifest(m);
      setVerdict(await post('/manifest/verify', { manifest: m }));
    } catch (e) { toast(e.message); } finally { setBusy(false); }
  };
  return (
    <div className="stack-lg">
      <Card title="Signed evidence manifest" description="Verify the signature and that the CBOM on disk is the one this scan produced."
        actions={<Button variant="primary" icon={ShieldCheck} busy={busy} onClick={verify}>Verify now</Button>}>
        {!verdict ? <p className="small soft">The manifest records the SHA-256 of every collector's output, the CBOM, the SARIF, the threat-model table and the policy, and is signed with ML-DSA-65 (FIPS 204) through OpenSSL on this machine.</p> : (
          <div className="stack">
            <Callout tone={verdict.valid && verdict.cbom_matches_current_scan ? 'ok' : 'bad'}
              title={verdict.valid ? `Signature verified (${verdict.alg})` : `Signature does not verify: ${verdict.reason}`}>
              {verdict.cbom_matches_current_scan ? 'The CBOM hash matches the current scan.' : 'The CBOM hash does not match the current scan.'}
              {verdict.key_trusted === false && ' The signing key is not the one this installation trusts.'}
            </Callout>
            {manifest && <Kv rows={[
              ['Signed', dateTime(manifest.created_at)], ['Algorithm', `${manifest.signature.alg} (${manifest.signature.provider})`],
              ['Public key SHA-256', <code key="k" className="break">{manifest.signature.public_key_sha256}</code>],
              ['CBOM SHA-256', <code key="c" className="break">{manifest.cbom_sha256}</code>],
              ['SARIF SHA-256', <code key="s" className="break">{manifest.sarif_sha256}</code>],
              ['Threat model', manifest.threat_model_version], ['Collector outputs hashed', fmt(manifest.inputs.length)],
            ]} />}
          </div>
        )}
      </Card>
      <Load resource={chain} skeleton={<Skeleton height="20rem" />}>
        {(a) => (
          <Card title="Audit chain" pad={false}
            description={a.verify.valid ? `Verifies end to end · ${fmt(a.verify.entries)} entries · each entry hashes the one before it.`
              : `Broken at entry ${a.verify.first_broken}: an entry was changed or removed.`}
            actions={a.verify.valid ? <Badge tone="ok" icon={CircleCheck}>Intact</Badge> : <Badge tone="bad" icon={OctagonX}>Broken</Badge>}>
            <div className="table-wrap" style={{ maxHeight: '32rem', overflowY: 'auto' }} tabIndex={0} role="region" aria-label="Audit chain entries">
              <table className="table">
                <thead><tr><th className="r">#</th><th>When</th><th>Who</th><th>What</th><th>Detail</th></tr></thead>
                <tbody>
                  {a.entries.map((e) => (
                    <tr key={e.idx}><td className="r num muted">{e.idx}</td><td className="nowrap small">{dateTime(e.at)}</td>
                      <td className="small">{e.actor.replace(/^user:/, '')}</td><td className="small"><strong>{e.kind}</strong> · {e.action.replace(/_/g, ' ')}</td>
                      <td className="xsmall muted break">{Object.entries(e.detail || {}).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join(' · ').slice(0, 180)}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </Load>
      <PublicKey />
      <AssistantLog />
    </div>
  );
}

function Changes() {
  const [params, setParams] = useQueryParams();
  const scans = useResource('/scans');
  const from = params.get('from');
  const to = params.get('to');
  const q = new URLSearchParams();
  if (from) q.set('from', from);
  if (to) q.set('to', to);
  const delta = useResource(`/delta${q.toString() ? `?${q}` : ''}`);
  const option = (s) => <option key={s.scan_id} value={s.scan_id}>{dateTime(s.timestamp)} · {s.label} · {s.total_assets}</option>;
  return (
    <div className="stack-lg">
      <Card title="Compare two scans">
        <div className="row-wrap" style={{ alignItems: 'flex-end' }}>
          <div className="field" style={{ minWidth: '20rem' }}>
            <label htmlFor="from">Earlier scan</label>
            <select id="from" className="select" value={from || ''} onChange={(e) => setParams({ from: e.target.value || null })}>
              <option value="">The one before the latest</option>{(scans.data || []).map(option)}
            </select>
          </div>
          <div className="field" style={{ minWidth: '20rem' }}>
            <label htmlFor="to">Later scan</label>
            <select id="to" className="select" value={to || ''} onChange={(e) => setParams({ to: e.target.value || null })}>
              <option value="">The current scan</option>{(scans.data || []).map(option)}
            </select>
          </div>
        </div>
      </Card>
      <Load resource={delta} skeleton={<Skeleton height="16rem" />}>
        {(d) => (
          <div className="stack-lg">
            {d.warning && <Callout tone="warn" title="These scans may not be comparable">{d.warning}</Callout>}
            <div className="grid-4">
              <Figure label="Migration progress" value={pct(d.migration.progress_percent)} detail={d.migration.progress_basis} />
              <Figure label="Added" value={fmt(d.added.length)} detail="assets new in the later scan" />
              <Figure label="Removed" value={fmt(d.removed.length)} detail="assets gone from the later scan" />
              <Figure label="Changed" value={fmt(d.changed.length)} detail="assets whose algorithm, verdict or score moved" />
            </div>
            <Callout tone="info" title="Why scores moved">{d.why_scores_moved?.explanation}</Callout>
            {[['Added', d.added], ['Removed', d.removed], ['Changed', d.changed]].filter(([, list]) => list.length).map(([title, list]) => (
              <Card key={title} title={title} pad={false}>
                <ul className="list-plain" style={{ padding: '0 var(--s-5)' }}>
                  {list.slice(0, 50).map((x) => (
                    <li key={x.id || x.asset_id} className="small">
                      <button type="button" className="link-btn" onClick={() => openAsset(x.id || x.asset_id)}>{x.name || x.asset_name || x.id}</button>
                      {x.reason && <span className="soft"> · {x.reason}</span>}
                      {x.changes && <span className="soft"> · {Object.keys(x.changes).join(', ')}</span>}
                    </li>
                  ))}
                </ul>
              </Card>
            ))}
            {!d.added.length && !d.removed.length && !d.changed.length && (
              <Callout tone="neutral" title="No asset changed between these scans." />
            )}
          </div>
        )}
      </Load>
    </div>
  );
}

function Split({ label, s }) {
  if (!s) return null;
  return <tr><td className="strong">{label}</td><td className="r num">{fmt1(s.precision)}</td><td className="r num">{fmt1(s.recall)}</td>
    <td className="r num">{fmt1(s.f1)}</td><td className="r num">{fmt(s.cases ?? (s.tp + s.fn))}</td></tr>;
}

function Method() {
  const model = useResource('/threat-model');
  const method = useResource('/method');
  const bench = useResource('/bench');
  const reg = useResource('/regulatory');
  const version = model.data?.versioned?.version?.version;
  const det = method.data?.detection;
  const agent = method.data?.agent?.summary;
  return (
    <div className="stack-lg">
      <Card title="How risk is decided">
        <div className="stack small">
          <p><strong>Mosca's inequality, per asset.</strong> An asset is exposed when X + Y &gt; Z: how long the data or trust must hold (X),
            plus how long migration takes (Y), against when a cryptographically relevant quantum computer arrives for that asset's
            primitive (Z). X comes from the data classes the estate register declares; Y from the class of asset and any supplier lead time.</p>
          <p><strong>Z per primitive.</strong> The survival ensemble from the Global Risk Institute's expert survey, shifted for each
            primitive by its published logical-qubit estimate against RSA-2048.</p>
          <p><strong>Deadlines.</strong> DST's migration tracks. An asset follows the high-priority milestone when it is a widely trusted
            anchor or faces the internet, and the full-migration milestone otherwise.</p>
        </div>
      </Card>
      <div className="grid-2">
        <Load resource={model} skeleton={<Skeleton height="12rem" />}>
          {(m) => (
            <Card title={`Threat model ${version}`}>
              <Kv rows={[['Survey', m.versioned?.version?.gri_edition], ['Survey date', date(m.versioned?.version?.report_date)],
                ['Doubling time D', `${m.versioned?.version?.D} years`], ['Curve', m.functional_form], ['Change log', m.versioned?.version?.changelog]]} />
              {m.caveat && <p className="xsmall muted" style={{ marginTop: 'var(--s-3)' }}>{m.caveat}</p>}
            </Card>
          )}
        </Load>
        <Load resource={reg} skeleton={<Skeleton height="12rem" />}>
          {(r) => (
            <Card title="DST migration tracks" footer={r.source}>
              <table className="table">
                <thead><tr><th>Sector</th><th className="r">Foundations</th><th className="r">High-priority</th><th className="r">Full</th></tr></thead>
                <tbody>{Object.entries(r.deadlines).map(([p, d]) => (
                  <tr key={p} aria-current={p === r.current_org_persona ? 'true' : undefined}>
                    <td className={p === r.current_org_persona ? 'strong' : undefined}>{p}{p === r.current_org_persona ? ' (this estate)' : ''}</td>
                    <td className="r num">{d.foundation}</td><td className="r num">{d.high_priority}</td><td className="r num">{d.full}</td></tr>
                ))}</tbody>
              </table>
            </Card>
          )}
        </Load>
      </div>
      <Card title="Detection accuracy" description={det ? `Measured ${dateTime(det.measured_at)} on ${det.corpus}` : 'Not measured on this installation.'}>
        {det && (
          <div className="stack">
            <table className="table">
              <thead><tr><th>Split</th><th className="r">Precision</th><th className="r">Recall</th><th className="r">F1</th><th className="r">Cases</th></tr></thead>
              <tbody>
                <Split label="Tune, first run" s={det.first_run?.tune} />
                <Split label="Held out, first run" s={det.first_run?.holdout} />
                <Split label="All, current rules" s={det.splits?.all?.overall} />
              </tbody>
            </table>
            <ul className="list-plain xsmall muted">{(det.caveats || []).map((c) => <li key={c}>{c}</li>)}</ul>
          </div>
        )}
      </Card>
      <div className="grid-2">
        <Card title="Assistant tool selection" description={method.data?.agent ? `${method.data.agent.prompts?.count} prompts × ${method.data.agent.repeats}, ${method.data.agent.model}` : 'Not measured.'}>
          {agent && (
            <table className="table">
              <thead><tr><th>Arm</th><th className="r">First decision right</th><th className="r">Median time to pick a tool</th></tr></thead>
              <tbody>
                <tr><td>Model alone</td><td className="r num">{pct(agent.llm_only.first_decision_accuracy * 100)}</td><td className="r num">{fmt(agent.llm_only.median_selection_ms)} ms</td></tr>
                <tr><td>Router, then model</td><td className="r num">{pct(agent.router_llm.first_decision_accuracy * 100)}</td><td className="r num">{fmt(agent.router_llm.median_selection_ms)} ms</td></tr>
              </tbody>
            </table>
          )}
          {method.data?.agent?.caveat && <p className="xsmall muted" style={{ marginTop: 'var(--s-3)' }}>{method.data.agent.caveat}</p>}
        </Card>
        <Load resource={bench} skeleton={<Skeleton height="12rem" />}>
          {(b) => (
            <Card title="Post-quantum cost on this machine" description={b.measured ? `Measured ${dateTime(b.measured_at)} with OpenSSL ${b.tool?.version}` : b.note} pad={false}>
              {b.measured && (
                <div className="table-wrap" style={{ maxHeight: '18rem', overflowY: 'auto' }} tabIndex={0} role="region" aria-label="Measured post-quantum costs">
                  <table className="table">
                    <thead><tr><th>Algorithm</th><th>Operation</th><th className="r">µs</th></tr></thead>
                    <tbody>{b.results.map((r, i) => <tr key={i}><td>{r.algorithm}</td><td>{r.operation}</td><td className="r num">{fmt1(r.microseconds)}</td></tr>)}</tbody>
                  </table>
                </div>
              )}
            </Card>
          )}
        </Load>
      </div>
      <SurvivalCurve />
      <EnginePipeline />
      <WireSizes />
      <ClassInputs />
      <p className="xsmall muted"><ExternalLink size={11} style={{ display: 'inline' }} aria-hidden /> Sources open outside V.E.R.A. only when you choose to follow them.</p>
    </div>
  );
}

export default function Evidence({ route, hasScan, scanInfo }) {
  const t = useT();
  const tabs = ['reports', 'certin', 'compliance', 'integrity', 'changes', 'detector', 'method'];
  const tab = tabs.includes(route.segments[1]) ? route.segments[1] : 'reports';
  const Body = { reports: Reports, certin: CertIn, compliance: () => <Compliance persona={scanInfo?.persona || 'Banking'} />,
    integrity: Integrity, changes: Changes, detector: Detector, method: Method }[tab];
  const needsScan = tab !== 'method' && tab !== 'detector';
  return (
    <div className="page">
      <PageHead title={t('nav.evidence')} description="Exports, conformance and integrity checks an assessor can verify independently." />
      <Tabs label="Evidence views" active={tab} items={tabs.map((key) => ({ key, label: t(`evidence.${key}`), to: `/evidence/${key}` }))} />
      {needsScan && !hasScan ? <Callout tone="info" title="Nothing scanned yet.">Run a scan first. The method is readable at any time.</Callout> : <Body />}
    </div>
  );
}
