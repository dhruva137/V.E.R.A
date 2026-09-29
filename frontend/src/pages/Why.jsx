/* Why V.E.R.A.: what it does that other crypto-discovery tools do not, shown rather than claimed.
 *
 * Every number here comes from a result file or from running the shipped detector now:
 *   /api/detector       measured on libraries never seen in training (research/results/*.json, with commits)
 *   /api/detector/live  the shipped model run on the bundled stripped binaries (demo/detector/), changing nothing
 * The public-repository comparison is from READMEs we read on 28 Sep 2026.
 */
import { useState } from 'react';
import { Binary, CircleCheck, CircleX, Cpu, FileCheck2, Play, ShieldCheck, Sparkles } from 'lucide-react';
import { Badge, Button, Callout, Card, Load, PageHead, Skeleton, useToast } from '../components/ui';
import { get } from '../lib/api';
import { useResource } from '../lib/data';
import { fmt } from '../lib/format';
import { Link } from '../lib/router';

const PILLARS = [
  { icon: ShieldCheck, title: 'Certified, not confident',
    them: 'Report every hit as if it were certain, or behind a fixed confidence cut-off.',
    us: 'Every binary finding carries a q-value: a provable bound on how often findings like it are wrong.' },
  { icon: Binary, title: 'Reads the black box',
    them: 'Need symbols, imports, version banners or known constant tables.',
    us: 'Finds cryptographic functions in stripped x86-64, AArch64 and ARM32 code with none of those.' },
  { icon: Cpu, title: 'Sovereign and air-gapped',
    them: 'Cloud services or heavy models; key material sometimes read.',
    us: 'One laptop, CPU only, offline by default, metadata only: no key byte is ever read.' },
  { icon: FileCheck2, title: 'Proof an auditor can check',
    them: 'A CBOM file, taken on trust.',
    us: 'CycloneDX 1.7 checked against CERT-In Table 9, signed with ML-DSA-65, every number traced to its source.' },
];

// What the eight most active public SIH26164 repositories say in their READMEs (read 28 Sep 2026).
const FIELD = [
  ['Container images', '8 of 8', true], ['Mosca risk scoring', '7 of 8', true], ['CycloneDX CBOM', '6 of 8', true],
  ['CERT-In reference', '1 of 8', true], ['Certified false-discovery bound', '0 of 8', true],
  ['Learned detection in stripped binaries', '0 of 8', true],
];

function Prevalence({ block }) {
  const rows = block.rows;
  const [i, setI] = useState(Math.min(1, rows.length - 1));
  const r = rows[i];
  const bar = (v, tone) => (
    <div className="why-bar"><div className={`why-bar-fill ${tone}`} style={{ width: `${Math.max(2, v * 100)}%` }} /></div>
  );
  return (
    <Card title="When crypto is rare, confidence lies"
      description="Share of flagged functions that are not cryptographic, on libraries the model never saw. Move the slider: real binaries are mostly not crypto.">
      <div className="stack-lg">
        <div className="field">
          <label htmlFor="prev">Share of functions that are cryptographic: <strong>{r.prevalence === 'natural' ? 'natural (about a third)' : `${Math.round(Number(r.prevalence) * 100)}%`}</strong></label>
          <input id="prev" type="range" min="0" max={rows.length - 1} step="1" value={i} onChange={(e) => setI(Number(e.target.value))} />
        </div>
        <div className="stack">
          <div className="row small"><span className="grow">A fixed 0.9 confidence cut-off (how most tools decide)</span><strong className="num">{(r.fixed_threshold_fdp * 100).toFixed(1)}% wrong</strong></div>
          {bar(r.fixed_threshold_fdp, 'bad')}
          <div className="row small"><span className="grow">V.E.R.A., conformal selection at α = 0.1</span><strong className="num">{(r.conformal_fdp * 100).toFixed(1)}% wrong</strong></div>
          {bar(r.conformal_fdp, 'ok')}
        </div>
        <p className="xsmall muted">Source: {block.file} @ {block.commit}. The bound holds as crypto gets rarer; the fixed cut-off does not.</p>
      </div>
    </Card>
  );
}

function Live() {
  const toast = useToast();
  const [run, setRun] = useState(null);
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try { setRun(await get('/detector/live')); } catch (e) { toast(e.message); } finally { setBusy(false); }
  };
  return (
    <Card title="Run it yourself, now"
      description="The shipped detector on four stripped, statically linked programs: two SipHash builds no signature tool recognises, and two with no cryptography. Nothing in your estate changes."
      actions={<Button variant="primary" icon={Play} busy={busy} onClick={go}>{run ? 'Run again' : 'Run the certified detector'}</Button>}>
      {!run && !busy && <p className="small muted">Takes about twenty seconds on this machine.</p>}
      {busy && <Skeleton lines={4} />}
      {run && !busy && (
        <div className="stack">
          <Callout tone={run.correct === run.total ? 'ok' : 'warn'} title={`${run.correct} of ${run.total} programs judged correctly.`}>
            Ground truth comes from the unstripped twin of each build.
          </Callout>
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Program</th><th>Truth</th><th>V.E.R.A. says</th><th>Found by</th><th className="r">q-value</th><th className="r">Functions</th><th className="r">Time</th></tr></thead>
            <tbody>{run.programs.map((p) => {
              const right = p.flagged === p.contains_crypto;
              return (
                <tr key={p.name} className="row-in">
                  <td><div className="strong">{p.name}</div><div className="xsmall muted">{p.what}</div></td>
                  <td>{p.contains_crypto ? <Badge tone="info">crypto</Badge> : <Badge>no crypto</Badge>}</td>
                  <td><span className={`row small ${right ? 'det-ok' : 'det-bad'}`}>{right ? <CircleCheck size={14} aria-hidden /> : <CircleX size={14} aria-hidden />}
                    {p.flagged ? 'cryptography, certified' : 'nothing to report'}</span></td>
                  <td className="small">{p.found_by.length ? p.found_by.map((x) => x.replace('_', ' ')).join(', ') : '—'}</td>
                  <td className="r num">{p.q_value == null ? '—' : <strong>{p.q_value.toFixed(3)}</strong>}</td>
                  <td className="r num">{p.functions_selected ? `${fmt(p.functions_selected)} of ${fmt(p.functions_scored)}` : fmt(p.functions_scored)}</td>
                  <td className="r num">{p.seconds} s</td>
                </tr>
              );
            })}</tbody>
          </table></div>
          <p className="xsmall muted">q-value: the lowest false-discovery level at which this program's most cryptographic function is still selected.
            Reported at α = {run.programs.find((p) => p.alpha)?.alpha ?? 0.1}. The same finding, with its q-value, is written into the CycloneDX CBOM.</p>
        </div>
      )}
    </Card>
  );
}

export default function Why() {
  const det = useResource('/detector');
  return (
    <div className="page">
      <PageHead title="Why V.E.R.A."
        description="Verified Enumeration of Risky Algorithms. To our knowledge, the first crypto-discovery engine in India, and the first CBOM tool we could find anywhere, that certifies every finding with a provable error bound." />
      <div className="stack-lg">
        <div className="grid-2 why-pillars">
          {PILLARS.map(({ icon: Icon, title, them, us }) => (
            <div key={title} className="card card-pad why-pillar">
              <div className="row"><span className="why-icon"><Icon size={18} aria-hidden /></span><span className="strong">{title}</span></div>
              <div className="why-vs">
                <div><div className="xsmall muted">Typical tools</div><p className="small">{them}</p></div>
                <div><div className="xsmall strong why-us">V.E.R.A.</div><p className="small">{us}</p></div>
              </div>
            </div>
          ))}
        </div>
        <Load resource={det} skeleton={<Skeleton lines={5} />}>
          {(d) => (d.threshold_vs_conformal ? <Prevalence block={d.threshold_vs_conformal} /> : null)}
        </Load>
        <Live />
        <Card title="The field, checked" description="What the eight most active public SIH26164 repositories say about themselves (READMEs read on 28 Sep 2026). Containers, Mosca and CycloneDX are now table stakes; the certified bound is not.">
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Capability</th><th className="r">Public repos that mention it</th><th>V.E.R.A.</th></tr></thead>
            <tbody>{FIELD.map(([cap, n, ours]) => (
              <tr key={cap}><td>{cap}</td><td className="r num">{n}</td><td>{ours && <span className="row small det-ok"><CircleCheck size={14} aria-hidden />built and measured</span>}</td></tr>
            ))}</tbody>
          </table></div>
          <p className="xsmall muted" style={{ marginTop: 'var(--s-3)' }}>Public search covers names, descriptions and READMEs only, so this supports the claim "to our knowledge" and cannot prove it.</p>
        </Card>
        <div className="row-wrap">
          <Link to="/evidence/detector" className="btn"><Sparkles size={16} aria-hidden /> Detector evidence</Link>
          <Link to="/evidence/certin" className="btn"><FileCheck2 size={16} aria-hidden /> CERT-In Table 9 check</Link>
          <Link to="/evidence/integrity" className="btn"><ShieldCheck size={16} aria-hidden /> Verify the signed evidence</Link>
        </div>
      </div>
    </div>
  );
}
