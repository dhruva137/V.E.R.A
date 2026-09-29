/* Evidence, continued.
 *
 *   /manifest/public-key           the ML-DSA key the manifest is signed with, to verify outside V.E.R.A.
 *   /sarif/validate                SARIF checked against the vendored OASIS schema
 *   /agent/audit                   every tool the assistant called, allowed or refused
 *   /packs, /packs/resolved/{s}    compliance packs: which control each piece of evidence answers
 *   /threat-model                  the CRQC probability curve behind every Z
 *   /engine/state, /engine/run     the scoring pipeline's own checks
 *   /benchmark                     sizes on the wire for every algorithm
 *   /policy-profiles               the X, Y, S, E, C inputs for each class of asset
 */

import { useState } from 'react';
import { CircleCheck, Copy, Download, OctagonX, Play, Trash2 } from 'lucide-react';
import {
  Badge, Button, Card, Dialog, Figure, Kv, Load, Skeleton, useToast,
} from '../components/ui';
import { del, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { invalidate, setCached, useResource } from '../lib/data';
import { dateTime, fmt, fmt1 } from '../lib/format';

function saveText(text, name, type = 'text/plain') {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

export function PublicKey() {
  const key = useResource('/manifest/public-key');
  const toast = useToast();
  return (
    <Load resource={key} skeleton={<Skeleton height="8rem" />}>
      {(k) => (
        <Card title="Signing public key" description="Verify the manifest outside V.E.R.A. with OpenSSL 3.5 or later and this key."
          actions={<>
            <Button size="sm" icon={Copy} onClick={() => navigator.clipboard.writeText(k.public_key_pem).then(() => toast('Key copied.'), () => toast('Copy failed.'))}>Copy</Button>
            <Button size="sm" icon={Download} onClick={() => saveText(k.public_key_pem, 'vera-manifest-public-key.pem')}>Save</Button>
          </>}>
          <Kv rows={[['Algorithm', k.alg], ['Provider', k.provider], ['SHA-256', <code key="h" className="break">{k.public_key_sha256}</code>]]} />
          <pre className="code-block" style={{ marginTop: 'var(--s-3)', maxHeight: '8rem' }} tabIndex={0} role="region"
            aria-label="Manifest signing public key">{k.public_key_pem}</pre>
        </Card>
      )}
    </Load>
  );
}

export function SarifStatus() {
  const v = useResource('/sarif/validate');
  if (!v.data) return null;
  return (
    <p className="xsmall">{v.data.valid ? <Badge tone="ok" icon={CircleCheck}>valid</Badge> : <Badge tone="bad" icon={OctagonX}>{fmt(v.data.errors.length)} errors</Badge>}
      <span className="muted"> {v.data.schema}</span></p>
  );
}

export function AssistantLog() {
  const auth = useAuth();
  const toast = useToast();
  const log = useResource('/agent/audit');
  const [confirm, setConfirm] = useState(false);
  const TONE = { allowed: 'ok', approved: 'ok', refused: 'bad', rejected: 'neutral', proposed: 'primary', error: 'bad', expired: 'neutral' };
  return (
    <Card title="Assistant actions" description="Every tool the assistant called, with the outcome. Refusals are kept too." pad={false}
      actions={auth.can('admin') && <Button size="sm" variant="danger" icon={Trash2} onClick={() => setConfirm(true)}>Clear</Button>}>
      <Load resource={log} skeleton={<div className="card-body"><Skeleton /></div>}>
        {(l) => (l.entries.length ? (
          <div className="table-wrap" style={{ maxHeight: '24rem', overflowY: 'auto' }} tabIndex={0} role="region" aria-label="Assistant actions">
            <table className="table">
              <thead><tr><th>When</th><th>Tool</th><th>Outcome</th><th>Mode</th><th>Detail</th></tr></thead>
              <tbody>{l.entries.map((e) => (
                <tr key={e.id}><td className="nowrap small">{dateTime(e.timestamp)}</td><td className="small strong">{e.tool.replace(/_/g, ' ')}{e.mutating && <Badge tone="warn">changes</Badge>}</td>
                  <td><Badge tone={TONE[e.outcome] || 'neutral'}>{e.outcome}</Badge></td><td className="small">{e.mode}</td>
                  <td className="xsmall muted break">{e.detail}{e.assets_affected ? ` · ${e.assets_affected} assets` : ''}</td></tr>
              ))}</tbody>
            </table>
          </div>
        ) : <div className="card-body small muted">The assistant has not called any tool since the engine started.</div>)}
      </Load>
      {confirm && (
        <Dialog title="Clear the assistant's action list?" onClose={() => setConfirm(false)}
          footer={<><Button onClick={() => setConfirm(false)}>Cancel</Button>
            <Button variant="danger" onClick={async () => {
              try { await del('/agent/audit'); invalidate('/agent/audit'); toast('Cleared. The hash-chained audit log keeps every entry.'); } catch (e) { toast(e.message); }
              setConfirm(false);
            }}>Clear the list</Button></>}>
          <p className="small">This clears the quick list on this screen. Every action also stays in the hash-chained audit log above, which cannot be edited.</p>
        </Dialog>
      )}
    </Card>
  );
}

export function Compliance({ persona }) {
  const auth = useAuth();
  const toast = useToast();
  const packs = useResource('/packs');
  const resolved = useResource(persona ? `/packs/resolved/${encodeURIComponent(persona)}` : null);
  const toggle = async (id, enabled) => {
    try { await post(`/packs/${id}/toggle`, { enabled }); invalidate('/packs'); toast(enabled ? 'Pack plugged in.' : 'Pack unplugged.'); }
    catch (e) { toast(e.message); }
  };
  return (
    <div className="stack-lg">
      <Load resource={resolved} skeleton={<Skeleton height="10rem" />}>
        {(r) => (
          <Card title={`What applies to ${r.sector}`} description={r.board_framing}>
            <div className="stack">
              <div className="table-wrap"><table className="table">
                <thead><tr><th>Control</th><th>Requirement</th><th>Answered by</th></tr></thead>
                <tbody>{r.controls.map((c) => <tr key={c.id}><td className="small"><strong>{c.id}</strong><div className="xsmall muted">{c.framework}</div></td><td className="small">{c.requirement}</td><td className="small soft">{c.answered_by}</td></tr>)}</tbody>
              </table></div>
              <Kv rows={[['Evidence to hand over', r.evidence.join('; ')], ['Dates', r.milestones.map((m) => `${m.year}: ${m.label}${m.binding ? ' (binding)' : ''}`).join(' · ')],
                ['Packs applied', r.packs_applied.join(', ')], ['Sources', r.sources.join('; ')]]} />
              {r.note && <p className="xsmall muted">{r.note}</p>}
            </div>
          </Card>
        )}
      </Load>
      <Load resource={packs} skeleton={<Skeleton height="20rem" />}>
        {(p) => (
          <div className="stack">
            <p className="small soft">{p.note} {fmt(p.enabled)} of {fmt(p.total)} packs are plugged in.</p>
            {p.packs.map((pk) => (
              <Card key={pk.id} title={pk.name} description={`${pk.sector} · v${pk.version} · ${fmt(pk.counts.controls)} controls, ${fmt(pk.counts.milestones)} dates (${fmt(pk.counts.binding_milestones)} binding)`}
                actions={<>{pk.enabled ? <Badge tone="ok">Plugged in</Badge> : <Badge>Unplugged</Badge>}
                  {auth.can('admin') && pk.id !== 'pack.baseline' && <Button size="sm" onClick={() => toggle(pk.id, !pk.enabled)}>{pk.enabled ? 'Unplug' : 'Plug in'}</Button>}</>}>
                <div className="stack small">
                  <p className="soft">{pk.summary}</p>
                  <details><summary>Controls and dates</summary>
                    <ul style={{ paddingLeft: '1.1rem', marginTop: 6 }}>
                      {pk.controls.map((c) => <li key={c.id}><strong>{c.framework}</strong>: {c.requirement}</li>)}
                      {pk.milestones.map((m) => <li key={`${m.year}${m.label}`}>{m.year}: {m.label} <span className="muted">({m.source}{m.binding ? ', binding' : ''})</span></li>)}
                    </ul>
                  </details>
                  {pk.insurance_questions?.length > 0 && <p className="xsmall muted">Questions an insurer or auditor asks: {pk.insurance_questions.join(' · ')}</p>}
                </div>
              </Card>
            ))}
          </div>
        )}
      </Load>
    </div>
  );
}

export function SurvivalCurve() {
  const model = useResource('/threat-model');
  return (
    <Load resource={model} skeleton={<Skeleton height="16rem" />}>
      {(m) => {
        const W = 720; const H = 260; const pad = 40;
        const pts = m.curves;
        const x0 = pts[0].year; const x1 = pts[pts.length - 1].year;
        const x = (yr) => pad + ((yr - x0) / (x1 - x0)) * (W - pad - 12);
        const y = (p) => H - 28 - p * (H - 28 - 12);
        const line = (key) => pts.map((p, i) => `${i ? 'L' : 'M'}${x(p.year).toFixed(1)},${y(p[key]).toFixed(1)}`).join(' ');
        const band = `${pts.map((p, i) => `${i ? 'L' : 'M'}${x(p.year).toFixed(1)},${y(p.pessimistic_prob).toFixed(1)}`).join(' ')} ${[...pts].reverse().map((p) => `L${x(p.year).toFixed(1)},${y(p.optimistic_prob).toFixed(1)}`).join(' ')} Z`;
        const ticks = []; for (let yr = Math.ceil(x0 / 5) * 5; yr <= x1; yr += 5) ticks.push(yr);
        return (
          <Card title="Probability of a cryptographically relevant quantum computer, by year"
            description={`${m.source}. Band: earliest to latest reading; line: median. ${m.functional_form}.`}>
            <svg viewBox={`0 0 ${W} ${H}`} width="100%" role="img" aria-label="Probability of a CRQC by year, median and band">
              {[0, 0.25, 0.5, 0.75, 1].map((p) => (
                <g key={p}><line x1={pad} x2={W - 12} y1={y(p)} y2={y(p)} stroke="var(--line)" />
                  <text x={pad - 6} y={y(p) + 4} textAnchor="end" fontSize="11" fill="var(--text-3)">{p * 100}%</text></g>
              ))}
              {ticks.map((t) => <text key={t} x={x(t)} y={H - 8} textAnchor="middle" fontSize="11" fill="var(--text-3)">{t}</text>)}
              <path d={band} fill="var(--warn-weak)" stroke="none" />
              <path d={line('median_prob')} fill="none" stroke="var(--warn-text)" strokeWidth="2" />
              {m.anchors.map((a) => <circle key={a.year} cx={x(a.year)} cy={y(a.median_prob)} r="3.5" fill="var(--text)"><title>{a.year}: {fmt1(a.median_prob * 100)}% (survey anchor)</title></circle>)}
            </svg>
            <p className="xsmall muted">Dots are the survey's anchor points; the curve between them is fitted, not surveyed. {m.caveat}</p>
          </Card>
        );
      }}
    </Load>
  );
}

export function EnginePipeline() {
  const auth = useAuth();
  const toast = useToast();
  const state = useResource('/engine/state');
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try { const r = await post('/engine/run'); setCached('/engine/state', { ...state.data, ...r, checks: r.checks }); toast(`Pipeline run ${r.run_id}: ${r.checks_passed ? 'every check passed' : 'a check failed'}.`); }
    catch (e) { toast(e.message); } finally { setBusy(false); }
  };
  return (
    <Load resource={state} skeleton={<Skeleton height="12rem" />}>
      {(s) => (
        <Card title="Scoring pipeline self-checks" description={`Run ${s.run_id} under the ${s.stats.policy} policy.`}
          actions={<>{s.checks_passed ? <Badge tone="ok" icon={CircleCheck}>All checks pass</Badge> : <Badge tone="bad" icon={OctagonX}>A check failed</Badge>}
            {auth.can('operate') && <Button size="sm" icon={Play} busy={busy} onClick={run}>Run again</Button>}</>}>
          <div className="stack">
            <div className="grid-4">
              <Figure label="Ranked" value={fmt(s.stats.ranked)} detail={`of ${fmt(s.stats.submitted)} submitted`} />
              <Figure label="Quarantined" value={fmt(s.stats.quarantined)} detail="refused with a reason" />
              <Figure label="Confirmed by 2+ planes" value={fmt(s.stats.corroborated)} detail={`${fmt(s.stats.observations)} observations`} />
              <Figure label="Flagged for review" value={fmt(s.stats.flagged)} detail={`mean confidence ${fmt1(s.stats.mean_confidence * 100)}%`} />
            </div>
            <ul className="list-plain small">
              {s.checks.map((c) => <li key={c.key} className="row">{c.passed ? <CircleCheck size={14} color="var(--ok)" aria-hidden /> : <OctagonX size={14} color="var(--bad)" aria-hidden />}
                <span className="grow">{c.description}</span>{c.detail && <span className="xsmall muted">{c.detail}</span>}</li>)}
            </ul>
          </div>
        </Card>
      )}
    </Load>
  );
}

export function WireSizes() {
  const b = useResource('/benchmark');
  return (
    <Load resource={b} skeleton={<Skeleton height="12rem" />}>
      {(d) => (
        <Card title="Sizes on the wire" description={d.handshake.provenance} pad={false}>
          <div className="table-wrap"><table className="table">
            <thead><tr><th>Algorithm</th><th>Kind</th><th className="r">Public key</th><th className="r">Payload</th><th>Standard</th><th>Quantum-safe</th></tr></thead>
            <tbody>{[...d.kem, ...d.signature].map((r) => (
              <tr key={r.name}><td className="strong">{r.name}</td><td className="small">{r.category === 'kem' ? 'Key exchange' : 'Signature'}</td>
                <td className="r num">{fmt(r.public_key_bytes)} B</td><td className="r num">{fmt(r.payload_bytes)} B <span className="xsmall muted">{r.payload_label}</span></td>
                <td className="small">{r.standard}</td><td>{r.quantum_safe ? <Badge tone="ok">yes</Badge> : <Badge tone="warn">no</Badge>}</td></tr>
            ))}</tbody>
          </table></div>
          <div className="card-foot">{d.handshake.mtu_note}</div>
        </Card>
      )}
    </Load>
  );
}

export function ClassInputs() {
  const p = useResource('/policy-profiles');
  return (
    <Load resource={p} skeleton={<Skeleton height="12rem" />}>
      {(d) => (
        <Card title="Inputs for each kind of asset" description={d.note} pad={false}>
          <div className="table-wrap" style={{ maxHeight: '28rem', overflowY: 'auto' }} tabIndex={0} role="region" aria-label="Inputs by asset kind">
            <table className="table">
              <thead><tr><th>Kind</th><th className="r">X confidentiality</th><th className="r">X trust</th><th className="r">Y effort</th><th className="r">S</th><th className="r">E</th><th className="r">C</th><th>Why</th></tr></thead>
              <tbody>{d.profiles.map((r) => (
                <tr key={r.key}><td className="strong small">{r.label}</td><td className="r num">{fmt1(r.x_c)} yr</td><td className="r num">{fmt1(r.x_i)} yr</td><td className="r num">{fmt1(r.y)} yr</td>
                  <td className="r num">{fmt1(r.s)}</td><td className="r num">{fmt1(r.e)}</td><td className="r num">{fmt1(r.c)}</td><td className="xsmall soft" style={{ minWidth: '18rem' }}>{r.rationale}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </Card>
      )}
    </Load>
  );
}

