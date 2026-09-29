/* Plan, continued: the order migrations must run in, and a place to try one.
 *
 *   /engine/migration-plan   dependency-ordered waves: what can start now, what waits, what must move together
 *   /harness/migrate         apply a migration to V.E.R.A.'s model of the estate and re-score it
 *   /agent/proposals         changes the assistant proposed, waiting for a person to decide
 *
 * Simulating changes V.E.R.A.'s model only, never a live system. The targets come
 * from each asset's own recommendation, so what is simulated is what Plan
 * recommends. Scanning again returns the model to what is actually deployed.
 */

import { useMemo, useState } from 'react';
import { Check, FlaskConical, GitMerge, RotateCcw, X } from 'lucide-react';
import {
  Badge, Button, ButtonLink, Callout, Card, Dialog, Figure, Load, Seg, Skeleton, useToast,
} from '../components/ui';
import { post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { invalidate, useResource } from '../lib/data';
import { date, fmt, fmt1, pct } from '../lib/format';
import { NEED } from '../lib/labels';
import { openAsset } from '../lib/router';
import { useScan } from '../lib/scan';

const SIM_KEY = 'vera.sim.applied';

function readSimApplied() {
  try { return window.sessionStorage.getItem(SIM_KEY) === '1'; } catch { return false; }
}
function writeSimApplied(on) {
  try {
    if (on) window.sessionStorage.setItem(SIM_KEY, '1');
    else window.sessionStorage.removeItem(SIM_KEY);
  } catch { /* session only */ }
}


export function Waves() {
  const plan = useResource('/engine/migration-plan');
  const [open, setOpen] = useState(null);
  return (
    <Load resource={plan} skeleton={<Skeleton height="30rem" />}>
      {(p) => {
        const waves = Array.from({ length: p.migration_depth }, (_, i) => p.clusters.filter((c) => c.depth === i + 1));
        return (
          <div className="stack-lg">
            <p className="soft">{p.reading}</p>
            <div className="grid-4">
              <Figure label="Can start now" value={fmt(p.migratable_now)} detail="depend on nothing still unmigrated" />
              <Figure label="Waves at minimum" value={fmt(p.migration_depth)} detail="sequential steps, however much runs in parallel" />
              <Figure label="Must move together" value={fmt(p.entangled_clusters)} detail={`groups with mutual dependencies; largest has ${fmt(p.largest_cluster)}`} />
              <Figure label="Dependencies" value={fmt(p.dependency_edges)} detail={`between ${fmt(p.components)} components`} />
            </div>
            <Card title="Start here" description="Unblocked, and the most other migrations wait on them.">
              <ol className="small" style={{ paddingLeft: '1.2rem' }}>
                {p.start_here.slice(0, 8).map((c) => (
                  <li key={c.id} style={{ marginBottom: 4 }}>
                    <button type="button" className="link-btn" style={{ textAlign: 'left' }} onClick={() => openAsset(c.members[0])}>{c.member_names[0]}</button>
                    {c.size > 1 && <span className="muted"> and {c.size - 1} more</span>}
                    <span className="muted"> · unblocks {fmt(c.required_by.length)}</span>
                  </li>
                ))}
              </ol>
            </Card>
            <div className="grid-4" style={{ gridTemplateColumns: `repeat(${Math.min(4, waves.length)}, minmax(0, 1fr))` }}>
              {waves.map((clusters, i) => (
                <Card key={i} title={`Wave ${i + 1}`} description={`${fmt(clusters.length)} group(s) · ${fmt(clusters.reduce((n, c) => n + c.size, 0))} assets`}>
                  <ul className="list-plain small" style={{ maxHeight: '22rem', overflowY: 'auto' }} tabIndex={0} aria-label={`Wave ${i + 1}`}>
                    {clusters.slice(0, open === i ? undefined : 12).map((c) => (
                      <li key={c.id}>
                        <button type="button" className="link-btn" style={{ textAlign: 'left' }} onClick={() => openAsset(c.members[0])}>{c.member_names[0]}</button>
                        {c.size > 1 && <span className="muted"> +{c.size - 1}</span>}
                        {c.entangled && <Badge tone="warn">together</Badge>}
                      </li>
                    ))}
                  </ul>
                  {clusters.length > 12 && <Button size="sm" variant="quiet" onClick={() => setOpen(open === i ? null : i)}>{open === i ? 'Show fewer' : `Show all ${fmt(clusters.length)}`}</Button>}
                </Card>
              ))}
            </div>
            {p.expected && (
              <p className="xsmall muted">For comparison, a random dependency graph of this size would need about {fmt1(p.expected.expected_migration_steps)} steps
                with clusters of about {fmt1(p.expected.expected_cluster_size)} ({p.expected.source}). {p.expected.note}</p>
            )}
          </div>
        );
      }}
    </Load>
  );
}

function Approvals() {
  const auth = useAuth();
  const toast = useToast();
  const proposals = useResource('/agent/proposals');
  const pending = proposals.data?.proposals || [];
  const decide = async (id, verb) => {
    try {
      await post(`/agent/proposals/${id}/${verb}`);
      invalidate('');
      toast(verb === 'approve' ? 'Approved and applied to the model.' : 'Rejected. Nothing changed.');
    } catch (e) { toast(e.message); }
  };
  return (
    <Card title="Proposed by the assistant" description="In approval mode the assistant can propose a migration; it happens only when a person approves it here.">
      {!pending.length ? <p className="small muted">Nothing is waiting. Ask the assistant, for example "migrate the payments gateway to hybrid".</p> : (
        <ul className="list-plain">
          {pending.map((p) => (
            <li key={p.id} className="stack" style={{ gap: 6 }}>
              <strong className="small">{p.summary}</strong>
              <span className="xsmall muted">{p.tool} · proposed {date(p.created_at)} · expires {date(p.expires_at)}</span>
              {p.preview?.changes?.length > 0 && (
                <ul className="xsmall" style={{ paddingLeft: '1.1rem' }}>
                  {p.preview.changes.slice(0, 6).map((c) => <li key={c.asset_id}>{c.name}: {c.from} → <strong>{c.to}</strong></li>)}
                </ul>
              )}
              {auth.can('operate') && (
                <div className="row">
                  <Button size="sm" variant="primary" icon={Check} onClick={() => decide(p.id, 'approve')}>Approve</Button>
                  <Button size="sm" icon={X} onClick={() => decide(p.id, 'reject')}>Reject</Button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

export function Simulate() {
  const auth = useAuth();
  const toast = useToast();
  const scan = useScan();
  const inventory = useResource('/inventory');
  const current = useResource('/scan/current');
  const [target, setTarget] = useState('');
  const [strategy, setStrategy] = useState('hybrid');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [applied, setApplied] = useState(readSimApplied);
  const systems = useMemo(() => [...new Set((inventory.data?.rows || []).map((r) => r.system).filter(Boolean))], [inventory.data]);
  const strategyLabel = strategy === 'pqc_only' ? 'PQC only' : 'Hybrid (classical + PQC)';
  const whereLabel = target.trim() || 'the whole estate';

  const run = async () => {
    setConfirmOpen(false);
    setBusy(true);
    try {
      const r = await post('/harness/migrate', { target: target.trim(), strategy });
      setResult(r);
      setApplied(true);
      writeSimApplied(true);
      invalidate('');
      toast(`Simulated: ${r.migrated} asset(s) migrated in the model.`);
    } catch (e) { toast(e.message); } finally { setBusy(false); }
  };

  const reset = async () => {
    setBusy(true);
    try {
      const estate = current.data?.scan?.estate || 'demo';
      await scan.start({ estate });
      setResult(null);
      setApplied(false);
      writeSimApplied(false);
      toast('Reset started: scanning again to restore what is deployed.');
    } catch (e) { toast(e.message); } finally { setBusy(false); }
  };

  return (
    <div className="stack-lg">
      {applied && (
        <Callout tone="warn" title="Simulation applied — Reset">
          <div className="row" style={{ flexWrap: 'wrap', gap: 'var(--s-3)' }}>
            <span className="grow">V.E.R.A.'s model of the estate has been changed by a simulation. Numbers on Overview, Risk and Plan reflect the simulated migration until you reset.</span>
            <Button size="sm" icon={RotateCcw} busy={busy || scan.running} onClick={reset}>Reset (scan again)</Button>
          </div>
        </Callout>
      )}
      <Callout tone="warn" title="This changes V.E.R.A.'s model of the estate, not your systems.">
        Use it to see what a migration would do to the risk, the milestones and the wire. Reset (or run a scan again) to return to what is deployed.
      </Callout>
      <div className="grid-main-side">
        <div className="stack-lg">
          {auth.can('operate') ? (
            <Card title="Simulate a migration" description="Every quantum-vulnerable asset whose location contains the text below moves to its recommended target.">
              <div className="stack">
                <div className="field">
                  <label htmlFor="sim-target">Where (part of a path, host or system name; empty means the whole estate)</label>
                  <input id="sim-target" className="input" list="sim-systems" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="payments-gateway" />
                  <datalist id="sim-systems">{systems.map((s) => <option key={s} value={s} />)}</datalist>
                </div>
                <div className="field"><span className="label">Strategy</span>
                  <Seg label="Strategy" value={strategy} onChange={setStrategy}
                    options={[{ value: 'hybrid', label: 'Hybrid (classical + PQC)' }, { value: 'pqc_only', label: 'PQC only' }]} />
                  <span className="hint">Hybrid keeps a classical fallback while confidence in the new algorithms grows; it is the transitional default.</span>
                </div>
                <div><Button variant="primary" icon={FlaskConical} busy={busy} onClick={() => setConfirmOpen(true)}>Simulate</Button></div>
              </div>
            </Card>
          ) : <Callout tone="info" title="Your role can read results but not simulate migrations." />}
          {result && (
            <Card title={`${fmt(result.migrated)} migrated in the model`} description={result.message}>
              <div className="stack-lg">
                <div className="grid-4">
                  <Figure label="Mean score" value={`${fmt1(result.before.avg_qirs * 100)} → ${fmt1(result.after.avg_qirs * 100)}`} detail={`${pct(result.qirs_reduction_pct)} lower`} />
                  <Figure label="Still vulnerable" value={`${fmt(result.before.quantum_vulnerable)} → ${fmt(result.after.quantum_vulnerable)}`} detail="in the selection" />
                  <Figure label="Late for DST" value={`${fmt(result.before.negative_slack)} → ${fmt(result.after.negative_slack)}`} detail="need a change they cannot finish in time" />
                  <Figure label="Handshake on the wire" value={`${fmt1(result.wire_cost.multiplier)}×`} detail={`${fmt(result.wire_cost.classical_total_bytes)} → ${fmt(result.wire_cost.pqc_total_bytes)} bytes`} />
                </div>
                <p className="small soft">{result.wire_cost.mtu_note}</p>
                <div className="table-wrap"><table className="table">
                  <thead><tr><th>Asset</th><th>From</th><th>To</th><th>After</th></tr></thead>
                  <tbody>{result.changes.map((c) => (
                    <tr key={c.asset_id} data-clickable onClick={() => openAsset(c.asset_id)}><td className="strong">{c.name}</td><td>{c.from}</td><td>{c.to}</td>
                      <td>{c.still_vulnerable ? <Badge tone="warn">still vulnerable</Badge> : <Badge tone="ok">safe</Badge>}</td></tr>
                  ))}</tbody>
                </table></div>
                {result.skipped?.length > 0 && (
                  <div className="stack">
                    <div className="strong small">Not an algorithm swap ({fmt(result.skipped.length)})</div>
                    <ul className="list-plain small">{result.skipped.map((s) => (
                      <li key={s.asset_id}><button type="button" className="link-btn" onClick={() => openAsset(s.asset_id)}>{s.name}</button>
                        <span className="muted"> · {NEED[s.need] || s.need}: {s.reason}</span></li>
                    ))}</ul>
                  </div>
                )}
                <div className="row">
                  <ButtonLink to="/overview" icon={GitMerge}>See the effect on the Overview</ButtonLink>
                  <Button icon={RotateCcw} busy={busy || scan.running} onClick={reset}>Reset (scan again)</Button>
                </div>
              </div>
            </Card>
          )}
        </div>
        <Approvals />
      </div>
      {confirmOpen && (
        <Dialog title="Apply this simulation?" onClose={() => setConfirmOpen(false)}
          footer={(
            <>
              <Button onClick={() => setConfirmOpen(false)}>Cancel</Button>
              <Button variant="primary" icon={FlaskConical} busy={busy} onClick={run}>Apply simulation</Button>
            </>
          )}>
          <p className="soft">
            This will migrate quantum-vulnerable assets matching <strong>{whereLabel}</strong> using
            strategy <strong>{strategyLabel}</strong> inside V.E.R.A.'s model only — not on your live systems.
            You can reset afterwards by scanning again.
          </p>
        </Dialog>
      )}
    </div>
  );
}
