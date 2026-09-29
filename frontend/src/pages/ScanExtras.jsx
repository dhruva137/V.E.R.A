/* The rest of Scan: bundled datasets, live endpoints, sensors and coverage,
 * adding assets no scanner can reach, finding reused keys, and every past job.
 *
 * Each block is one engine capability, called directly:
 *   /scan/demo, /estate/metadata          the synthetic generator estate (195 findings)
 *   /scan/vault, /vault/summary           key-manager metadata (HSM, KMIP, cloud KMS)
 *   /scan/tls, /scan/ssh, /scan/targets   live probes of hosts the operator names
 *   /discovery/plugins, /adapters,        which sensors exist, which are running,
 *   /discovery/provenance                 and how much each kind of evidence is worth
 *   /profiles, /profiles/{key}/fit        which sensors a sector needs, and the gap
 *   /assets/register, /assets/import-csv  inventory from records: HSM configs, offline systems
 *   /discovery/scan-tree                  one private key found in several places
 *   /scan/jobs, /scan/jobs/{id}           every job and its event log
 */

import { useState } from 'react';
import { CircleCheck, CircleHelp, Database, FileUp, Fingerprint, KeyRound, Network, Play, Plus, ServerCog } from 'lucide-react';
import {
  Badge, Button, Callout, Card, Dialog, Load, Meter, Seg, Skeleton, useToast,
} from '../components/ui';
import { get, post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { invalidate, useResource } from '../lib/data';
import { fmt, fmt1, pct, shortPath } from '../lib/format';

function useRun() {
  const toast = useToast();
  const [busy, setBusy] = useState('');
  const run = async (key, fn, done) => {
    setBusy(key);
    try {
      const result = await fn();
      invalidate('');
      toast(done ? done(result) : result?.message || 'Done.');
      return result;
    } catch (e) {
      toast(e.message);
      return null;
    } finally {
      setBusy('');
    }
  };
  return [busy, run];
}

export function Datasets({ persona }) {
  const auth = useAuth();
  const meta = useResource('/estate/metadata');
  const vault = useResource('/vault/summary');
  const [busy, run] = useRun();
  const [merge, setMerge] = useState(true);
  const q = `org_persona=${encodeURIComponent(persona)}`;
  return (
    <Card title="Bundled datasets" description="Synthetic estates that ship with V.E.R.A., for trying it without touching a real system.">
      <ul className="list-plain">
        <li className="stack" style={{ gap: 'var(--s-2)' }}>
          <div className="row"><Database size={16} aria-hidden /><strong className="grow">{meta.data?.organisation || 'Synthetic generator estate'}</strong>
            {meta.data?.synthetic && <Badge>synthetic</Badge>}</div>
          <p className="small soft">{meta.data?.description}</p>
          {meta.data && <p className="xsmall muted">{fmt(meta.data.tls_services)} TLS services · {fmt(meta.data.keystore_entries)} keystore entries ·{' '}
            {fmt(meta.data.config_entries)} config entries · {fmt(meta.data.source_entries)} source findings · seed {meta.data.seed}</p>}
          {auth.can('scan') && <div><Button size="sm" icon={Play} busy={busy === 'demo'}
            onClick={() => run('demo', () => post(`/scan/demo?${q}`))}>Load this estate</Button></div>}
        </li>
        <li className="stack" style={{ gap: 'var(--s-2)' }}>
          <div className="row"><KeyRound size={16} aria-hidden /><strong className="grow">Key managers: HSM, KMIP, cloud KMS</strong>
            {vault.data?.synthetic && <Badge>synthetic</Badge>}</div>
          {vault.data && (
            <>
              <p className="small soft">{fmt(vault.data.objects)} objects: {Object.entries(vault.data.by_source || {}).map(([k, n]) => `${fmt(n)} ${k.replace('vault_', '').replace('_', ' ')}`).join(' · ')}.
                {' '}Key material present: {vault.data.key_material_present ? 'yes' : 'no, metadata only'}.</p>
              {vault.data.blind_spots?.length > 0 && <p className="xsmall muted">Not reachable by any sensor: {vault.data.blind_spots.join('; ')}</p>}
            </>
          )}
          {auth.can('scan') && (
            <div className="row-wrap">
              <label className="check small"><input type="checkbox" checked={merge} onChange={(e) => setMerge(e.target.checked)} />
                Add to the current estate instead of replacing it</label>
              <Button size="sm" icon={Play} busy={busy === 'vault'}
                onClick={() => run('vault', () => post(`/scan/vault?${q}&merge=${merge}`))}>Read the key managers</Button>
            </div>
          )}
        </li>
      </ul>
    </Card>
  );
}

export function LiveEndpoints() {
  const auth = useAuth();
  const saved = useResource('/scan/targets');
  const ntro = useResource('/ntro-mode');
  const [kind, setKind] = useState('tls');
  const [hosts, setHosts] = useState('');
  const [busy, run] = useRun();
  const list = hosts.split(/[\s,]+/).map((h) => h.trim()).filter(Boolean);
  if (!auth.can('scan')) return null;
  return (
    <Card title="Live endpoints" description="Complete a handshake with hosts you name and record what they negotiate. Only the hosts listed here are contacted.">
      <div className="stack">
        {ntro.data?.offline?.enforced && (
          <Callout tone="info" title="The offline guard is on.">Only this machine and hosts an operator names are reachable. Hosts typed here count as named.</Callout>
        )}
        <Seg label="Protocol" value={kind} onChange={setKind} options={[{ value: 'tls', label: 'TLS' }, { value: 'ssh', label: 'SSH' }]} />
        <div className="field">
          <label htmlFor="hosts">Hosts (host or host:port, one per line)</label>
          <textarea id="hosts" className="textarea mono" rows={3} value={hosts} onChange={(e) => setHosts(e.target.value)}
            placeholder={kind === 'tls' ? 'pay.example.in:443' : 'bastion.example.in:22'} />
        </div>
        {kind === 'tls' && saved.data?.tls_targets?.length > 0 && (
          <p className="xsmall muted">Saved list ({fmt(saved.data.tls_targets.length)}):{' '}
            <button type="button" className="link-btn" onClick={() => setHosts(saved.data.tls_targets.join('\n'))}>use it</button>
            {' '}· {saved.data.tls_targets.slice(0, 6).join(', ')}{saved.data.tls_targets.length > 6 ? ' …' : ''}</p>
        )}
        <div><Button icon={Network} busy={busy === 'probe'} disabled={!list.length}
          onClick={() => run('probe', () => post(`/scan/${kind}`, { targets: list }))}>Probe {fmt(list.length)} host{list.length === 1 ? '' : 's'}</Button></div>
      </div>
    </Card>
  );
}

export function Sensors() {
  const plugins = useResource('/discovery/plugins');
  const provenance = useResource('/discovery/provenance');
  const profiles = useResource('/profiles');
  const [profile, setProfile] = useState('');
  const key = profile || profiles.data?.default;
  const fit = useResource(key ? `/profiles/${key}/fit` : null);
  return (
    <div className="stack-lg">
      <Load resource={plugins} skeleton={<Skeleton height="20rem" />}>
        {(p) => (
          <Card title="Sensors" description={`${fmt(p.coverage.active)} of ${fmt(p.coverage.total_plugins)} sensors are running. The rest say why not.`} pad={false}>
            <div className="table-wrap">
              <table className="table">
                <thead><tr><th>Sensor</th><th>Reads</th><th>Evidence worth</th><th>State</th></tr></thead>
                <tbody>
                  {p.plugins.map((s) => (
                    <tr key={s.id}>
                      <td><div className="strong">{s.name}</div><div className="xsmall muted">{s.zone}</div></td>
                      <td className="small soft" style={{ maxWidth: '28rem' }}>{s.description}</td>
                      <td className="small"><div className="strong num">{fmt1(s.confidence * 100)}%</div><div className="xsmall muted">{s.provenance_label}</div></td>
                      <td>{s.available ? <Badge tone="ok" icon={CircleCheck}>Running</Badge>
                        : <div className="stack" style={{ gap: 2 }}><Badge tone="warn" icon={CircleHelp}>Not running</Badge><span className="xsmall muted">{s.unavailable_reason}</span></div>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}
      </Load>
      <div className="grid-2">
        <Load resource={profiles} skeleton={<Skeleton height="16rem" />}>
          {(pr) => (
            <Card title="What a sector needs" description="Which sensors matter for this kind of organisation, and what is missing."
              actions={<select className="select" style={{ height: '2rem', width: '14rem' }} aria-label="Sector profile" value={key}
                onChange={(e) => setProfile(e.target.value)}>{pr.profiles.map((x) => <option key={x.key} value={x.key}>{x.label}</option>)}</select>}>
              <Load resource={fit} skeleton={<Skeleton />}>
                {(f) => (
                  <div className="stack">
                    <p className="small soft">{f.profile.summary}</p>
                    <div className="row"><span className="small grow">Required sensors running</span><span className="strong num">{pct(f.required_sensor_coverage_pct)}</span></div>
                    <Meter value={f.required_sensor_coverage_pct / 100} tone={f.required_sensor_coverage_pct === 100 ? 'ok' : 'warn'} label="Required sensor coverage" />
                    <ul className="list-plain small">
                      {f.sensors.map((s) => (
                        <li key={s.plugin_id} className="row" style={{ alignItems: 'flex-start' }}>
                          {s.active ? <CircleCheck size={14} color="var(--ok)" aria-hidden /> : <CircleHelp size={14} color="var(--warn-text)" aria-hidden />}
                          <span className="grow"><strong>{s.plugin_id}</strong> ({s.criticality}): {s.reason}</span>
                        </li>
                      ))}
                    </ul>
                    {f.profile.lead_with && <p className="xsmall muted">Lead with: {f.profile.lead_with}</p>}
                  </div>
                )}
              </Load>
            </Card>
          )}
        </Load>
        <Load resource={provenance} skeleton={<Skeleton height="16rem" />}>
          {(pv) => (
            <Card title="What each kind of evidence is worth" description="Confidence V.E.R.A. gives a finding by how it was found.">
              <ul className="list-plain small">
                {pv.grades.map((g) => (
                  <li key={g.key}><div className="row"><strong className="grow">{g.label}</strong><span className="num strong">{fmt1(g.confidence * 100)}%</span></div>
                    <div className="xsmall muted">{g.rationale}</div></li>
                ))}
              </ul>
            </Card>
          )}
        </Load>
      </div>
      <Load resource={plugins} skeleton={null}>
        {(p) => (
          <Card title="Connectors for key managers and HSMs" description="What each adapter can and cannot prove.">
            <div className="grid-2">
              {p.adapters.map((a) => (
                <div key={a.id} className="card card-pad stack" style={{ gap: 'var(--s-2)' }}>
                  <div className="row"><ServerCog size={16} aria-hidden /><strong>{a.name}</strong></div>
                  {a.coverage_contract?.proves && <p className="xsmall"><strong>Proves:</strong> {a.coverage_contract.proves.join('; ')}</p>}
                  {a.coverage_contract?.cannot_prove && <p className="xsmall muted"><strong>Cannot prove:</strong> {a.coverage_contract.cannot_prove.join('; ')}</p>}
                  {a.measurement && <p className="xsmall muted">{typeof a.measurement === 'string' ? a.measurement : JSON.stringify(a.measurement)}</p>}
                </div>
              ))}
            </div>
          </Card>
        )}
      </Load>
    </div>
  );
}

const EMPTY_ASSET = { name: '', source_location: '', asset_class: 'tls-server', algorithm: '', key_size: '', owner: '' };

export function AddAssets({ persona }) {
  const auth = useAuth();
  const classes = useResource('/asset-classes');
  const [busy, run] = useRun();
  const [asset, setAsset] = useState(EMPTY_ASSET);
  const [file, setFile] = useState(null);
  const [root, setRoot] = useState('');
  const [mergeTree, setMergeTree] = useState(false);
  const [tree, setTree] = useState(null);
  const q = `org_persona=${encodeURIComponent(persona)}`;
  if (!auth.can('scan')) return <Callout tone="info" title="Your role can read results but not add assets." />;
  const set = (k) => (e) => setAsset({ ...asset, [k]: e.target.value });
  return (
    <div className="stack-lg">
      <div className="grid-2">
        <Card title="Register an asset by hand" description="For what no scanner reaches: an HSM configured by a vendor, an offline system, a record in a spreadsheet.">
          <form className="stack" onSubmit={(e) => {
            e.preventDefault();
            run('register', () => post(`/assets/register?${q}`, [{ ...asset, key_size: asset.key_size ? Number(asset.key_size) : null,
              algorithm: asset.algorithm || null, owner: asset.owner || null }]), (r) => r.message).then((r) => r && setAsset(EMPTY_ASSET));
          }}>
            <div className="grid-2">
              <div className="field"><label htmlFor="an">Name</label><input id="an" className="input" value={asset.name} onChange={set('name')} /></div>
              <div className="field"><label htmlFor="al">Where it is</label><input id="al" className="input" value={asset.source_location} onChange={set('source_location')} placeholder="hsm://dc1/slot3/signing" /></div>
              <div className="field"><label htmlFor="ac">Kind</label>
                <select id="ac" className="select" value={asset.asset_class} onChange={set('asset_class')}>
                  {(classes.data?.classes || []).map((c) => <option key={c.key} value={c.key}>{c.label}</option>)}
                </select></div>
              <div className="field"><label htmlFor="aa">Algorithm</label><input id="aa" className="input" value={asset.algorithm} onChange={set('algorithm')} placeholder="RSA" /></div>
              <div className="field"><label htmlFor="ak">Key size (bits)</label><input id="ak" className="input" inputMode="numeric" value={asset.key_size} onChange={set('key_size')} /></div>
              <div className="field"><label htmlFor="ao">Owner</label><input id="ao" className="input" value={asset.owner} onChange={set('owner')} /></div>
            </div>
            {classes.data && <p className="xsmall muted">{classes.data.classes.find((c) => c.key === asset.asset_class)?.rationale}</p>}
            <div><Button type="submit" variant="primary" icon={Plus} busy={busy === 'register'} disabled={!asset.name || !asset.source_location}>Add to the inventory</Button></div>
          </form>
        </Card>
        <Card title="Import a spreadsheet" description="A CSV with at least a name or location column. Column names are matched loosely (algorithm, key size, owner, expiry…).">
          <div className="stack">
            <div className="field"><label htmlFor="csv">CSV file</label><input id="csv" type="file" accept=".csv,text/csv" onChange={(e) => setFile(e.target.files?.[0] || null)} /></div>
            <div><Button icon={FileUp} busy={busy === 'csv'} disabled={!file} onClick={() => run('csv', () => {
              const form = new FormData(); form.append('file', file); return post(`/assets/import-csv?${q}`, form);
            }, (r) => r.message)}>Import</Button></div>
          </div>
        </Card>
      </div>
      <Card title="Find reused private keys" description="Scans a folder tree for private keys and groups them by fingerprint. The same key in several places means compromising any one of them compromises all.">
        <div className="stack">
          <div className="row" style={{ alignItems: 'flex-end' }}>
            <div className="field grow"><label htmlFor="root">Folder</label><input id="root" className="input mono" value={root} onChange={(e) => setRoot(e.target.value)} placeholder={'D:\\builds'} /></div>
            <Button icon={Fingerprint} busy={busy === 'tree'} disabled={!root.trim()} onClick={() => run('tree', () => post('/discovery/scan-tree', { root: root.trim(), merge: mergeTree }), (r) => `${fmt(r.found)} key(s) found, ${fmt(r.reused_key_count)} reused.`).then((r) => r && setTree(r))}>Scan</Button>
          </div>
          <label className="check small"><input type="checkbox" checked={mergeTree} onChange={(e) => setMergeTree(e.target.checked)} /> Also add what is found to the inventory</label>
          {tree && (
            <div className="stack">
              <p className="small">{fmt(tree.found)} private key(s) under <code>{tree.root}</code>; {fmt(tree.needs_review)} need review; {fmt(tree.reused_key_count)} reused.</p>
              {tree.reuse_clusters.map((c) => (
                <Callout key={c.fingerprint} tone="bad" title={`One ${c.algorithm || ''} key in ${c.occurrences} places (fingerprint ${c.fingerprint}…)`}>
                  <ul style={{ paddingLeft: '1.1rem' }}>{c.locations.map((l) => <li key={l}><code className="break">{shortPath(l)}</code></li>)}</ul>
                </Callout>
              ))}
              <p className="xsmall muted">{tree.note}</p>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}

export function Jobs() {
  const jobs = useResource('/scan/jobs');
  const [open, setOpen] = useState(null);
  const [log, setLog] = useState(null);
  const show = async (id) => { setOpen(id); setLog(null); try { setLog(await get(`/scan/jobs/${id}`)); } catch (e) { setLog({ error: e.message }); } };
  return (
    <Card title="Scan jobs" description="The last jobs on this engine, with every event each one recorded." pad={false}>
      <Load resource={jobs} skeleton={<div className="card-body"><Skeleton /></div>}>
        {(rows) => (rows.length ? (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>Job</th><th>Status</th><th className="r">Targets</th><th className="r">Events</th><th>Result</th><th /></tr></thead>
              <tbody>
                {rows.map((j) => (
                  <tr key={j.job_id}><td className="mono xsmall">{j.job_id.slice(0, 8)}</td>
                    <td>{j.status === 'done' ? <Badge tone="ok">done</Badge> : j.status === 'failed' ? <Badge tone="bad">failed</Badge> : <Badge tone="primary">{j.status}</Badge>}</td>
                    <td className="r num">{fmt(j.targets.length)}</td><td className="r num">{fmt(j.events)}</td>
                    <td className="small">{j.result ? `${fmt(j.result.assets)} assets, ${fmt(j.result.quantum_vulnerable)} vulnerable` : j.error || '—'}</td>
                    <td className="r"><Button size="sm" onClick={() => show(j.job_id)}>Event log</Button></td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="card-body muted">No jobs yet on this engine run.</div>)}
      </Load>
      {open && (
        <Dialog title={`Job ${open.slice(0, 8)}: event log`} onClose={() => setOpen(null)} className="dialog-wide">
          {!log ? <Skeleton /> : log.error ? <Callout tone="bad" title={log.error} /> : (
            <div className="table-wrap" style={{ maxHeight: '60vh', overflowY: 'auto' }} tabIndex={0} role="region" aria-label="Event log">
              <table className="table">
                <thead><tr><th className="r">#</th><th className="r">At</th><th>Event</th><th>Detail</th></tr></thead>
                <tbody>
                  {log.event_log.map((e) => (
                    <tr key={e.seq}><td className="r num muted">{e.seq}</td><td className="r num">{fmt1(e.at)} s</td><td className="small strong">{e.type.replace(/_/g, ' ')}</td>
                      <td className="xsmall break">{e.collector ? `${e.collector} · ` : ''}{e.target ? shortPath(e.target) : ''}{e.findings !== undefined ? ` · ${e.findings} findings` : ''}{e.error ? ` · ${e.error}` : ''}{e.type === 'resolved' ? ` · ${e.findings} findings → ${e.assets} assets` : ''}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Dialog>
      )}
    </Card>
  );
}

