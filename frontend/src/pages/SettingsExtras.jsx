/* Settings, continued.
 *
 *   /scan/clear                       empty the current estate (admin)
 *   /agent/tools                      what the assistant can call, and which calls change things
 *   /agents/pool, /agents/keys,       optional cloud models behind a gateway, with measured
 *   /agents/probe                     reliability. Blocked while the offline guard is on.
 *   /engine/policy/presets, /preview  change the scoring policy only after seeing what it moves
 *   /access-keys, /v1/manifest        keys for another system to call V.E.R.A.'s tools
 */

import { useState } from 'react';
import { CircleCheck, CircleHelp, Copy, KeyRound, Play, Plus, Save, Trash2 } from 'lucide-react';
import {
  Badge, Button, Callout, Card, Dialog, Figure, Kv, Load, Skeleton, useToast,
} from '../components/ui';
import { del, post, put } from '../lib/api';
import { useAuth } from '../lib/auth';
import { invalidate, setCached, useResource } from '../lib/data';
import { dateTime, fmt, fmt1 } from '../lib/format';

export function ClearScan() {
  const auth = useAuth();
  const toast = useToast();
  const [confirm, setConfirm] = useState(false);
  if (!auth.can('admin')) return null;
  return (
    <Card title="Current estate" description="Remove the scan the screens are showing. History, exports already made and the audit log are kept.">
      <Button variant="danger" icon={Trash2} onClick={() => setConfirm(true)}>Clear the current scan</Button>
      {confirm && (
        <Dialog title="Clear the current scan?" onClose={() => setConfirm(false)}
          footer={<><Button onClick={() => setConfirm(false)}>Cancel</Button>
            <Button variant="danger" onClick={async () => {
              try { await post('/scan/clear'); invalidate(''); toast('The current scan was cleared.'); } catch (e) { toast(e.message); }
              setConfirm(false);
            }}>Clear it</Button></>}>
          <p className="small">Every screen will show "nothing scanned" until the next scan. Previous scans stay in the history, and the
            audit log records who cleared it.</p>
        </Dialog>
      )}
    </Card>
  );
}

export function AgentTools() {
  const tools = useResource('/agent/tools');
  return (
    <Load resource={tools} skeleton={<Skeleton height="12rem" />}>
      {(t) => (
        <Card title={`What the assistant can do (${fmt(t.tools.length)} tools)`} description="Each answer is built from these calls, and each call is logged. Tools that change the estate are offered only outside read-only mode." pad={false}>
          <div className="table-wrap" style={{ maxHeight: '26rem', overflowY: 'auto' }} tabIndex={0} role="region" aria-label="Assistant tools">
            <table className="table">
              <thead><tr><th>Tool</th><th>Does</th><th>Changes things</th><th>Offered now</th></tr></thead>
              <tbody>{t.tools.map((x) => (
                <tr key={x.name}><td className="strong small nowrap">{x.name.replace(/_/g, ' ')}</td><td className="xsmall soft">{x.description}</td>
                  <td>{x.mutating ? <Badge tone="warn">yes</Badge> : <span className="small muted">no</span>}</td>
                  <td>{x.available ? <Badge tone="ok" icon={CircleCheck}>yes</Badge> : <Badge icon={CircleHelp}>no</Badge>}</td></tr>
              ))}</tbody>
            </table>
          </div>
        </Card>
      )}
    </Load>
  );
}

export function ModelPool() {
  const auth = useAuth();
  const toast = useToast();
  const pool = useResource('/agents/pool');
  const probe = useResource('/agents/probe');
  const ntro = useResource('/ntro-mode');
  const [form, setForm] = useState({ provider: '', api_key: '', model: '', base_url: '' });
  const [busy, setBusy] = useState('');
  const act = async (key, fn, done) => {
    setBusy(key);
    try { await fn(); invalidate('/agents/'); toast(done); } catch (e) { toast(e.message); } finally { setBusy(''); }
  };
  return (
    <Load resource={pool} skeleton={<Skeleton height="16rem" />}>
      {(p) => (
        <div className="stack-lg">
          <Card title="Measured model reliability" description={p.model_health.note}>
            <div className="table-wrap"><table className="table">
              <thead><tr><th>Model</th><th className="r">Answered</th><th className="r">Reliability</th><th className="r">Median time</th><th>State</th></tr></thead>
              <tbody>{p.model_health.models.map((m) => (
                <tr key={m.model}><td className="strong">{m.model}</td><td className="r num">{fmt(m.successes)} of {fmt(m.attempts)}</td>
                  <td className="r num">{fmt1(m.reliability * 100)}%</td><td className="r num">{m.median_latency_s ? `${fmt1(m.median_latency_s)} s` : '—'}</td>
                  <td>{m.available ? <Badge tone="ok">available</Badge> : <Badge tone="warn">{m.unavailable_reason || 'unavailable'}</Badge>}</td></tr>
              ))}</tbody>
            </table></div>
          </Card>
          <Card title="Cloud models (optional)" description="Keys for hosted models, held in memory only. Not used in NTRO mode.">
            <div className="stack">
              {ntro.data?.offline?.enforced && <Callout tone="info" title="The offline guard is on, so no cloud model can be reached.">This section stays for installations that allow it.</Callout>}
              <div className="grid-4">
                <Figure label="Keys" value={fmt(p.capacity.keys)} detail={`${fmt(p.capacity.usable_now)} usable now`} />
                <Figure label="Requests a minute" value={fmt(p.capacity.requests_per_minute)} detail="across every key" />
                <Figure label="Requests a day" value={fmt(p.capacity.requests_per_day)} detail="across every key" />
                <Figure label="Last probe" value={fmt(probe.data?.probed || 0)} detail={`${fmt(probe.data?.working?.length || 0)} models answered with tools`} />
              </div>
              {p.keys.length > 0 && (
                <ul className="list-plain small">{p.keys.map((k) => (
                  <li key={k.id} className="row"><KeyRound size={14} aria-hidden /><span className="grow">{k.provider} · {k.hint || k.masked || k.id}{k.model ? ` · ${k.model}` : ''}</span>
                    {auth.can('admin') && <Button size="sm" variant="danger" icon={Trash2} busy={busy === k.id} onClick={() => act(k.id, () => del(`/agents/keys/${k.id}`), 'Key removed.')}>Remove</Button>}</li>
                ))}</ul>
              )}
              {auth.can('admin') && (
                <form className="grid-2" onSubmit={(e) => { e.preventDefault(); act('add', () => post('/agents/keys', form), 'Key added.').then(() => setForm({ provider: '', api_key: '', model: '', base_url: '' })); }}>
                  <div className="field"><label htmlFor="pp">Provider</label>
                    <select id="pp" className="select" value={form.provider} onChange={(e) => setForm({ ...form, provider: e.target.value })}>
                      <option value="">Choose</option>{p.providers.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}
                    </select>
                    {form.provider && <span className="hint">{p.providers.find((x) => x.id === form.provider)?.note}</span>}</div>
                  <div className="field"><label htmlFor="pk">API key</label><input id="pk" className="input" type="password" autoComplete="off" value={form.api_key} onChange={(e) => setForm({ ...form, api_key: e.target.value })} /></div>
                  <div className="field"><label htmlFor="pm">Model (optional)</label><input id="pm" className="input" value={form.model} onChange={(e) => setForm({ ...form, model: e.target.value })} /></div>
                  <div className="field"><label htmlFor="pb">Address (optional)</label><input id="pb" className="input" value={form.base_url} onChange={(e) => setForm({ ...form, base_url: e.target.value })} /></div>
                  <div className="row"><Button type="submit" icon={Plus} busy={busy === 'add'} disabled={!form.provider || !form.api_key}>Add key</Button>
                    <Button icon={Play} busy={busy === 'probe'} onClick={() => act('probe', () => post('/agents/probe', {}), 'Probe finished.')}>Probe models</Button></div>
                </form>
              )}
              {probe.data?.note && <p className="xsmall muted">{probe.data.note}</p>}
            </div>
          </Card>
        </div>
      )}
    </Load>
  );
}

export function PolicyPresets() {
  const auth = useAuth();
  const toast = useToast();
  const presets = useResource('/engine/policy/presets');
  const current = useResource('/engine/policy');
  const [preview, setPreview] = useState(null);
  const [busy, setBusy] = useState('');
  const run = async (key, fn) => { setBusy(key); try { await fn(); } catch (e) { toast(e.message); } finally { setBusy(''); } };
  return (
    <Load resource={presets} skeleton={<Skeleton height="10rem" />}>
      {(p) => (
        <Card title="Change the scoring policy" description="Preview first: it shows which assets would move in the ranking and whether the pipeline's checks still pass.">
          <div className="stack">
            {p.presets.map((x) => (
              <div key={x.id} className="row" style={{ alignItems: 'flex-start' }}>
                <div className="grow"><strong>{x.name}</strong>{current.data?.policy?.name === x.name && <Badge tone="primary">in force</Badge>}
                  <div className="small soft">{x.description}</div></div>
                <Button size="sm" busy={busy === x.id} onClick={() => run(x.id, async () => setPreview({ preset: x, result: await post('/engine/policy/preview', { policy: x.policy }) }))}>Preview</Button>
              </div>
            ))}
            {preview && (
              <div className="card card-pad stack" style={{ gap: 'var(--s-2)' }}>
                <strong>If "{preview.preset.name}" were in force</strong>
                <Kv rows={[['Assets that change rank', fmt(preview.result.moved_count)], ['Newly ranked', fmt(preview.result.entered_ranking.length)],
                  ['No longer ranked', fmt(preview.result.left_ranking.length)], ['Flagged for review', `${fmt(preview.result.flagged.current)} → ${fmt(preview.result.flagged.proposed)}`],
                  ['Pipeline checks', preview.result.checks.proposed?.checks_passed ? 'all pass' : 'a check fails']]} />
                {preview.result.rank_moves.slice(0, 8).map((m) => <p key={m.id || m.name} className="xsmall">{m.name}: {m.from} → {m.to}</p>)}
                {auth.can('admin') ? (
                  <div className="row"><Button variant="primary" icon={Save} busy={busy === 'apply'} onClick={() => run('apply', async () => {
                    setCached('/engine/policy', await put('/engine/policy', { policy: preview.preset.policy }));
                    invalidate(''); setPreview(null); toast(`Scoring policy "${preview.preset.name}" is in force.`);
                  })}>Put this policy in force</Button><Button variant="quiet" onClick={() => setPreview(null)}>Cancel</Button></div>
                ) : <p className="xsmall muted">Only an admin can change the policy.</p>}
              </div>
            )}
          </div>
        </Card>
      )}
    </Load>
  );
}

export function ApiAccess() {
  const auth = useAuth();
  const toast = useToast();
  const keys = useResource(auth.can('admin') ? '/access-keys' : null);
  const manifest = useResource('/v1/manifest');
  const [name, setName] = useState('Integration key');
  const [write, setWrite] = useState(false);
  const [issued, setIssued] = useState(null);
  const create = async () => {
    try { setIssued(await post('/access-keys', { name, allow_write: write })); invalidate('/access-keys'); } catch (e) { toast(e.message); }
  };
  return (
    <div className="stack-lg">
      <Load resource={manifest} skeleton={<Skeleton height="10rem" />}>
        {(m) => (
          <Card title="Let another system call V.E.R.A." description={m.governance || m.description}>
            <Kv rows={[['How to authenticate', m.auth?.header], ['Also accepted', m.auth?.alternative_header], ['List tools', <code key="t">{m.endpoints?.tools}</code>],
              ['Call a tool', <code key="i">{m.endpoints?.invoke}</code>], ['API reference', <code key="d">{m.endpoints?.docs}</code>],
              ['Tools', `${fmt(m.tool_count)}, of which ${fmt(m.write_tools?.length || 0)} change things (${(m.write_tools || []).join(', ')})`]]} />
          </Card>
        )}
      </Load>
      {!auth.can('admin') ? <Callout tone="info" title="Only an admin can issue keys." /> : (
        <Load resource={keys} skeleton={<Skeleton height="10rem" />}>
          {(k) => (
            <Card title="Keys" description={k.note}>
              <div className="stack">
                <div className="row" style={{ alignItems: 'flex-end' }}>
                  <div className="field grow"><label htmlFor="kn">Name</label><input id="kn" className="input" value={name} onChange={(e) => setName(e.target.value)} /></div>
                  <label className="check small"><input type="checkbox" checked={write} onChange={(e) => setWrite(e.target.checked)} /> May change things</label>
                  <Button icon={Plus} onClick={create} disabled={!name.trim()}>Issue a key</Button>
                </div>
                {k.keys.length ? (
                  <div className="table-wrap"><table className="table">
                    <thead><tr><th>Name</th><th>Key</th><th>Scopes</th><th className="r">Calls</th><th>Last used</th><th /></tr></thead>
                    <tbody>{k.keys.map((x) => (
                      <tr key={x.id}><td className="strong">{x.name}</td><td className="mono small">{x.hint}</td><td>{x.scopes.join(', ')}</td><td className="r num">{fmt(x.call_count)}</td>
                        <td className="small">{x.last_used_at ? dateTime(x.last_used_at) : 'never'}</td>
                        <td className="r">{x.revoked ? <Badge>revoked</Badge> : <Button size="sm" variant="danger" onClick={async () => {
                          try { await del(`/access-keys/${x.id}`); invalidate('/access-keys'); toast('Key revoked.'); } catch (e) { toast(e.message); }
                        }}>Revoke</Button>}</td></tr>
                    ))}</tbody>
                  </table></div>
                ) : <p className="small muted">No keys issued.</p>}
              </div>
            </Card>
          )}
        </Load>
      )}
      {issued && (
        <Dialog title="Copy this key now" onClose={() => setIssued(null)} footer={<Button variant="primary" onClick={() => setIssued(null)}>Done</Button>}>
          <div className="stack">
            <p className="small">{issued.warning}</p>
            <pre className="code-block">{issued.key}</pre>
            <Button icon={Copy} onClick={() => navigator.clipboard.writeText(issued.key).then(() => toast('Copied.'), () => toast('Copy failed.'))}>Copy</Button>
          </div>
        </Dialog>
      )}
    </div>
  );
}
