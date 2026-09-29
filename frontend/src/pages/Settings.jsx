/* Settings: how this installation runs, who can use it, and how it looks.
 *
 *   Runtime                     NTRO posture: offline guard, local model, assistant authority
 *   Users and roles             local accounts (admin only), and your own password
 *   Assistant model             the local model the assistant runs on
 *   Profile and policy          recommendation profile (NIST or CNSA 2.0), the scoring policy in force
 *   Accessibility and language  text size, theme, language, keyboard
 *
 * Every change here is written to the audit chain with the name of who made it.
 */

import { useState } from 'react';
import { CircleCheck, CircleHelp, KeyRound, Plug, Save, UserPlus } from 'lucide-react';
import {
  Badge, Button, Callout, Card, Kv, Load, PageHead, Seg, Skeleton, Tabs, useToast,
} from '../components/ui';
import { get, patch, post, put } from '../lib/api';
import { useAuth } from '../lib/auth';
import { invalidate, setCached, useResource } from '../lib/data';
import { dateTime } from '../lib/format';
import { ClassInputs } from './EvidenceExtras';
import { AgentTools, ApiAccess, ClearScan, ModelPool, PolicyPresets } from './SettingsExtras';
import { usePrefs, useT } from '../lib/prefs';

const MODES = {
  read_only: 'Read-only: explains the estate; cannot change it. NTRO mode.',
  approval: 'Approval: may propose a change; an analyst must approve it.',
  autonomous: 'Autonomous: may apply changes within the asset cap. Not for assessments.',
};

function Runtime() {
  const auth = useAuth();
  const toast = useToast();
  const ntro = useResource('/ntro-mode');
  const agent = useResource('/agent/status');
  const setMode = async (mode) => {
    try {
      setCached('/agent/status', await post('/agent/settings', { mode }));
      invalidate('/ntro-mode');
      toast('Assistant authority changed.');
    } catch (e) { toast(e.message); }
  };
  return (
    <div className="stack-lg">
      <Load resource={ntro} skeleton={<Skeleton height="10rem" />}>
        {(n) => (
          <Card title="Operating posture" description={n.ntro_mode ? 'NTRO mode is in force.' : 'NTRO mode is not fully in force.'}
            actions={n.ntro_mode ? <Badge tone="ok" icon={CircleCheck}>NTRO mode</Badge> : <Badge tone="warn" icon={CircleHelp}>Partial</Badge>}>
            <ul className="list-plain">
              {n.facts.map((f) => (
                <li key={f.key} className="row" style={{ alignItems: 'flex-start' }}>
                  {f.ok ? <CircleCheck size={18} color="var(--ok)" aria-hidden /> : <CircleHelp size={18} color="var(--warn-text)" aria-hidden />}
                  <div className="grow"><div className="strong">{f.label}</div><div className="small soft">{f.detail}</div></div>
                </li>
              ))}
            </ul>
            {n.offline?.recently_blocked?.length > 0 && (
              <Callout tone="info" title="Recently blocked outbound connections">{n.offline.recently_blocked.map((b) => (typeof b === 'string' ? b : JSON.stringify(b))).join(', ')}</Callout>
            )}
            <p className="xsmall muted" style={{ marginTop: 'var(--s-3)' }}>Set at start-up: VERA_OFFLINE=1, VERA_AGENT_MODE, VERA_LLM_PROVIDER and VERA_LLM_MODEL. <code>python main.py</code> applies the NTRO defaults when they are unset.</p>
          </Card>
        )}
      </Load>
      <Load resource={agent} skeleton={<Skeleton height="10rem" />}>
        {(a) => (
          <Card title="Assistant authority" description={a.mode_note}>
            <div className="stack">
              {Object.entries(MODES).map(([key, text]) => (
                <label key={key} className="check" style={{ alignItems: 'flex-start' }}>
                  <input type="radio" name="mode" checked={a.settings.mode === key} disabled={!auth.can('admin')} onChange={() => setMode(key)} />
                  <span>{text}</span>
                </label>
              ))}
              {!auth.can('admin') && <p className="small muted">Only an admin can change this.</p>}
              <Kv rows={[['Tool calls per minute', a.settings.max_tool_calls_per_minute], ['Steps per answer', a.settings.max_iterations_per_turn],
                ['Assets per change', a.settings.max_assets_per_action], ['Answers given', a.totals.calls], ['Refused', a.totals.refusals],
                ['Deterministic router', a.router ? 'On: known questions skip the model' : 'Off']]} />
            </div>
          </Card>
        )}
      </Load>
      <ClearScan />
    </div>
  );
}

/* Who uses V.E.R.A. and what each role may do: one column per role, one row per capability (GET /api/auth/roles,
   the same matrix the engine enforces in api/auth.py). */
function RoleMatrix() {
  const auth = useAuth();
  const res = useResource('/auth/roles');
  return (
    <Card title="Who uses V.E.R.A., and what each role may do"
      description="The primary user is the NTRO analyst. Every other role is a real person in an assessment, with only the rights that job needs. The engine enforces this matrix on every request." pad={false}>
      <Load resource={res} skeleton={<Skeleton height="14rem" />}>
        {(m) => (
          <div className="table-wrap">
            <table className="table role-matrix">
              <thead>
                <tr><th>What they can do</th>{m.roles.map((r) => (
                  <th key={r.key} className="c" aria-current={auth.user?.role === r.key ? 'true' : undefined}>
                    <div>{r.label}</div><div className="role-who">{r.who}</div>
                  </th>
                ))}</tr>
              </thead>
              <tbody>{m.capabilities.map((c) => (
                <tr key={c.key}><td className="small">{c.label}</td>{m.roles.map((r) => (
                  <td key={r.key} className="c">{c.roles.includes(r.key)
                    ? <CircleCheck size={16} className="role-yes" aria-label="yes" />
                    : <span className="role-no" aria-label="no">·</span>}</td>
                ))}</tr>
              ))}</tbody>
            </table>
          </div>
        )}
      </Load>
    </Card>
  );
}

function Users() {
  const auth = useAuth();
  const toast = useToast();
  const users = useResource(auth.can('admin') ? '/auth/users' : null);
  const roles = useResource('/auth/roles');
  const roleOptions = (roles.data?.roles || []).map((r) => <option key={r.key} value={r.key}>{r.label}</option>);
  const [form, setForm] = useState({ username: '', display_name: '', password: '', role: 'viewer' });
  const [pw, setPw] = useState({ current: '', new: '' });
  const add = async (e) => {
    e.preventDefault();
    try {
      await post('/auth/users', form);
      setForm({ username: '', display_name: '', password: '', role: 'viewer' });
      invalidate('/auth/users');
      toast('User added.');
    } catch (err) { toast(err.message); }
  };
  const change = async (username, body) => {
    try { await patch(`/auth/users/${encodeURIComponent(username)}`, body); invalidate('/auth/users'); toast('Saved.'); } catch (err) { toast(err.message); }
  };
  return (
    <div className="stack-lg">
      <RoleMatrix />
      {!auth.auth && <Callout tone="warn" title="Sign-in is off on this engine.">VERA_AUTH=0 is set, so everyone who can reach it acts as an admin. Remove it before an assessment.</Callout>}
      {auth.can('admin') && auth.auth && (
        <Load resource={users} skeleton={<Skeleton height="12rem" />}>
          {(u) => (
            <Card title="People" pad={false}>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>User</th><th>Role</th><th>Last sign-in</th><th>Status</th><th /></tr></thead>
                  <tbody>
                    {u.users.map((x) => (
                      <tr key={x.username}>
                        <td><div className="strong">{x.display_name}</div><div className="xsmall muted">{x.username}</div></td>
                        <td><select className="select" style={{ height: '2rem', width: '9rem' }} value={x.role} aria-label={`Role of ${x.username}`}
                          onChange={(e) => change(x.username, { role: e.target.value })}>
                          {roleOptions}
                        </select></td>
                        <td className="small">{x.last_login ? dateTime(x.last_login) : 'Never'}</td>
                        <td>{x.disabled ? <Badge>Disabled</Badge> : <Badge tone="ok">Active</Badge>}</td>
                        <td className="r"><Button size="sm" onClick={() => change(x.username, { disabled: !x.disabled })}>{x.disabled ? 'Enable' : 'Disable'}</Button></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </Load>
      )}
      {auth.can('admin') && auth.auth && (
        <Card title="Add a person">
          <form className="grid-2" onSubmit={add}>
            <div className="field"><label htmlFor="nu">Username</label><input id="nu" className="input" value={form.username} autoComplete="off" onChange={(e) => setForm({ ...form, username: e.target.value })} /></div>
            <div className="field"><label htmlFor="nn">Full name</label><input id="nn" className="input" value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} /></div>
            <div className="field"><label htmlFor="np">First password</label><input id="np" className="input" type="password" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
              <span className="hint">At least 12 characters. They can change it after signing in.</span></div>
            <div className="field"><label htmlFor="nr">Role</label>
              <select id="nr" className="select" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
                {roleOptions}
              </select></div>
            <div><Button type="submit" variant="primary" icon={UserPlus} disabled={!form.username || form.password.length < 12}>Add</Button></div>
          </form>
        </Card>
      )}
      {auth.auth && (
        <Card title="Your password">
          <form className="grid-2" onSubmit={async (e) => {
            e.preventDefault();
            try { await post('/auth/password', pw); setPw({ current: '', new: '' }); toast('Password changed. Other sessions were signed out.'); } catch (err) { toast(err.message); }
          }}>
            <div className="field"><label htmlFor="pc">Current password</label><input id="pc" className="input" type="password" autoComplete="current-password" value={pw.current} onChange={(e) => setPw({ ...pw, current: e.target.value })} /></div>
            <div className="field"><label htmlFor="pn">New password</label><input id="pn" className="input" type="password" autoComplete="new-password" value={pw.new} onChange={(e) => setPw({ ...pw, new: e.target.value })} /></div>
            <div><Button type="submit" icon={KeyRound} disabled={!pw.current || pw.new.length < 12}>Change password</Button></div>
          </form>
        </Card>
      )}
    </div>
  );
}

function Model() {
  const auth = useAuth();
  const toast = useToast();
  const config = useResource('/llm/config');
  const [draft, setDraft] = useState(null);
  const [models, setModels] = useState(null);
  const [test, setTest] = useState(null);
  const [busy, setBusy] = useState('');
  const admin = auth.can('admin');
  const run = async (what, fn) => {
    setBusy(what);
    try { await fn(); } catch (e) { toast(e.message); } finally { setBusy(''); }
  };
  return (
    <>
    <Load resource={config} skeleton={<Skeleton height="16rem" />}>
      {(c) => {
        const d = draft || { provider: c.provider, base_url: c.base_url, model: c.model };
        const local = ['ollama', 'lmstudio', 'llamacpp', 'openai_compatible_local'].includes(d.provider) || /localhost|127\.0\.0\.1/.test(d.base_url || '');
        return (
          <div className="stack-lg">
            <Callout tone={local || !c.is_configured ? 'info' : 'warn'} title={local ? 'The assistant runs on this machine.' : c.is_configured ? 'This model is not local.' : 'No model is configured.'}>
              {local ? 'Questions and answers never leave the machine.' : c.is_configured
                ? 'Questions would be sent to a remote service. With the offline guard on, the connection is refused.'
                : 'The assistant still answers common questions from the engine through its router. For NTRO use: Ollama with qwen3:1.7b.'}
            </Callout>
            <Card title="Model">
              <div className="grid-2">
                <div className="field"><label htmlFor="prov">Provider</label>
                  <select id="prov" className="select" disabled={!admin} value={d.provider || ''} onChange={(e) => {
                    const p = c.providers.find((x) => x.key === e.target.value);
                    setDraft({ ...d, provider: e.target.value, base_url: p?.default_base_url || d.base_url });
                  }}>
                    <option value="">None</option>
                    {c.providers.map((p) => <option key={p.key} value={p.key}>{p.label}</option>)}
                  </select>
                  {c.providers.find((p) => p.key === d.provider)?.note && <span className="hint">{c.providers.find((p) => p.key === d.provider).note}</span>}
                </div>
                <div className="field"><label htmlFor="url">Address</label>
                  <input id="url" className="input mono" disabled={!admin} value={d.base_url || ''} onChange={(e) => setDraft({ ...d, base_url: e.target.value })} /></div>
                <div className="field"><label htmlFor="mdl">Model</label>
                  {models ? (
                    <select id="mdl" className="select" disabled={!admin} value={d.model || ''} onChange={(e) => setDraft({ ...d, model: e.target.value })}>
                      <option value="">Choose</option>{models.map((m) => <option key={m} value={m}>{m}</option>)}
                    </select>
                  ) : <input id="mdl" className="input mono" disabled={!admin} value={d.model || ''} onChange={(e) => setDraft({ ...d, model: e.target.value })} />}
                </div>
                <div className="field"><span className="label">Status</span>
                  <span>{c.verified ? <Badge tone="ok" icon={CircleCheck}>Answered a test</Badge> : <Badge>Not tested</Badge>}
                    {c.last_error && <span className="small" style={{ color: 'var(--bad-text)' }}> {c.last_error}</span>}</span></div>
              </div>
              {admin ? (
                <div className="row-wrap" style={{ marginTop: 'var(--s-4)' }}>
                  <Button icon={Plug} busy={busy === 'models'} onClick={() => run('models', async () => {
                    const r = await get('/llm/models');
                    setModels((r.models || r).map((m) => (typeof m === 'string' ? m : m.id || m.name)));
                  })}>List installed models</Button>
                  <Button variant="primary" icon={Save} busy={busy === 'save'} disabled={!draft} onClick={() => run('save', async () => {
                    setCached('/llm/config', await post('/llm/config', draft));
                    setDraft(null);
                    invalidate('/agent/status'); invalidate('/ntro-mode');
                    toast('Model saved.');
                  })}>Save</Button>
                  <Button busy={busy === 'test'} onClick={() => run('test', async () => { setTest(await post('/llm/test')); invalidate('/llm/config'); })}>Test</Button>
                </div>
              ) : <p className="small muted" style={{ marginTop: 'var(--s-3)' }}>Only an admin can change the model.</p>}
              {test && <Callout tone="ok" title={`Answered in ${test.latency_ms ?? test.elapsed_ms ?? '?'} ms`}>{test.reply || test.message}</Callout>}
            </Card>
          </div>
        );
      }}
    </Load>
    <AgentTools />
    <ModelPool />
    </>
  );
}

function Policy() {
  const auth = useAuth();
  const toast = useToast();
  const profile = useResource('/profile');
  const policy = useResource('/engine/policy');
  const [choice, setChoice] = useState(null);
  const [saving, setSaving] = useState(false);
  /* A global setting: chosen first, then saved on purpose, never on a single click. */
  const save = async () => {
    setSaving(true);
    try {
      setCached('/profile', { ...profile.data, ...(await put('/profile', { profile: choice })) });
      setChoice(null);
      invalidate('/recommendations'); invalidate('/overview'); invalidate('/cost');
      toast('Profile saved. Every recommendation now follows it.');
    } catch (e) { toast(e.message); } finally { setSaving(false); }
  };
  return (
    <div className="stack-lg">
      <Load resource={profile} skeleton={<Skeleton height="8rem" />}>
        {(p) => (
          <Card title="Recommendation profile" description="Which standard the migration targets follow, for everyone using this installation.">
            <div className="stack">
              {[['commercial', 'NIST FIPS 203/204/205', 'Banks, insurers and most CII.'],
                ['cnsa', 'CNSA 2.0', 'Higher parameter sets (ML-KEM-1024, ML-DSA-87) for sovereign and defence systems.']].map(([value, label, note]) => (
                <label key={value} className="check" style={{ alignItems: 'flex-start' }}>
                  <input type="radio" name="profile" value={value} disabled={!auth.can('admin')}
                    checked={(choice ?? p.profile) === value} onChange={() => setChoice(value)} />
                  <span><strong>{label}</strong>{p.profile === value ? ' (in force)' : ''}<br /><span className="small soft">{note}</span></span>
                </label>
              ))}
              {auth.can('admin') ? (
                <div className="row">
                  <Button variant="primary" icon={Save} busy={saving} disabled={!choice || choice === p.profile} onClick={save}>Save profile</Button>
                  {choice && choice !== p.profile && <Button variant="quiet" onClick={() => setChoice(null)}>Cancel</Button>}
                </div>
              ) : <p className="small muted">Only an admin can change the profile. Plan can preview either profile without changing it.</p>}
            </div>
          </Card>
        )}
      </Load>
      <Load resource={policy} skeleton={<Skeleton height="10rem" />}>
        {(p) => (
          <Card title={`Scoring policy: ${p.policy.name}`} description={p.policy.description}>
            <Kv rows={[
              ['Weight on confidentiality (harvest now, decrypt later)', p.policy.w_H], ['Weight on integrity (trust now, forge later)', p.policy.w_T],
              ['Risk bands', p.policy.risk_bands.map((b) => `${b.level} ≥ ${b.threshold}`).join(' · ')],
              ['Flag assets with evidence confidence below', p.policy.flag_threshold], ['CRQC estimate used', p.policy.survival_curve_reading],
              ['Version', p.policy.version],
            ]} />
          </Card>
        )}
      </Load>
      <PolicyPresets />
      <ClassInputs />
    </div>
  );
}

function Access() {
  const { prefs, set } = usePrefs();
  const t = useT();
  return (
    <div className="stack-lg">
      <Card title={t('settings.access')} description="Stored in this browser only.">
        <div className="stack-lg">
          <div className="field"><span className="label">{t('top.textSize')}</span>
            <Seg label={t('top.textSize')} value={prefs.text} onChange={(text) => set({ text })}
              options={[{ value: 'normal', label: '100%' }, { value: 'large', label: '112%' }, { value: 'larger', label: '125%' }]} /></div>
          <div className="field"><span className="label">{t('top.theme')}</span>
            <Seg label={t('top.theme')} value={prefs.theme} onChange={(theme) => set({ theme })}
              options={[{ value: 'light', label: t('top.light') }, { value: 'dark', label: t('top.dark') }]} /></div>
          <div className="field"><span className="label">{t('top.language')}</span>
            <Seg label={t('top.language')} value={prefs.lang} onChange={(lang) => set({ lang })}
              options={[{ value: 'en', label: 'English' }, { value: 'hi', label: 'हिन्दी' }]} />
            <span className="hint">Menus, headings, buttons and status words are translated. Findings and evidence stay in English, exactly as exported.</span></div>
        </div>
      </Card>
      <Card title="Keyboard">
        <Kv rows={[
          [<kbd key="k">Ctrl K</kbd>, 'Search assets, screens and actions'], [<kbd key="s">/</kbd>, 'Ask the assistant'],
          [<kbd key="t">Tab</kbd>, 'Move through every control; the first stop skips to the main content'],
          [<kbd key="a">↑ ↓ Enter</kbd>, 'Move through the inventory and open an asset'], [<kbd key="e">Esc</kbd>, 'Close a panel, menu or dialog'],
        ]} />
      </Card>
      <Card title="Standards this interface follows">
        <p className="small soft">UX4G 3.0 (NeGD) for type, colour and components; GIGW 3.0 and WCAG 2.1 AA for access: keyboard use, visible focus,
          contrast of 4.5:1 for text, text resize to 125%, meaning never carried by colour alone, and reduced motion when the system asks for it.</p>
      </Card>
    </div>
  );
}

export default function Settings({ route }) {
  const t = useT();
  const tabs = ['runtime', 'users', 'model', 'policy', 'api', 'access'];
  const tab = tabs.includes(route.segments[1]) ? route.segments[1] : 'runtime';
  const Body = { runtime: Runtime, users: Users, model: Model, policy: Policy, api: ApiAccess, access: Access }[tab];
  const labels = { runtime: 'settings.runtime', users: 'settings.users', model: 'settings.model', policy: 'settings.policy', api: 'settings.api', access: 'settings.access' };
  return (
    <div className="page">
      <PageHead title={t('nav.settings')} description="How this installation runs, who can use it, and how it looks to you." />
      <Tabs label="Settings" active={tab} items={tabs.map((key) => ({ key, label: t(labels[key]), to: `/settings/${key}` }))} />
      <Body />
    </div>
  );
}
