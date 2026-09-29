/* Projects: one piece of assessment work each, with its targets, the scans run for it and the assistant
 * conversations held about it (GET/POST /api/projects, engine/projects.py).
 *
 *   #/projects          every project, and starters for each kind of user
 *   #/projects/<id>     one project: targets, scan it, its scan history, its conversations
 */
import { useState } from 'react';
import { ArrowLeft, Bot, FolderKanban, Plus, Radar, Star, Trash2 } from 'lucide-react';
import { Badge, Button, Callout, Card, Empty, Load, PageHead, Skeleton, useToast } from '../components/ui';
import { del, patch, post } from '../lib/api';
import { invalidate, useResource } from '../lib/data';
import { ago, dateTime, fmt } from '../lib/format';
import { setCurrentProject, useCurrentProject } from '../lib/project';
import { Link, navigate } from '../lib/router';
import { useScan } from '../lib/scan';
import { KINDS, PLACEHOLDER } from '../lib/targets';

// One starter per kind of user (engine/auth.py ROLE_INFO): each is a real project, created on click.
const STARTERS = [
  { name: 'Milestone-1 inventory (demo bank)', purpose: 'CII risk owner: inventory and quantum risk for the DST foundations milestone',
    sector: 'Banking', estate: 'demo', who: 'Risk owner (CISO)' },
  { name: 'Vendor appliance review', purpose: 'NTRO analyst: characterise the cryptography in a binary delivered without source',
    sector: 'CII', targets: [{ kind: 'path', value: '' }], who: 'NTRO analyst' },
  { name: 'CERT-In CBOM check', purpose: 'Auditor: check a CBOM element by element against CERT-In Table 9',
    sector: 'Banking', estate: 'demo', who: 'Auditor' },
];

function Targets({ targets, onChange }) {
  const set = (i, key, value) => onChange(targets.map((t, j) => (j === i ? { ...t, [key]: value } : t)));
  return (
    <div className="stack">
      {targets.map((t, i) => (
        <div key={i} className="row" style={{ alignItems: 'flex-end' }}>
          <div className="field" style={{ width: '14rem' }}>
            <label htmlFor={`pk${i}`}>Kind</label>
            <select id={`pk${i}`} className="select" value={t.kind} onChange={(e) => set(i, 'kind', e.target.value)}>
              {t.kind === 'estate' && <option value="estate">Estate register</option>}
              {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
            </select>
          </div>
          <div className="field grow">
            <label htmlFor={`pv${i}`}>Location</label>
            <input id={`pv${i}`} className="input mono" value={t.value} placeholder={t.kind === 'estate' ? 'demo' : PLACEHOLDER[t.kind]}
              onChange={(e) => set(i, 'value', e.target.value)} />
          </div>
          <Button variant="quiet" icon={Trash2} aria-label="Remove this target" onClick={() => onChange(targets.filter((_, j) => j !== i))} />
        </div>
      ))}
      <div><Button size="sm" icon={Plus} onClick={() => onChange([...targets, { kind: 'path', value: '' }])}>Add a target</Button></div>
    </div>
  );
}

function NewProject({ onCreated }) {
  const toast = useToast();
  const [name, setName] = useState('');
  const [purpose, setPurpose] = useState('');
  const [busy, setBusy] = useState(false);
  const create = async (body) => {
    setBusy(true);
    try {
      const p = await post('/projects', body);
      invalidate('/projects');
      setCurrentProject(p);
      onCreated(p);
    } catch (e) {
      toast(e.message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Start a project" description="A project keeps one job's targets, scans and assistant conversations together.">
      <div className="stack-lg">
        <div className="grid-3">
          {STARTERS.map((s) => (
            <button key={s.name} type="button" className="card card-pad starter" disabled={busy}
              onClick={() => create({ name: s.name, purpose: s.purpose, sector: s.sector, estate: s.estate || null,
                targets: (s.targets || []).filter((t) => t.value) })}>
              <Badge tone="info">{s.who}</Badge>
              <div className="strong" style={{ marginTop: 'var(--s-2)' }}>{s.name}</div>
              <div className="small soft">{s.purpose}</div>
            </button>
          ))}
        </div>
        <div className="row" style={{ alignItems: 'flex-end' }}>
          <div className="field grow"><label htmlFor="pn">Or name your own</label>
            <input id="pn" className="input" value={name} placeholder="e.g. Core banking Q4 inventory" onChange={(e) => setName(e.target.value)} /></div>
          <div className="field grow"><label htmlFor="pp">Purpose (optional)</label>
            <input id="pp" className="input" value={purpose} onChange={(e) => setPurpose(e.target.value)} /></div>
          <Button variant="primary" icon={Plus} busy={busy} disabled={!name.trim()}
            onClick={() => create({ name, purpose, sector: 'Banking', targets: [] })}>Create</Button>
        </div>
      </div>
    </Card>
  );
}

function List() {
  const res = useResource('/projects');
  const current = useCurrentProject();
  return (
    <div className="page">
      <PageHead title="Projects" description="Each assessment job, with its targets, scans and assistant conversations. Pick one to work in." />
      <div className="stack-lg">
        <Load resource={res} skeleton={<Skeleton lines={4} />}>
          {(projects) => (projects.length ? (
            <div className="grid-3">
              {projects.map((p) => (
                <Link key={p.id} to={`/projects/${p.id}`} className="card card-pad project-card">
                  <div className="row"><FolderKanban size={18} aria-hidden /><span className="strong grow truncate">{p.name}</span>
                    {current?.id === p.id && <Badge tone="primary" icon={Star}>Current</Badge>}</div>
                  {p.purpose && <p className="small soft">{p.purpose}</p>}
                  <div className="row-wrap xsmall muted">
                    <span>{fmt(p.targets.length)} targets</span><span>{fmt(p.scans)} scans</span>
                    <span>{fmt(p.conversations)} conversations</span><span>{p.sector}</span><span>created {ago(p.created_at)}</span>
                  </div>
                </Link>
              ))}
            </div>
          ) : <Empty title="No projects yet.">Start one below: each starter is set up for one kind of user.</Empty>)}
        </Load>
        <NewProject onCreated={(p) => navigate(`/projects/${p.id}`)} />
      </div>
    </div>
  );
}

function Detail({ id }) {
  const toast = useToast();
  const scan = useScan();
  const res = useResource(`/projects/${id}`);
  const current = useCurrentProject();
  const [draft, setDraft] = useState(null);
  const saveTargets = async (p) => {
    try {
      await patch(`/projects/${id}`, { targets: draft.filter((t) => t.value.trim()) });
      setDraft(null);
      invalidate(`/projects/${id}`);
      invalidate('/projects');
      toast('Targets saved.');
    } catch (e) {
      toast(e.message);
    }
    return p;
  };
  const runScan = async (p) => {
    const estate = p.targets.find((t) => t.kind === 'estate')?.value || null;
    const targets = p.targets.filter((t) => t.kind !== 'estate');
    try {
      await scan.start({ estate, targets, org_persona: p.sector, project_id: p.id });
      setCurrentProject(p);
      navigate('/scan');
    } catch (e) {
      toast(e.message);
    }
  };
  const remove = async (p) => {
    if (!window.confirm(`Delete the project "${p.name}"? Its scans stay in scan history.`)) return;
    await del(`/projects/${id}`);
    if (current?.id === id) setCurrentProject(null);
    invalidate('/projects');
    navigate('/projects');
  };
  return (
    <div className="page">
      <Link to="/projects" className="back-link small"><ArrowLeft size={14} aria-hidden /> Projects</Link>
      <Load resource={res} skeleton={<Skeleton lines={8} />}>
        {(p) => {
          const targets = draft || p.targets;
          const scannable = p.targets.some((t) => t.value);
          return (
            <div className="stack-lg">
              <PageHead title={p.name} description={[p.purpose, p.sector, `created ${dateTime(p.created_at)} by ${p.created_by}`].filter(Boolean).join(' · ')}
                actions={(
                  <>
                    {current?.id !== p.id && <Button icon={Star} onClick={() => setCurrentProject(p)}>Work in this project</Button>}
                    <Button variant="primary" icon={Radar} disabled={!scannable || scan.running} onClick={() => runScan(p)}>
                      {scan.running ? 'A scan is running' : 'Scan this project'}</Button>
                  </>
                )} />
              {current?.id === p.id && <Callout tone="info" title="You are working in this project.">The assistant files its conversations here.</Callout>}
              <Card title="Targets" description="What this project scans. An estate register brings its own systems, owners and exposure."
                actions={draft && <Button size="sm" variant="primary" onClick={() => saveTargets(p)}>Save targets</Button>}>
                {targets.length ? null : <p className="small muted">No targets yet: add a folder, repository, image, binary folder or endpoint.</p>}
                <Targets targets={targets} onChange={setDraft} />
              </Card>
              <Card title="Scans" description="Every scan run for this project, newest first." pad={false}>
                {p.scans.length ? (
                  <div className="table-wrap"><table className="table">
                    <thead><tr><th>When</th><th>Scan</th><th className="r">Assets</th><th className="r">Quantum-vulnerable</th><th className="r">Late for DST</th></tr></thead>
                    <tbody>{p.scans.map((s) => (
                      <tr key={s.scan_id}><td className="nowrap">{dateTime(s.timestamp)}</td><td>{s.label}</td>
                        <td className="r num">{fmt(s.assets)}</td><td className="r num">{fmt(s.quantum_vulnerable)}</td>
                        <td className="r num">{fmt(s.late_for_dst)}</td></tr>
                    ))}</tbody>
                  </table></div>
                ) : <div className="card-pad small muted">Not scanned yet. {scannable ? 'Press "Scan this project".' : 'Add a target first.'}</div>}
              </Card>
              <Card title="Assistant conversations" description="Saved automatically while you work in this project; open the assistant (press /) to continue one.">
                {p.conversations.length ? (
                  <ul className="list-plain stack">{p.conversations.map((c) => (
                    <li key={c.id} className="row"><Bot size={16} aria-hidden /><span className="grow truncate">{c.title}</span>
                      <span className="xsmall muted">{fmt(c.message_count)} messages · {ago(c.updated_at)}</span></li>
                  ))}</ul>
                ) : <p className="small muted">None yet. Work in this project and ask the assistant anything: the conversation is kept here.</p>}
              </Card>
              <div><Button variant="quiet" icon={Trash2} onClick={() => remove(p)}>Delete project</Button></div>
            </div>
          );
        }}
      </Load>
    </div>
  );
}

export default function Projects({ route }) {
  return route.segments[1] ? <Detail id={route.segments[1]} /> : <List />;
}
