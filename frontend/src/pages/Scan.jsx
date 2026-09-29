/* Scan: choose what to read, watch every surface being read, keep the history.
 *
 * Three ways in: an estate register (the organisation's own list of systems,
 * which also sets exposure, criticality and data lifetimes), individual targets,
 * or a CycloneDX CBOM that another tool produced. Progress streams per
 * collector; a failure is shown with its reason and never folded into a total.
 */

import { useState } from 'react';
import {
  ArrowRight, CircleCheck, LoaderCircle, OctagonX, Play, Plus, Radar, Trash2, Upload,
} from 'lucide-react';
import {
  Badge, Button, ButtonLink, Callout, Card, Load, Meter, PageHead, Seg, Skeleton, Tabs, useToast,
} from '../components/ui';
import { AddAssets, Datasets, Jobs, LiveEndpoints, Sensors } from './ScanExtras';
import { post } from '../lib/api';
import { useAuth } from '../lib/auth';
import { invalidate, useResource } from '../lib/data';
import { dateTime, fmt, shortPath } from '../lib/format';
import { useT } from '../lib/prefs';
import { useScan } from '../lib/scan';
import { KINDS } from '../lib/targets';

const PLANE = { declared: 'Declared', built: 'Built', held: 'Held', observed: 'Observed' };

function Sector({ value, onChange }) {
  const reg = useResource('/regulatory');
  return (
    <div className="field">
      <label htmlFor="sector">Sector</label>
      <select id="sector" className="select" value={value} onChange={(e) => onChange(e.target.value)}>
        {(reg.data?.personas || ['Banking']).map((p) => <option key={p} value={p}>{p}</option>)}
      </select>
      <span className="hint">Sets the DST track: critical sectors 2027 / 2028 / 2029, other enterprises 2028 / 2030 / 2033.</span>
    </div>
  );
}

function Start({ persona, setPersona }) {
  const scan = useScan();
  const toast = useToast();
  const [mode, setMode] = useState('register');
  const [register, setRegister] = useState('demo');
  const [path, setPath] = useState('');
  const [targets, setTargets] = useState([{ kind: 'path', value: '', system: '' }]);
  const [file, setFile] = useState(null);
  const [imported, setImported] = useState(null);
  const [busy, setBusy] = useState(false);

  const run = async () => {
    try {
      if (mode === 'register') await scan.start({ estate: register === 'demo' ? 'demo' : path.trim(), org_persona: persona });
      else await scan.start({ targets: targets.filter((t) => t.value.trim()).map((t) => ({ ...t, value: t.value.trim(), system: t.system || null })), org_persona: persona });
    } catch (e) {
      toast(e.message);
    }
  };

  const importCbom = async () => {
    if (!file) return;
    setBusy(true);
    try {
      const form = new FormData();
      form.append('file', file);
      const result = await post(`/import/cbom?org_persona=${encodeURIComponent(persona)}`, form);
      setImported(result);
      invalidate('');
    } catch (e) {
      toast(e.message);
    } finally {
      setBusy(false);
    }
  };

  const ready = mode === 'register' ? register === 'demo' || path.trim() : targets.some((t) => t.value.trim());
  return (
    <Card title="What to scan" actions={<Seg label="Scan source" value={mode} onChange={setMode}
      options={[{ value: 'register', label: 'Estate register' }, { value: 'targets', label: 'Targets' }, { value: 'import', label: 'Import a CBOM' }]} />}>
      <div className="stack-lg">
        {mode === 'register' && (
          <div className="stack">
            <p className="small soft">A register lists the organisation's systems: where each runs, whether it faces the internet, how
              critical it is and what data it holds. The scan checks those declarations against what it finds.</p>
            <label className="check"><input type="radio" name="reg" checked={register === 'demo'} onChange={() => setRegister('demo')} />
              Bundled demo estate: a synthetic bank with nine systems</label>
            <label className="check"><input type="radio" name="reg" checked={register === 'file'} onChange={() => setRegister('file')} />
              A register file on this machine</label>
            {register === 'file' && (
              <div className="field">
                <label htmlFor="regpath">Path to estate.yaml</label>
                <input id="regpath" className="input mono" value={path} onChange={(e) => setPath(e.target.value)}
                  placeholder={'D:\\estates\\bank\\estate.yaml'} />
              </div>
            )}
          </div>
        )}
        {mode === 'targets' && (
          <div className="stack">
            <p className="small soft">Each target is read by every collector that understands it. Live endpoints are probed only when
              you name them here, even with the offline guard on.</p>
            {targets.map((t, i) => (
              <div key={i} className="row" style={{ alignItems: 'flex-end' }}>
                <div className="field" style={{ width: '14rem' }}>
                  <label htmlFor={`k${i}`}>Kind</label>
                  <select id={`k${i}`} className="select" value={t.kind} onChange={(e) => setTargets(targets.map((x, j) => (j === i ? { ...x, kind: e.target.value } : x)))}>
                    {KINDS.map((k) => <option key={k.value} value={k.value}>{k.label}</option>)}
                  </select>
                </div>
                <div className="field grow">
                  <label htmlFor={`v${i}`}>Location</label>
                  <input id={`v${i}`} className="input mono" value={t.value} placeholder={t.kind === 'host' ? 'pay.example.in:443' : 'C:\\code\\payments'}
                    onChange={(e) => setTargets(targets.map((x, j) => (j === i ? { ...x, value: e.target.value } : x)))} />
                </div>
                <div className="field" style={{ width: '10rem' }}>
                  <label htmlFor={`s${i}`}>System (optional)</label>
                  <input id={`s${i}`} className="input" value={t.system}
                    onChange={(e) => setTargets(targets.map((x, j) => (j === i ? { ...x, system: e.target.value } : x)))} />
                </div>
                <Button variant="quiet" icon={Trash2} aria-label="Remove this target" disabled={targets.length === 1}
                  onClick={() => setTargets(targets.filter((_, j) => j !== i))} />
              </div>
            ))}
            <div><Button size="sm" icon={Plus} onClick={() => setTargets([...targets, { kind: 'path', value: '', system: '' }])}>Add a target</Button></div>
          </div>
        )}
        {mode === 'import' && (
          <div className="stack">
            <p className="small soft">Rank a CycloneDX 1.6 or 1.7 CBOM produced by another scanner, such as IBM CBOMkit, without
              rescanning. The import replaces the current estate.</p>
            <div className="field">
              <label htmlFor="cbomfile">CBOM file (.json)</label>
              <input id="cbomfile" type="file" accept=".json,application/json" onChange={(e) => setFile(e.target.files?.[0] || null)} />
            </div>
            {imported && <Callout tone="ok" title={imported.message} />}
          </div>
        )}
        <Sector value={persona} onChange={setPersona} />
        <div className="row">
          {mode === 'import' ? (
            <Button variant="primary" icon={Upload} busy={busy} disabled={!file} onClick={importCbom}>Import and rank</Button>
          ) : (
            <Button variant="primary" size="lg" icon={Play} busy={scan.running} disabled={!ready} onClick={run}>Run scan</Button>
          )}
          {scan.error && <span className="small" style={{ color: 'var(--bad-text)' }}>{scan.error.message}</span>}
        </div>
      </div>
    </Card>
  );
}

function Progress({ collectors }) {
  const scan = useScan();
  const s = scan.summary;
  if (!scan.job) return null;
  const labels = Object.fromEntries((collectors || []).map((c) => [c.name, c]));
  const status = s.failed ? 'failed' : s.done ? 'done' : 'running';
  return (
    <Card title={status === 'done' ? 'Scan finished' : status === 'failed' ? 'Scan failed' : 'Scanning'}
      description={`${fmt(s.finished)} of ${fmt(s.runs)} collector runs · ${fmt(scan.job.targets)} targets`}
      actions={status === 'done' && <ButtonLink to="/overview" variant="primary" icon={ArrowRight}>Open the overview</ButtonLink>}
      pad={false}>
      <div className="card-body stack">
        <Meter value={s.progress} tone={status === 'failed' ? 'bad' : status === 'done' ? 'ok' : ''} label="Scan progress" />
        {s.failed && <Callout tone="bad" title="The scan stopped">{s.failed.error}</Callout>}
        {s.done && (
          <p className="small soft">{fmt(s.resolved?.findings)} findings resolved to {fmt(s.done.assets)} assets
            ({fmt(s.resolved?.merged)} merged across collectors, {fmt(s.done.cross_plane_assets)} confirmed on more than one plane).
            {' '}{fmt(s.done.quantum_vulnerable)} are quantum-vulnerable; {fmt(s.done.drift)} drift records.</p>
        )}
      </div>
      <div className="table-wrap">
        <table className="table">
          <thead><tr><th>Surface</th><th>Plane</th><th>Status</th><th className="r">Runs</th><th className="r">Findings</th><th className="r">Time</th><th>Problems</th></tr></thead>
          <tbody>
            {s.surfaces.map((row) => {
              const info = labels[row.name] || {};
              const done = row.finished >= row.runs && row.runs > 0;
              return (
                <tr key={row.name}>
                  <td className="strong">{info.label || row.name}</td>
                  <td>{PLANE[info.plane] || '—'}</td>
                  <td>{row.fatal ? <Badge tone="bad" icon={OctagonX}>Failed</Badge>
                    : done ? <Badge tone="ok" icon={CircleCheck}>Done</Badge>
                      : row.running ? <Badge tone="primary" icon={LoaderCircle}>Reading</Badge> : <Badge>Queued</Badge>}</td>
                  <td className="r num">{row.finished}/{row.runs}</td>
                  <td className="r num">{fmt(row.findings)}</td>
                  <td className="r num">{row.ms ? `${(row.ms / 1000).toFixed(1)} s` : '—'}</td>
                  <td className="small">{row.failures.length ? (
                    <details><summary>{row.failures.length} item(s)</summary>
                      <ul className="list-plain">{row.failures.slice(0, 8).map((f, i) => <li key={i} className="break"><code>{shortPath(f.target)}</code>: {f.reason}</li>)}</ul>
                    </details>) : <span className="muted">None</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

function Surfaces({ collectors, grammars }) {
  return (
    <Card title="Surfaces V.E.R.A. reads" description="Eleven collectors on four evidence planes." pad={false}>
      <ul className="list-plain" style={{ padding: '0 var(--s-5)' }}>
        {collectors.map((c) => (
          <li key={c.name} className="stack" style={{ gap: 2 }}>
            <div className="row"><span className="strong grow">{c.label}</span><Badge>{PLANE[c.plane]}</Badge></div>
            <span className="small soft">{c.description}</span>
          </li>
        ))}
      </ul>
      {grammars && <div className="card-foot">Source parsers loaded: {Object.keys(grammars).join(', ')}.</div>}
    </Card>
  );
}

function HistoryCard() {
  const scans = useResource('/scans');
  return (
    <Card title="Previous scans" description="Compare any two in Evidence, Changes." pad={false}>
      <Load resource={scans} skeleton={<div className="card-body"><Skeleton /></div>}>
        {(rows) => (rows.length ? (
          <div className="table-wrap">
            <table className="table">
              <thead><tr><th>When</th><th>What</th><th className="r">Assets</th><th className="r">Vulnerable</th><th className="r">Late</th></tr></thead>
              <tbody>
                {rows.slice(0, 12).map((r) => (
                  <tr key={r.scan_id}><td className="nowrap">{dateTime(r.timestamp)}</td><td>{r.label}</td>
                    <td className="r num">{fmt(r.total_assets)}</td><td className="r num">{fmt(r.quantum_vulnerable)}</td>
                    <td className="r num">{fmt(r.negative_slack_count)}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <div className="card-body muted">No scans yet.</div>)}
      </Load>
    </Card>
  );
}

const TABS = [['run', 'Run a scan'], ['sensors', 'Sensors and coverage'], ['add', 'Add assets'], ['history', 'History']];

export default function Scan({ route }) {
  const t = useT();
  const auth = useAuth();
  const collectors = useResource('/scan/collectors');
  const [persona, setPersona] = useState('Banking');
  const tab = TABS.some(([k]) => k === route.segments[1]) ? route.segments[1] : 'run';
  return (
    <div className="page">
      <PageHead title={t('nav.scan')} description="Read every surface of an estate. Progress appears as each collector runs, and nothing leaves this machine." />
      <Tabs label="Scan views" active={tab} items={TABS.map(([key, label]) => ({ key, label, to: key === 'run' ? '/scan' : `/scan/${key}` }))} />
      {tab === 'run' && (
        <div className="grid-main-side">
          <div className="stack-lg">
            {auth.can('scan') ? <Start persona={persona} setPersona={setPersona} /> : (
              <Callout tone="info" title="Your role can read results but not start scans.">Ask an analyst or admin to run a scan.</Callout>
            )}
            <Progress collectors={collectors.data?.collectors} />
            <Datasets persona={persona} />
            <LiveEndpoints />
          </div>
          <Load resource={collectors} skeleton={<Skeleton height="30rem" />}>
            {(c) => <Surfaces collectors={c.collectors} grammars={c.grammars} />}
          </Load>
        </div>
      )}
      {tab === 'sensors' && <Sensors />}
      {tab === 'add' && <AddAssets persona={persona} />}
      {tab === 'history' && <div className="stack-lg"><HistoryCard /><Jobs /></div>}
      <p className="xsmall muted" style={{ marginTop: 'var(--s-5)' }}><Radar size={12} style={{ display: 'inline' }} aria-hidden /> Metadata only: key
        material is recorded by location and fingerprint, never read into V.E.R.A..</p>
    </div>
  );
}
