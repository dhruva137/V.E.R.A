/* The frame every screen sits in: skip link, brand, navigation, top bar,
 * the screen itself, the assistant panel and the asset panel.
 *
 * The top bar answers "what am I looking at and is it current": the estate,
 * when it was scanned, whether a scan is running, and the three NTRO posture
 * facts (offline, local model, read-only assistant). Everything else a person
 * needs is one keystroke away: Ctrl K searches assets, screens and actions,
 * and / opens the assistant.
 */

import { Suspense, useEffect, useRef, useState } from 'react';
import {
  Bot, CircleCheck, CircleHelp, Languages, LogOut, Search, Type, User, WifiOff,
} from 'lucide-react';
import { DESTINATIONS, SCREENS, SETTINGS, WHY, warm } from '../pages';
import { useAuth } from '../lib/auth';
import { useResource } from '../lib/data';
import { ago } from '../lib/format';
import { usePrefs, useT } from '../lib/prefs';
import { Link, navigate, useQueryParams, useRoute } from '../lib/router';
import { useScan } from '../lib/scan';
import Assistant from './Assistant';
import CommandPalette from './CommandPalette';
import Inbox from './Inbox';
import Mark from './Mark';
import { Button, Menu, Seg, Skeleton, Tip } from './ui';

const ASSIST_KEY = 'vera.assistant.open';

/* The assistant is closed, a side panel, or full screen. */
function readAssist() {
  try {
    const v = window.localStorage.getItem(ASSIST_KEY);
    return v === 'full' || v === '1' ? (v === 'full' ? 'full' : 'open') : 'closed';
  } catch { return 'closed'; }
}

function Ring({ value }) {
  const r = 8;
  const c = 2 * Math.PI * r;
  return (
    <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden>
      <circle cx="10" cy="10" r={r} fill="none" stroke="var(--line-strong)" strokeWidth="2.5" />
      <circle cx="10" cy="10" r={r} fill="none" stroke="var(--primary)" strokeWidth="2.5" strokeLinecap="round"
        strokeDasharray={c} strokeDashoffset={c * (1 - value)} transform="rotate(-90 10 10)"
        style={{ transition: 'stroke-dashoffset 180ms var(--ease)' }} />
    </svg>
  );
}

function Posture() {
  const ntro = useResource('/ntro-mode');
  const facts = ntro.data?.facts || [];
  const okCount = facts.filter((f) => f.ok).length;
  const label = facts.length ? `${okCount} of ${facts.length} safeguards on` : 'Posture';
  return (
    <Menu label="Operating posture" trigger={(props) => (
      <button type="button" className="btn btn-quiet btn-sm" onClick={props.toggle} aria-expanded={props['aria-expanded']}
        aria-haspopup="menu" aria-label={`Operating posture: ${ntro.data?.line || label}. Open details or Settings.`}>
        {ntro.data?.offline?.enforced ? <WifiOff size={16} aria-hidden /> : <CircleHelp size={16} aria-hidden />}
        <span className="nowrap hide-md">{label}</span>
        <span className="nowrap show-md">{facts.length ? `${okCount}/${facts.length}` : ''}</span>
      </button>
    )}>
      <div className="menu-label">Operating posture</div>
      {facts.map((fact) => (
        <div key={fact.key} className="menu-item" style={{ alignItems: 'flex-start', cursor: 'default' }}>
          {fact.ok ? <CircleCheck size={16} color="var(--ok)" aria-hidden /> : <CircleHelp size={16} color="var(--warn-text)" aria-hidden />}
          <span className="stack" style={{ gap: 0 }}>
            <span>{fact.label}</span>
            <span className="xsmall muted" style={{ maxWidth: '18rem' }}>{fact.detail}</span>
          </span>
        </div>
      ))}
      <hr />
      <Link to="/settings/runtime" className="menu-item" data-close>
        <span className="strong">Open Runtime settings</span>
        <span className="xsmall muted">Change offline mode, local model and assistant posture</span>
      </Link>
    </Menu>
  );
}

function DisplayMenu() {
  const { prefs, set } = usePrefs();
  const t = useT();
  return (
    <Menu label={t('top.display')} trigger={(props) => (
      <Button variant="quiet" icon={Type} onClick={props.toggle} aria-expanded={props['aria-expanded']}
        aria-haspopup="menu" aria-label={t('top.display')}><span className="hide-md">{t('top.display')}</span></Button>
    )}>
      <div className="stack" style={{ padding: 'var(--s-3)', gap: 'var(--s-3)', width: '17rem' }}>
        <div className="field">
          <span className="label">{t('top.textSize')}</span>
          <Seg label={t('top.textSize')} value={prefs.text} onChange={(text) => set({ text })}
            options={[{ value: 'normal', label: 'A' }, { value: 'large', label: 'A+' }, { value: 'larger', label: 'A++' }]} />
        </div>
        <div className="field">
          <span className="label">{t('top.theme')}</span>
          <Seg label={t('top.theme')} value={prefs.theme} onChange={(theme) => set({ theme })}
            options={[{ value: 'light', label: t('top.light') }, { value: 'dark', label: t('top.dark') }]} />
        </div>
        <div className="field">
          <span className="label">{t('top.language')}</span>
          <Seg label={t('top.language')} value={prefs.lang} onChange={(lang) => set({ lang })}
            options={[{ value: 'en', label: 'English' }, { value: 'hi', label: 'हिन्दी' }]} />
        </div>
      </div>
    </Menu>
  );
}

function UserMenu() {
  const auth = useAuth();
  const t = useT();
  const user = auth.user || {};
  return (
    <Menu label={t('top.signedInAs')} trigger={(props) => (
      <button type="button" className="btn btn-quiet btn-sm" onClick={props.toggle} aria-expanded={props['aria-expanded']}
        aria-haspopup="menu">
        <User size={16} aria-hidden />
        <span className="nowrap hide-md">{user.display_name || user.username}</span>
        {user.username === 'demo' && <span className="badge tone-info hide-sm">Demo</span>}
        <span className="badge tone-neutral hide-sm">{t(`role.${user.role}`)}</span>
      </button>
    )}>
      <div className="menu-label">{t('top.signedInAs')} {user.username}</div>
      {!auth.auth && <div className="menu-item xsmall muted" style={{ cursor: 'default' }}>Sign-in is off on this engine (VERA_AUTH=0).</div>}
      <Link to="/settings/users" className="menu-item" data-close>{t('settings.users')}</Link>
      {auth.auth && (
        <button type="button" className="menu-item" data-close onClick={auth.signOut}>
          <LogOut size={16} aria-hidden /> {t('top.signOut')}
        </button>
      )}
    </Menu>
  );
}

function TopBar({ current, onSearch, onAssistant, assistOpen }) {
  const t = useT();
  const scan = useScan();
  const scanInfo = current.data?.scan;
  return (
    <header className="top">
      <div className="top-estate">
        {current.data === undefined ? <Skeleton lines={1} /> : scanInfo ? (
          <>
            <strong title={scanInfo.estate}>{scanInfo.estate}</strong>
            <span>{t('top.lastScan')} {ago(scanInfo.timestamp)} · {scanInfo.assets} assets</span>
          </>
        ) : (
          <>
            <strong>{t('top.noScan')}</strong>
            <span>Start from Scan</span>
          </>
        )}
      </div>
      {scan.running && (
        <Link to="/scan" className="btn btn-sm" aria-label={`${t('top.scanning')}: ${scan.summary.finished} of ${scan.summary.runs}`}>
          <Ring value={scan.summary.progress} />
          <span className="nowrap">{t('top.scanning')} {scan.summary.finished}/{scan.summary.runs || '…'}</span>
        </Link>
      )}
      <button type="button" className="top-search" onClick={onSearch}>
        <Search size={16} aria-hidden />
        <span className="truncate hide-sm">{t('top.search')}</span>
        <kbd className="hide-sm">Ctrl</kbd><kbd className="hide-sm">K</kbd>
      </button>
      <span className="hide-sm"><Posture /></span>
      <Inbox />
      <span className="top-divider hide-sm" aria-hidden />
      <Tip below text="Ask about this estate. Press / from anywhere.">
        <Button variant="quiet" icon={Bot} aria-pressed={assistOpen} onClick={onAssistant} aria-label={t('top.assistant')}>
          <span className="hide-md">{t('top.assistant')}</span>
        </Button>
      </Tip>
      <DisplayMenu />
      <UserMenu />
    </header>
  );
}

function Nav({ active, hasScan }) {
  const t = useT();
  const item = (d) => (
    <li key={d.key}>
      <Link to={d.to} className="nav-item" aria-current={active === d.key ? 'page' : undefined}
        onWarm={() => warm(d.key, hasScan)} title={t(`nav.${d.key}`)}>
        <d.icon size={18} aria-hidden />
        <span>{t(`nav.${d.key}`)}</span>
      </Link>
    </li>
  );
  return (
    <nav className="nav" aria-label="Main">
      <ul className="nav-list">{DESTINATIONS.map(item)}</ul>
      <ul className="nav-list nav-list-secondary">
        {item(WHY)}
        {item(SETTINGS)}
      </ul>
      <div className="nav-foot">
        <div className="nav-fact"><Languages size={14} aria-hidden /><span>English · हिन्दी in Display</span></div>
        <div className="nav-fact"><CircleCheck size={14} aria-hidden /><span>Runs on this machine. No request leaves it.</span></div>
      </div>
    </nav>
  );
}

export default function Shell() {
  const route = useRoute();
  const t = useT();
  const [params] = useQueryParams();
  const [assistMode, setAssistMode] = useState(readAssist);
  const assistOpen = assistMode !== 'closed';
  const [paletteOpen, setPaletteOpen] = useState(false);
  const current = useResource('/scan/current');
  const hasScan = Boolean(current.data?.scan);
  const main = useRef(null);

  const screenKey = SCREENS[route.segments[0]] ? route.segments[0] : 'overview';
  const Screen = SCREENS[screenKey];
  const assetId = params.get('asset');

  useEffect(() => {
    if (!route.segments.length) navigate('/overview', { replace: true });
  }, [route.segments.length]);

  // Older links carried the asset as ?asset=<id> on another screen; assets now have their own page.
  useEffect(() => {
    if (assetId) navigate(`/asset/${encodeURIComponent(assetId)}${params.get('tab') ? `/${params.get('tab')}` : ''}`, { replace: true });
  }, [assetId]);

  useEffect(() => {
    document.title = `${t(`nav.${screenKey}`)} · V.E.R.A.`;
    if (main.current) main.current.scrollTop = 0;
  }, [route.path, screenKey, t]);

  useEffect(() => {
    try { window.localStorage.setItem(ASSIST_KEY, assistMode === 'full' ? 'full' : assistMode === 'open' ? '1' : '0'); } catch { /* per visit only */ }
  }, [assistMode]);

  useEffect(() => {
    const onKey = (event) => {
      const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(event.target.tagName) || event.target.isContentEditable;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        setPaletteOpen(true);
      } else if (event.key === '/' && !typing) {
        event.preventDefault();
        setAssistMode((mode) => (mode === 'closed' ? 'open' : mode));
        setTimeout(() => document.getElementById('assist-input')?.focus(), 0);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="shell" data-assist={assistMode === 'open' ? 'open' : 'closed'}>
      <a className="skip-link" href="#main" onClick={(event) => { event.preventDefault(); main.current?.focus(); }}>
        {t('common.skip')}
      </a>
      <Link to="/overview" className="brand" aria-label="V.E.R.A., Verified Enumeration of Risky Algorithms: go to Overview">
        <Mark />
        <span className="brand-text">
          <span className="brand-name">V.E.R.A.</span>
          <span className="brand-sub" style={{ display: 'block' }}>Certified crypto discovery</span>
        </span>
      </Link>
      <TopBar current={current} onSearch={() => setPaletteOpen(true)} assistOpen={assistOpen}
        onAssistant={() => setAssistMode((mode) => (mode === 'closed' ? 'open' : 'closed'))} />
      <Nav active={screenKey === 'asset' ? 'inventory' : screenKey} hasScan={hasScan} />
      <main id="main" ref={main} className="main" tabIndex={-1}>
        <Suspense fallback={<div className="page"><Skeleton lines={6} /></div>}>
          <div key={screenKey} className="route-enter">
            <Screen route={route} hasScan={hasScan} scanInfo={current.data?.scan} />
          </div>
        </Suspense>
      </main>
      {assistOpen && <Assistant full={assistMode === 'full'} onClose={() => setAssistMode('closed')}
        onToggleFull={() => setAssistMode((mode) => (mode === 'full' ? 'open' : 'full'))} />}

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} hasScan={hasScan}
        onAssistant={() => setAssistMode((mode) => (mode === 'closed' ? 'open' : mode))} />}
    </div>
  );
}
