/* Ctrl K: one box to reach any screen, any asset and the common actions.
 *
 * Assets are matched on name, location, algorithm and system, from the same
 * inventory rows the Inventory screen reads, so nothing extra is fetched.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { Bot, Boxes, Download, FileCheck2, Moon, Radar, Search, Sun } from 'lucide-react';
import { download } from '../lib/api';
import { useResource } from '../lib/data';
import { usePrefs, useT } from '../lib/prefs';
import { navigate, openAsset } from '../lib/router';
import { StatusBadge } from './ui';

const SCREENS = [
  ['/overview', 'nav.overview'], ['/scan', 'nav.scan'], ['/inventory', 'nav.inventory'],
  ['/risk/exposure', 'risk.exposure'], ['/risk/drift', 'risk.drift'], ['/risk/dependencies', 'risk.dependencies'],
  ['/plan/actions', 'plan.actions'], ['/plan/suppliers', 'plan.suppliers'], ['/plan/timeline', 'plan.timeline'],
  ['/evidence/reports', 'evidence.reports'], ['/evidence/certin', 'evidence.certin'],
  ['/evidence/integrity', 'evidence.integrity'], ['/evidence/changes', 'evidence.changes'],
  ['/evidence/method', 'evidence.method'], ['/settings/runtime', 'settings.runtime'],
  ['/settings/users', 'settings.users'], ['/settings/model', 'settings.model'],
  ['/settings/policy', 'settings.policy'], ['/settings/access', 'settings.access'],
];

export default function CommandPalette({ onClose, hasScan, onAssistant }) {
  const t = useT();
  const { prefs, set } = usePrefs();
  const [query, setQuery] = useState('');
  const [index, setIndex] = useState(0);
  const input = useRef(null);
  const inventory = useResource('/inventory', { enabled: hasScan });

  useEffect(() => { input.current?.focus(); }, []);

  const groups = useMemo(() => {
    const q = query.trim().toLowerCase();
    const match = (text) => !q || text.toLowerCase().includes(q);
    const screens = SCREENS.filter(([path, key]) => match(`${t(key)} ${path}`)).map(([path, key]) => ({
      id: path, icon: path.startsWith('/scan') ? Radar : path.startsWith('/evidence') ? FileCheck2 : Boxes,
      label: t(key), sub: path.split('/')[1], run: () => navigate(path),
    }));
    const actions = [
      { id: 'assistant', icon: Bot, label: 'Ask the assistant', run: onAssistant },
      { id: 'theme', icon: prefs.theme === 'dark' ? Sun : Moon, label: prefs.theme === 'dark' ? 'Use light theme' : 'Use dark theme',
        run: () => set({ theme: prefs.theme === 'dark' ? 'light' : 'dark' }) },
      ...(hasScan ? [
        { id: 'cbom', icon: Download, label: 'Download the CBOM (CycloneDX 1.7)', run: () => download('/cbom', 'vera-cbom.cdx.json') },
        { id: 'report', icon: Download, label: 'Download the NTRO assessment report (PDF)', run: () => download('/report/ntro') },
      ] : []),
    ].filter((a) => match(a.label));
    const rows = inventory.data?.rows || [];
    const assets = q.length < 2 ? [] : rows.filter((r) => match(`${r.name} ${r.location} ${r.algorithm || ''} ${r.system || ''}`))
      .slice(0, 12).map((r) => ({ id: r.id, icon: Search, label: r.name, sub: r.system || r.class_label, status: r.status, run: () => {
        navigate('/inventory');
        setTimeout(() => openAsset(r.id), 0);
      } }));
    return [['Screens', screens], ['Actions', actions], ['Assets', assets]].filter(([, items]) => items.length);
  }, [query, t, prefs.theme, set, hasScan, inventory.data, onAssistant]);

  const flat = groups.flatMap(([, items]) => items);
  useEffect(() => { setIndex(0); }, [query]);

  const choose = (item) => {
    if (!item) return;
    onClose();
    item.run();
  };

  const onKey = (event) => {
    if (event.key === 'ArrowDown') { event.preventDefault(); setIndex((i) => Math.min(flat.length - 1, i + 1)); }
    if (event.key === 'ArrowUp') { event.preventDefault(); setIndex((i) => Math.max(0, i - 1)); }
    if (event.key === 'Enter') { event.preventDefault(); choose(flat[index]); }
    if (event.key === 'Escape') onClose();
  };

  let position = -1;
  return (
    <>
      <div className="scrim dialog-scrim" onClick={onClose} aria-hidden />
      <div className="dialog palette" role="dialog" aria-modal="true" aria-label="Search">
        <div className="palette-input">
          <Search size={18} aria-hidden />
          <input ref={input} value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={onKey}
            placeholder={t('top.search')} aria-label={t('top.search')} role="combobox" aria-expanded="true"
            aria-controls="palette-list" aria-activedescendant={flat[index] ? `pal-${index}` : undefined} />
          <kbd>Esc</kbd>
        </div>
        <ul id="palette-list" className="palette-list" role="listbox">
          {groups.map(([name, items]) => (
            <li key={name} role="presentation">
              <div className="palette-group">{name}</div>
              <ul role="group" aria-label={name} style={{ listStyle: 'none' }}>
                {items.map((item) => {
                  position += 1;
                  const mine = position;
                  return (
                    <li key={item.id} id={`pal-${mine}`} role="option" aria-selected={mine === index} className="palette-item"
                      onMouseEnter={() => setIndex(mine)} onClick={() => choose(item)}>
                      <item.icon size={16} aria-hidden />
                      <span className="truncate">{item.label}</span>
                      {item.status && <StatusBadge status={item.status} />}
                      {item.sub && <span className="sub">{item.sub}</span>}
                    </li>
                  );
                })}
              </ul>
            </li>
          ))}
          {!flat.length && <li className="palette-group">Nothing matches “{query}”.</li>}
        </ul>
        <div className="palette-foot">
          <span><kbd>↑</kbd> <kbd>↓</kbd> move</span>
          <span><kbd>Enter</kbd> open</span>
          <span>Type two letters to search assets</span>
        </div>
      </div>
    </>
  );
}
