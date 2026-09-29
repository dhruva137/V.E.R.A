/* Inventory: every cryptographic asset, as a work queue.
 *
 * Sorted by priority by default. Filters live in the address, so a filtered
 * view can be linked from a report or a ticket. The list renders only the rows
 * on screen, so it scrolls smoothly at twenty thousand assets as at two hundred.
 * Opening a row shows the asset panel over this screen; closing it returns to
 * the same place in the list.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronDown, Download, ListFilter, Search, TriangleAlert, X } from 'lucide-react';
import {
  Badge, Button, Callout, Empty, Load, Menu, MoscaBadge, PageHead, Skeleton, StatusBadge,
} from '../components/ui';
import { useResource } from '../lib/data';
import { fmt, fmt1, shortPath } from '../lib/format';
import { NEED, OWNER, PLANE, SOURCE } from '../lib/labels';
import { useT } from '../lib/prefs';
import { openAsset, useQueryParams } from '../lib/router';

const ROW_H = 56;
const FACETS = [
  ['status', 'Status'], ['mosca', 'Mosca'], ['risk_level', 'Risk'], ['system', 'System'], ['class_label', 'Type'],
  ['plane', 'Evidence'], ['need', 'Fix'], ['owner', 'Who acts'], ['source_type', 'Found in'],
];

function useLabel() {
  const t = useT();
  return (facet, value) => {
    if (facet === 'status') return t(`status.${value}`);
    if (facet === 'mosca') return t(`mosca.${value || 'not_applicable'}`);
    if (facet === 'need') return NEED[value] || value;
    if (facet === 'owner') return OWNER[value] || value;
    if (facet === 'plane') return PLANE[value] || value;
    if (facet === 'source_type') return SOURCE[value] || value;
    if (facet === 'system') return value || 'Not in the register';
    if (facet === 'risk_level') return value ? value[0].toUpperCase() + value.slice(1) : '—';
    return value || '—';
  };
}

function FacetMenu({ facet, title, options, selected, onChange }) {
  const label = useLabel();
  const active = selected.length > 0;
  return (
    <Menu label={title} align="left" trigger={(props) => (
      <button type="button" className="btn btn-sm" aria-pressed={active} onClick={props.toggle}
        aria-expanded={props['aria-expanded']} aria-haspopup="menu">
        {title}{active ? `: ${selected.length === 1 ? label(facet, selected[0]) : selected.length}` : ''}
        <ChevronDown size={14} aria-hidden />
      </button>
    )}>
      <div style={{ maxHeight: '22rem', overflowY: 'auto', padding: 'var(--s-1)' }}>
        {options.map((o) => (
          <label key={o.value} className="menu-item check" style={{ justifyContent: 'flex-start' }}>
            <input type="checkbox" checked={selected.includes(o.value)}
              onChange={(e) => onChange(e.target.checked ? [...selected, o.value] : selected.filter((v) => v !== o.value))} />
            <span className="grow">{label(facet, o.value)}</span>
            <span className="xsmall muted num">{fmt(o.count)}</span>
          </label>
        ))}
      </div>
    </Menu>
  );
}

function toCsv(rows) {
  const cols = ['name', 'status', 'algorithm', 'key_size', 'class_label', 'system', 'location', 'plane', 'mosca',
    'deadline_year', 'slack_months', 'need', 'fix', 'owner', 'priority_rank'];
  const esc = (v) => (v === null || v === undefined ? '' : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
  return [cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
}

function List({ rows, sort, setSort }) {
  const scroller = useRef(null);
  const [top, setTop] = useState(0);
  const [height, setHeight] = useState(600);
  useEffect(() => {
    const node = scroller.current;
    if (!node) return undefined;
    const measure = () => setHeight(node.clientHeight);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);
  const start = Math.max(0, Math.floor(top / ROW_H) - 8);
  const end = Math.min(rows.length, Math.ceil((top + height) / ROW_H) + 8);
  const visible = rows.slice(start, end);

  const th = (key, text, align) => {
    const active = sort.key === key;
    return (
      <th className={align === 'r' ? 'r' : undefined} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
        <button type="button" className="th-sort" onClick={() => setSort({ key, dir: active && sort.dir === 'asc' ? 'desc' : 'asc' })}>
          {text}{active ? (sort.dir === 'asc' ? ' ↑' : ' ↓') : ''}
        </button>
      </th>
    );
  };

  const onKey = (event, index) => {
    if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openAsset(rows[index].id); }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault();
      const next = index + (event.key === 'ArrowDown' ? 1 : -1);
      if (next < 0 || next >= rows.length) return;
      const node = scroller.current;
      const y = next * ROW_H;
      if (y < node.scrollTop + ROW_H) node.scrollTop = Math.max(0, y - ROW_H);
      if (y > node.scrollTop + node.clientHeight - 2 * ROW_H) node.scrollTop = y - node.clientHeight + 2 * ROW_H;
      requestAnimationFrame(() => node.querySelector(`[data-index="${next}"]`)?.focus());
    }
  };

  return (
    <div ref={scroller} className="card table-wrap" style={{ height: 'calc(100vh - 17rem)', minHeight: '24rem', overflowY: 'auto' }}
      onScroll={(e) => setTop(e.currentTarget.scrollTop)}>
      <table className="table" style={{ tableLayout: 'fixed' }} aria-rowcount={rows.length + 1}>
        <colgroup>
          <col style={{ width: '3.5rem' }} /><col style={{ width: '25%' }} /><col style={{ width: '8.5rem' }} /><col style={{ width: '8%' }} />
          <col style={{ width: '9%' }} /><col style={{ width: '9.5rem' }} /><col style={{ width: '5.5rem' }} /><col style={{ width: '8rem' }} /><col />
        </colgroup>
        <thead>
          <tr>{th('priority_rank', '#', 'r')}{th('name', 'Asset')}{th('status', 'Status')}{th('algorithm', 'Algorithm')}
            {th('system', 'System')}{th('mosca', 'Mosca')}{th('dependents', 'Relied on by', 'r')}{th('slack_months', 'DST', 'r')}{th('fix', 'Fix')}</tr>
        </thead>
        <tbody>
          {start > 0 && <tr aria-hidden style={{ height: start * ROW_H }}><td colSpan={9} style={{ padding: 0, border: 0 }} /></tr>}
          {visible.map((r, i) => {
            const index = start + i;
            return (
              <tr key={r.id} data-clickable data-index={index} tabIndex={0} aria-rowindex={index + 2} style={{ height: ROW_H }}
                onClick={() => openAsset(r.id)} onKeyDown={(e) => onKey(e, index)}>
                <td className="r num muted">{r.priority_rank || '—'}</td>
                <td>
                  <div className="truncate strong" title={r.name}>{r.name}</div>
                  <div className="truncate xsmall muted mono" title={r.location}>{shortPath(r.location)}</div>
                </td>
                <td><StatusBadge status={r.status} /></td>
                <td className="truncate">{r.algorithm || '—'}{r.key_size ? <span className="muted"> {r.key_size}</span> : null}</td>
                <td className="truncate">{r.system || <span className="muted">Unregistered</span>}</td>
                <td><MoscaBadge category={r.mosca || 'not_applicable'} /></td>
                <td className="r num" title="Assets that rely on this one, directly or through others">{r.dependents ? fmt(r.dependents) : <span className="muted">—</span>}</td>
                <td className="r num">
                  {r.need ? (
                    <span style={{ color: r.behind ? 'var(--bad-text)' : undefined, fontWeight: r.behind ? 600 : 400 }}>
                      {r.behind && <TriangleAlert size={12} style={{ display: 'inline', marginRight: 4 }} aria-label="Late" />}
                      {r.deadline_year} · {r.slack_months < 0 ? '−' : '+'}{fmt1(Math.abs(r.slack_months))} mo
                    </span>
                  ) : <span className="muted">—</span>}
                </td>
                <td className="truncate" title={r.fix || ''}>{r.fix || <span className="muted">Nothing</span>}
                  {r.drift && <Badge tone="warn">drift</Badge>}</td>
              </tr>
            );
          })}
          {end < rows.length && <tr aria-hidden style={{ height: (rows.length - end) * ROW_H }}><td colSpan={9} style={{ padding: 0, border: 0 }} /></tr>}
        </tbody>
      </table>
    </div>
  );
}

const ORDER = { status: { broken: 0, vulnerable: 1, weakened: 2, unresolved: 3, safe: 4 },
  mosca: { certain: 0, likely: 1, possible: 2, clear: 3, not_applicable: 4 } };

function Body({ data: raw }) {
  const t = useT();
  const deps = useResource('/dependencies/summary');
  const data = useMemo(() => ({ ...raw, rows: raw.rows.map((r) => ({ ...r, dependents: deps.data?.assets?.[r.id]?.dependents ?? 0 })) }), [raw, deps.data]);
  const [params, setParams] = useQueryParams();
  const [query, setQuery] = useState(params.get('q') || '');
  const [sort, setSort] = useState({ key: 'priority_rank', dir: 'asc' });
  useEffect(() => {
    const timer = setTimeout(() => setParams({ q: query || null }), 200);
    return () => clearTimeout(timer);
  }, [query, setParams]);

  const selected = (facet) => (params.has(facet) ? params.get(facet).split(',') : []);
  const flags = selected('flag');
  const filtered = useMemo(() => {
    const q = (params.get('q') || '').toLowerCase();
    const active = FACETS.map(([f]) => [f, params.has(f) ? params.get(f).split(',') : null]).filter(([, v]) => v);
    const rows = data.rows.filter((r) => {
      for (const [facet, values] of active) if (!values.includes(r[facet] === null || r[facet] === undefined ? '' : String(r[facet]))) return false;
      if (flags.includes('behind') && !r.behind) return false;
      if (flags.includes('drift') && !r.drift) return false;
      if (q && !`${r.name} ${r.location} ${r.algorithm || ''} ${r.system || ''} ${r.fix || ''}`.toLowerCase().includes(q)) return false;
      return true;
    });
    const value = (r) => {
      const v = r[sort.key];
      if (ORDER[sort.key]) return ORDER[sort.key][v || 'not_applicable'] ?? 9;
      if (sort.key === 'priority_rank') return v || 1e9;
      return v === null || v === undefined ? '' : v;
    };
    return rows.sort((a, b) => {
      const x = value(a); const y = value(b);
      return (x < y ? -1 : x > y ? 1 : 0) * (sort.dir === 'asc' ? 1 : -1);
    });
  }, [data.rows, params, sort, flags]);

  const anyFilter = FACETS.some(([f]) => params.has(f)) || flags.length || params.get('q');
  const exportCsv = () => {
    const blob = new Blob([toCsv(filtered)], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'vera-inventory.csv'; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  return (
    <div className="stack">
      <div className="row-wrap">
        <div className="search-input" style={{ width: '18rem' }}>
          <Search size={16} aria-hidden />
          <input className="input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Name, path, algorithm, system"
            aria-label="Search the inventory" />
        </div>
        <ListFilter size={16} className="muted" aria-hidden />
        {FACETS.map(([facet, title]) => (
          <FacetMenu key={facet} facet={facet} title={title} options={data.facets[facet] || []} selected={selected(facet)}
            onChange={(values) => setParams({ [facet]: values.length ? values.join(',') : null })} />
        ))}
        {data.facets.flags.map((f) => (
          <button key={f.value} type="button" className="btn btn-sm" aria-pressed={flags.includes(f.value)}
            onClick={() => setParams({ flag: (flags.includes(f.value) ? flags.filter((x) => x !== f.value) : [...flags, f.value]).join(',') || null })}>
            {f.value === 'behind' ? 'Late for DST' : 'Policy drift'} <span className="muted">{fmt(f.count)}</span>
          </button>
        ))}
      </div>
      <div className="row">
        <span className="small soft grow" role="status">Showing {fmt(filtered.length)} of {fmt(data.rows.length)} assets</span>
        {anyFilter && <Button size="sm" variant="quiet" icon={X} onClick={() => {
          setQuery('');
          setParams(Object.fromEntries([...FACETS.map(([f]) => [f, null]), ['flag', null], ['q', null]]));
        }}>Clear filters</Button>}
        <Button size="sm" icon={Download} onClick={exportCsv}>{t('common.export')}</Button>
      </div>
      {filtered.length ? <List rows={filtered} sort={sort} setSort={setSort} /> : (
        <div className="card"><Empty title="No asset matches these filters">Remove a filter, or search for part of a path or algorithm.</Empty></div>
      )}
    </div>
  );
}

export default function Inventory({ hasScan }) {
  const t = useT();
  const inventory = useResource(hasScan ? '/inventory' : null);
  return (
    <div className="page">
      <PageHead title={t('nav.inventory')} description="Every cryptographic asset, in priority order. Select one to see where it is, the evidence, and the fix." />
      {!hasScan ? <Callout tone="info" title="Nothing scanned yet.">Run a scan first; the inventory fills in as soon as it finishes.</Callout> : (
        <Load resource={inventory} skeleton={<Skeleton height="30rem" />}>{(data) => <Body data={data} />}</Load>
      )}
    </div>
  );
}
