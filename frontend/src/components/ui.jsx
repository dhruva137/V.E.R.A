/* Shared building blocks. Each one carries its meaning in words and an icon,
 * never in colour alone (GIGW 3.0 / WCAG 1.4.1), and every figure can show
 * its source on hover or keyboard focus. */

import { createContext, useCallback, useContext, useEffect, useId, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle, ArrowDown, ArrowUp, ArrowUpDown, CircleCheck, CircleHelp, Info, LoaderCircle, OctagonX,
  ShieldAlert, ShieldCheck, X,
} from 'lucide-react';
import { useT } from '../lib/prefs';
import { Link } from '../lib/router';

/* ------------------------------------------------------------------ buttons */

export function Button({ variant, size, icon: Icon, busy, children, className = '', ...rest }) {
  const classes = ['btn', variant && `btn-${variant}`, size && `btn-${size}`, !children && 'btn-icon', className]
    .filter(Boolean).join(' ');
  return (
    <button type="button" className={classes} disabled={busy || rest.disabled} aria-busy={busy || undefined} {...rest}>
      {/* Busy is shown by a still icon and the disabled state: no looping animation. */}
      {busy ? <LoaderCircle size={16} aria-hidden /> : Icon && <Icon size={16} aria-hidden />}
      {children}
    </button>
  );
}

export function ButtonLink({ to, variant, size, icon: Icon, children, ...rest }) {
  return (
    <Link to={to} className={['btn', variant && `btn-${variant}`, size && `btn-${size}`].filter(Boolean).join(' ')} {...rest}>
      {Icon && <Icon size={16} aria-hidden />}
      {children}
    </Link>
  );
}

/* ------------------------------------------------------------------ layout */

export function PageHead({ title, description, actions }) {
  return (
    <header className="page-head">
      <div className="grow">
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {actions && <div className="page-head-actions">{actions}</div>}
    </header>
  );
}

export function Card({ title, description, actions, children, footer, pad = true, className = '', as: Tag = 'section', ...rest }) {
  const headingId = useId();
  return (
    <Tag className={`card ${className}`} aria-labelledby={title ? headingId : undefined} {...rest}>
      {title && (
        <div className="card-head">
          <div className="grow">
            <h2 id={headingId}>{title}</h2>
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="actions">{actions}</div>}
        </div>
      )}
      {pad ? <div className="card-body">{children}</div> : children}
      {footer && <div className="card-foot">{footer}</div>}
    </Tag>
  );
}

export function SectionTitle({ title, description, actions }) {
  return (
    <div className="section-title">
      <h2>{title}</h2>
      {description && <p>{description}</p>}
      {actions && <div className="actions">{actions}</div>}
    </div>
  );
}

export function Kv({ rows }) {
  return (
    <dl className="kv">
      {rows.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v], i) => (
        <div key={typeof k === 'string' ? k : i} style={{ display: 'contents' }}>
          <dt>{k}</dt>
          <dd>{v}</dd>
        </div>
      ))}
    </dl>
  );
}

/* ------------------------------------------------------------------ tooltips and sources */

export function Tip({ text, children, label, below = false }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  if (!text) return children;
  return (
    <span
      className="tip"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
    >
      {children || (
        <button type="button" className="btn btn-quiet btn-icon btn-sm" aria-label={label || 'Source'} aria-describedby={open ? id : undefined}>
          <Info size={14} aria-hidden />
        </button>
      )}
      {open && <span role="tooltip" id={id} className={below ? 'tip-body below' : 'tip-body'}>{text}</span>}
    </span>
  );
}

export function Figure({ label, value, detail, source, onClick, tone }) {
  const t = useT();
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag className="figure" onClick={onClick} type={onClick ? 'button' : undefined}>
      <span className="figure-label">
        {tone && <span className={`dot dot-${tone}`} aria-hidden />}
        {label}
      </span>
      <span className="figure-value">{value}</span>
      {detail && <span className="figure-detail">{detail}</span>}
      {source && (
        <span className="figure-source">
          <Info size={12} aria-hidden />
          <span><span className="sr-only">{t('common.source')}: </span>{source}</span>
        </span>
      )}
    </Tag>
  );
}

/* ------------------------------------------------------------------ status words */

const STATUS = {
  broken: { tone: 'bad', icon: OctagonX },
  vulnerable: { tone: 'warn', icon: AlertTriangle },
  weakened: { tone: 'info', icon: ShieldAlert },
  safe: { tone: 'ok', icon: ShieldCheck },
  unresolved: { tone: 'neutral', icon: CircleHelp },
};

export function StatusBadge({ status }) {
  const t = useT();
  const spec = STATUS[status] || STATUS.unresolved;
  const Icon = spec.icon;
  return (
    <span className={`badge tone-${spec.tone}`}>
      <Icon size={12} aria-hidden />
      {t(`status.${status}`)}
    </span>
  );
}

const MOSCA = {
  certain: { tone: 'bad', icon: OctagonX },
  likely: { tone: 'warn', icon: AlertTriangle },
  possible: { tone: 'warn', icon: AlertTriangle },
  clear: { tone: 'ok', icon: CircleCheck },
  not_applicable: { tone: 'neutral', icon: CircleHelp },
};

export function MoscaBadge({ category }) {
  const t = useT();
  if (!category) return <span className="muted">—</span>;
  const spec = MOSCA[category] || MOSCA.not_applicable;
  const Icon = spec.icon;
  return (
    <span className={`badge tone-${spec.tone}`}>
      <Icon size={12} aria-hidden />
      {t(`mosca.${category}`)}
    </span>
  );
}

const SEVERITY = { critical: 'bad', high: 'warn', medium: 'info', low: 'neutral', informational: 'neutral', safe: 'ok' };

export function SeverityBadge({ level }) {
  if (!level) return null;
  const tone = SEVERITY[level] || 'neutral';
  const Icon = tone === 'bad' ? OctagonX : tone === 'warn' ? AlertTriangle : tone === 'ok' ? CircleCheck : Info;
  return (
    <span className={`badge tone-${tone}`}>
      <Icon size={12} aria-hidden />
      {level[0].toUpperCase() + level.slice(1)}
    </span>
  );
}

export function Badge({ tone = 'neutral', icon: Icon, children, title }) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      {Icon && <Icon size={12} aria-hidden />}
      {children}
    </span>
  );
}

/* ------------------------------------------------------------------ states */

export function Callout({ tone = 'info', title, children, icon, action }) {
  const Icon = icon || (tone === 'bad' ? OctagonX : tone === 'warn' ? AlertTriangle : tone === 'ok' ? CircleCheck : Info);
  return (
    <div className={`callout tone-${tone}`} role={tone === 'bad' ? 'alert' : undefined}>
      <Icon size={16} aria-hidden />
      <div className="grow stack" style={{ gap: 'var(--s-1)' }}>
        {title && <div className="title">{title}</div>}
        {children && <div>{children}</div>}
      </div>
      {action}
    </div>
  );
}

export function Empty({ title, children, action }) {
  return (
    <div className="empty">
      <h2>{title}</h2>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function ErrorState({ error, onRetry }) {
  const t = useT();
  return (
    <Callout
      tone="bad"
      title={error?.status === 403 ? 'Your role does not allow this.' : 'This could not be loaded.'}
      action={onRetry && <Button size="sm" onClick={onRetry}>{t('common.retry')}</Button>}
    >
      <p>{error?.message || String(error)}</p>
      {error?.remedy && <p>{error.remedy}</p>}
    </Callout>
  );
}

export function Skeleton({ lines = 3, height }) {
  if (height) return <div className="skeleton" style={{ height }} aria-hidden />;
  return (
    <div className="stack" aria-hidden>
      {Array.from({ length: lines }, (_, i) => (
        <div key={i} className="skeleton-line" style={{ width: `${90 - i * 12}%` }} />
      ))}
    </div>
  );
}

/* Render a resource: a static skeleton first, the error with a retry, or the data. */
export function Load({ resource, skeleton, children, empty }) {
  if (resource.error && resource.data === undefined) {
    if (resource.error.status === 409 && empty) return empty;
    return <ErrorState error={resource.error} onRetry={resource.reload} />;
  }
  if (resource.data === undefined) return skeleton || <Skeleton />;
  return children(resource.data);
}

/* ------------------------------------------------------------------ bars */

export function Meter({ value, tone, label }) {
  const clamped = Math.max(0, Math.min(1, value || 0));
  return (
    <div className={`meter ${tone || ''}`} role="meter" aria-valuemin={0} aria-valuemax={100}
      aria-valuenow={Math.round(clamped * 100)} aria-label={label}>
      <span style={{ width: `${clamped * 100}%` }} />
    </div>
  );
}

const TONE_VAR = { bad: 'var(--bad)', warn: 'var(--warn)', ok: 'var(--ok)', info: 'var(--info)', neutral: 'var(--line-strong)', primary: 'var(--primary)' };

export function Stacked({ parts, label }) {
  const total = parts.reduce((n, p) => n + p.value, 0) || 1;
  return (
    <div className="stacked" role="img" aria-label={label || parts.map((p) => `${p.label}: ${p.value}`).join(', ')}>
      {parts.filter((p) => p.value > 0).map((p) => (
        <span key={p.label} title={`${p.label}: ${p.value}`} style={{ width: `${(100 * p.value) / total}%`, background: TONE_VAR[p.tone] }} />
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ tabs */

export function Tabs({ items, active, label }) {
  return (
    <nav className="tabs" aria-label={label}>
      {items.map((item) => (
        <Link key={item.key} to={item.to} className="tab"
          aria-current={item.key === active ? 'page' : undefined} onWarm={item.onWarm}>
          {item.label}
          {item.count !== undefined && <span className="count">{item.count}</span>}
        </Link>
      ))}
    </nav>
  );
}

export function LocalTabs({ items, active, onChange, label }) {
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {items.map((item) => (
        <button key={item.key} type="button" role="tab" className="tab" aria-selected={item.key === active}
          onClick={() => onChange(item.key)}>
          {item.label}
          {item.count !== undefined && <span className="count">{item.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Seg({ options, value, onChange, label }) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.value} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

/* ------------------------------------------------------------------ sortable tables */

export function useSort(rows, initial) {
  const [sort, setSort] = useState(initial);
  const sorted = useMemo(() => {
    if (!sort || !rows) return rows || [];
    const { key, dir } = sort;
    const value = typeof key === 'function' ? key : (row) => row[key];
    return [...rows].sort((a, b) => {
      const x = value(a);
      const y = value(b);
      if (x === y) return 0;
      if (x === null || x === undefined) return 1;
      if (y === null || y === undefined) return -1;
      return (x < y ? -1 : 1) * (dir === 'asc' ? 1 : -1);
    });
  }, [rows, sort]);
  const header = (key, label, { align } = {}) => {
    const activeKey = sort && (typeof sort.key === 'string' ? sort.key : sort.id);
    const active = activeKey === key;
    const Icon = !active ? ArrowUpDown : sort.dir === 'asc' ? ArrowUp : ArrowDown;
    return (
      <th className={align === 'right' ? 'r' : undefined} aria-sort={active ? (sort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}>
        <button type="button" className="th-sort" onClick={() => setSort({ key, dir: active && sort.dir === 'desc' ? 'asc' : 'desc' })}>
          {label}
          <Icon size={12} aria-hidden />
        </button>
      </th>
    );
  };
  return { sorted, header, sort, setSort };
}

/* ------------------------------------------------------------------ overlays */

function useEscape(onClose) {
  useEffect(() => {
    const onKey = (event) => { if (event.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);
}

/* Keep keyboard focus inside an open dialog or drawer, and put it back afterwards. */
function useFocusTrap(ref) {
  useEffect(() => {
    const previous = document.activeElement;
    const node = ref.current;
    const focusable = () => node?.querySelectorAll('a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])') || [];
    const first = focusable()[0];
    (node?.querySelector('[data-autofocus]') || first)?.focus();
    const onKey = (event) => {
      if (event.key !== 'Tab') return;
      const items = [...focusable()];
      if (!items.length) return;
      const [head, tail] = [items[0], items[items.length - 1]];
      if (event.shiftKey && document.activeElement === head) { event.preventDefault(); tail.focus(); }
      else if (!event.shiftKey && document.activeElement === tail) { event.preventDefault(); head.focus(); }
    };
    node?.addEventListener('keydown', onKey);
    return () => {
      node?.removeEventListener('keydown', onKey);
      if (previous && previous.focus) previous.focus();
    };
  }, [ref]);
}

export function Dialog({ title, onClose, children, footer, className = '' }) {
  const ref = useRef(null);
  const id = useId();
  useEscape(onClose);
  useFocusTrap(ref);
  return (
    <>
      <div className="scrim dialog-scrim" onClick={onClose} aria-hidden />
      <div ref={ref} className={`dialog ${className}`} role="dialog" aria-modal="true" aria-labelledby={title ? id : undefined}>
        {title && (
          <div className="card-head">
            <h2 id={id} className="grow">{title}</h2>
            <Button variant="quiet" icon={X} aria-label="Close" onClick={onClose} />
          </div>
        )}
        <div className="card-body">{children}</div>
        {footer && <div className="card-foot row" style={{ justifyContent: 'flex-end' }}>{footer}</div>}
      </div>
    </>
  );
}

export function Drawer({ title, subtitle, onClose, children, tabs, headExtra, headActions, full = false }) {
  const ref = useRef(null);
  const id = useId();
  useEscape(onClose);
  useFocusTrap(ref);
  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden />
      <aside ref={ref} className={full ? 'drawer drawer-full' : 'drawer'} role="dialog" aria-modal="true" aria-labelledby={id}>
        <div className="drawer-head">
          <div className="grow stack" style={{ gap: 'var(--s-1)' }}>
            {subtitle && <div className="small muted">{subtitle}</div>}
            <h2 id={id}>{title}</h2>
            {headExtra}
          </div>
          {headActions}
          <Button variant="quiet" icon={X} aria-label="Close" onClick={onClose} data-autofocus />
        </div>
        {tabs}
        {children}
      </aside>
    </>
  );
}

export function Menu({ trigger, children, align = 'right', label }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const onDown = (event) => { if (!ref.current?.contains(event.target)) setOpen(false); };
    const onKey = (event) => { if (event.key === 'Escape') setOpen(false); };
    const pathOf = () => window.location.hash.split('?')[0];
    const openedOn = pathOf();
    const onRoute = () => { if (pathOf() !== openedOn) setOpen(false); };   // never follows you to another page
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    window.addEventListener('hashchange', onRoute);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
      window.removeEventListener('hashchange', onRoute);
    };
  }, [open]);
  return (
    <div ref={ref} style={{ position: 'relative' }}>
      {trigger({ open, toggle: () => setOpen((o) => !o), 'aria-expanded': open, 'aria-haspopup': 'menu' })}
      {open && (
        <div className="menu" role="menu" aria-label={label} style={{ [align]: 0, top: 'calc(100% + 6px)' }}
          onClick={(event) => { if (event.target.closest('[data-close]')) setOpen(false); }}>
          {children}
        </div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ toasts */

const ToastContext = createContext(() => {});

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([]);
  const push = useCallback((text) => {
    const id = Math.random().toString(36).slice(2);
    setToasts((now) => [...now, { id, text }]);
    setTimeout(() => setToasts((now) => now.filter((x) => x.id !== id)), 4000);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toast-stack" role="status" aria-live="polite">
        {toasts.map((x) => <div key={x.id} className="toast">{x.text}</div>)}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  return useContext(ToastContext);
}
