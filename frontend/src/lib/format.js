/* Numbers, money and dates as an Indian reader expects them.
 *
 * Counts use Indian digit grouping (1,23,456). Money is in rupees with lakh
 * and crore, the units budgets here are written in. Dates are unambiguous
 * (25 Sep 2026), never 09/25.
 */

const count = new Intl.NumberFormat('en-IN');
const oneDecimal = new Intl.NumberFormat('en-IN', { maximumFractionDigits: 1, minimumFractionDigits: 0 });

export const fmt = (n) => (n === null || n === undefined || Number.isNaN(n) ? '—' : count.format(n));
export const fmt1 = (n) => (n === null || n === undefined || Number.isNaN(n) ? '—' : oneDecimal.format(n));
export const pct = (n) => (n === null || n === undefined ? '—' : `${oneDecimal.format(n)}%`);

export function money(amount, currency = 'INR') {
  if (amount === null || amount === undefined) return '—';
  if (currency !== 'INR') return `${currency} ${count.format(Math.round(amount))}`;
  const abs = Math.abs(amount);
  if (abs >= 1e7) return `₹${oneDecimal.format(amount / 1e7)} crore`;
  if (abs >= 1e5) return `₹${oneDecimal.format(amount / 1e5)} lakh`;
  return `₹${count.format(Math.round(amount))}`;
}

const dateFmt = new Intl.DateTimeFormat('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
const dateTimeFmt = new Intl.DateTimeFormat('en-IN', {
  day: 'numeric', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
});

export function date(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : dateFmt.format(d);
}

export function dateTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? String(value) : dateTimeFmt.format(d);
}

export function ago(value) {
  if (!value) return '';
  const d = new Date(value);
  const seconds = (Date.now() - d.getTime()) / 1000;
  if (Number.isNaN(seconds)) return '';
  if (seconds < 60) return 'just now';
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}

/* "26.8 months late" / "9.2 months to spare". */
export function slack(months) {
  if (months === null || months === undefined) return '—';
  const m = Math.abs(months);
  return months < 0 ? `${oneDecimal.format(m)} months late` : `${oneDecimal.format(m)} months to spare`;
}

export function years(value) {
  if (value === null || value === undefined) return '—';
  return `${oneDecimal.format(value)} yr`;
}

export function plural(n, one, many = `${one}s`) {
  return `${fmt(n)} ${n === 1 ? one : many}`;
}

/* The last part of a path, which is the part a person recognises. */
export function shortPath(location) {
  if (!location) return '';
  const clean = String(location).replace(/\\/g, '/');
  const parts = clean.split('/');
  return parts.length > 3 ? `…/${parts.slice(-3).join('/')}` : clean;
}
