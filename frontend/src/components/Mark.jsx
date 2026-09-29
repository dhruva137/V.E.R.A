/* The V.E.R.A. mark: a V that is also a verification tick, inside a segmented ring. V.E.R.A. is
 * Verified Enumeration of Risky Algorithms; the tick is the certified bound every finding carries. */
export default function Mark({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden focusable="false">
      <rect width="64" height="64" rx="14" fill="var(--primary)" />
      <circle cx="32" cy="32" r="21" fill="none" stroke="#fff" strokeWidth="3" strokeDasharray="10 3.2" opacity="0.9" />
      <path d="M21 25 L30 43 L43 21" fill="none" stroke="#fff" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
