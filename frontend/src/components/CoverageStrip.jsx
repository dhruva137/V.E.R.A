/* The problem statement's own words, each lit only by evidence from this scan.
 *
 * PS 26164 asks for algorithms, keys, certificates, protocols, libraries, hardware modules and cloud services,
 * across source code, binaries, libraries and container images. Each term maps to the collectors that can see
 * it; a term is "read" when at least one of those collectors ran and returned findings in this scan, "ran" when
 * it ran and found nothing, and "not scanned" otherwise. No per-term count is shown: several terms share a
 * collector (the key-manager collector sees keys, HSMs and cloud KMS), so a count would overstate; the tooltip
 * names the collectors and their total instead.
 */
import { Check, Minus } from 'lucide-react';

const TERMS = [
  { label: 'Algorithms', from: ['source', 'dependency', 'binary', 'config'] },
  { label: 'Keys', from: ['keystore', 'secret', 'vault'] },
  { label: 'Certificates', from: ['keystore', 'tls', 'binary', 'vault'] },
  { label: 'Protocols', from: ['config', 'tls', 'ssh', 'capture'] },
  { label: 'Libraries', from: ['dependency', 'binary', 'container'] },
  { label: 'Hardware modules', from: ['vault'] },
  { label: 'Cloud services', from: ['vault'] },
  { label: 'Source code', from: ['source'] },
  { label: 'Binaries', from: ['binary'] },
  { label: 'Container images', from: ['container'] },
];

export default function CoverageStrip({ surfaces }) {
  const by = Object.fromEntries((surfaces || []).map((s) => [s.collector, s]));
  const state = (t) => {
    const hits = t.from.map((c) => by[c]).filter(Boolean);
    const findings = hits.reduce((n, s) => n + (s.findings || 0), 0);
    if (findings > 0) return { key: 'read', findings };
    if (hits.some((s) => s.runs > 0)) return { key: 'ran', findings: 0 };
    return { key: 'none', findings: 0 };
  };
  return (
    <section className="coverage-strip" aria-label="Problem-statement coverage in this scan">
      <span className="coverage-title">PS 26164 coverage</span>
      <ul>
        {TERMS.map((t) => {
          const s = state(t);
          return (
            <li key={t.label} className={`cov cov-${s.key}`}
              title={`${t.label}: ${s.key === 'read' ? `${s.findings} findings` : s.key === 'ran' ? 'scanned, nothing found' : 'not scanned'} (from ${t.from.join(', ')})`}>
              {s.key === 'read' ? <Check size={13} aria-hidden /> : <Minus size={13} aria-hidden />}
              <span>{t.label}</span>
              {s.key !== 'read' && <span className="cov-n">{s.key === 'ran' ? 'nothing found' : 'not scanned'}</span>}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
