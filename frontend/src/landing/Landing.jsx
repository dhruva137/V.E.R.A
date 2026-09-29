/* The V.E.R.A. lab: the page before sign-in.
 *
 * Laid out as an instrument, not a brochure. A walkthrough (chapters on the left, the live figure on the right)
 * tells the story; the other tabs are instrument panels whose controls recompute the real mathematics in
 * scenes.js: Shor's order finding, lattice decoding, ML-KEM decryption, and the shipped detector's
 * Benjamini-Hochberg selection over real p-values from stripped binaries (data.json, from
 * scripts/landing_data.py). Every figure on this page is computed, measured or cited.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowLeft, ArrowRight, RotateCcw } from 'lucide-react';
import Mark from '../components/Mark';
import data from './data.json';
import {
  MLKEM, bhSelect, certify, decrypt, decryptCompute, lattice, latticeCompute, shor, shorCompute,
} from './scenes';
import './landing.css';

const REDUCED = typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

/* A canvas that animates only while visible, reports its frame rate, and restarts when `k` changes. */
function Figure({ draw, state, k, label, status, height = 520 }) {
  const ref = useRef(null);
  const fpsRef = useRef(null);
  const st = useRef(state);
  st.current = state;
  useEffect(() => {
    const canvas = ref.current, ctx = canvas.getContext('2d');
    let raf = 0, start = 0, visible = false, last = 0, frames = 0, rect;
    const size = () => {
      rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      canvas.width = Math.round(rect.width * dpr); canvas.height = Math.round(rect.height * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    size();
    const frame = (now) => {
      if (!start) { start = now; last = now; }
      const t = REDUCED ? 60 : (now - start) / 1000;
      draw(ctx, rect.width, rect.height, t, st.current);
      frames += 1;
      if (now - last > 500) { if (fpsRef.current) fpsRef.current.textContent = `${Math.round((frames * 1000) / (now - last))} fps`; frames = 0; last = now; }
      if (visible && !REDUCED) raf = requestAnimationFrame(frame);
    };
    const io = new IntersectionObserver(([e]) => {
      const was = visible; visible = e.isIntersecting;
      if (visible && !was) { cancelAnimationFrame(raf); raf = requestAnimationFrame(frame); }
      if (!visible) { cancelAnimationFrame(raf); if (fpsRef.current) fpsRef.current.textContent = 'idle'; }
    }, { threshold: 0.2 });
    io.observe(canvas);
    const onResize = () => { size(); draw(ctx, rect.width, rect.height, 60, st.current); };
    window.addEventListener('resize', onResize);
    draw(ctx, rect.width, rect.height, REDUCED ? 60 : 0, st.current);
    return () => { cancelAnimationFrame(raf); io.disconnect(); window.removeEventListener('resize', onResize); };
  }, [draw, k]);
  return (
    <figure className="lab-figure">
      <canvas ref={ref} style={{ height }} role="img" aria-label={label} />
      <figcaption className="lab-status">
        <span>CANVAS 2D</span><span ref={fpsRef}>idle</span>{status.map((s) => <span key={s}>{s}</span>)}
      </figcaption>
    </figure>
  );
}

function Seg({ options, value, onChange, label }) {
  return (
    <div className="lab-seg" role="group" aria-label={label}>
      {options.map(([v, text]) => (
        <button key={String(v)} type="button" className={v === value ? 'on' : ''} aria-pressed={v === value} onClick={() => onChange(v)}>{text}</button>
      ))}
    </div>
  );
}

function Slider({ label, value, min, max, step, onChange, fmt = (v) => v }) {
  return (
    <label className="lab-slider">
      <span className="lab-slider-label">{label}</span>
      <input type="range" min={min} max={max} step={step} value={value} onChange={(e) => onChange(Number(e.target.value))} />
      <span className="lab-slider-value">{fmt(value)}</span>
    </label>
  );
}

const Eq = ({ children }) => <div className="lab-eq">{children}</div>;
const Section = ({ title, children }) => (
  <section className="lab-section"><h3>{title}</h3>{children}</section>
);

/* ---------------------------------------------------------------- instrument panels */
function ShorPanel({ compact }) {
  const [N, setN] = useState(15);
  const coprimes = useMemo(() => {
    const g = (x, y) => (y ? g(y, x % y) : x);
    return Array.from({ length: N - 2 }, (_, i) => i + 2).filter((a) => g(a, N) === 1).slice(0, 6);
  }, [N]);
  const [a, setA] = useState(7);
  const [seed, setSeed] = useState(3);
  const aa = coprimes.includes(a) ? a : coprimes[0];
  const S = useMemo(() => shorCompute(N, aa, seed), [N, aa, seed]);
  const half = S.r % 2 === 0 ? `${aa}^${S.r / 2}` : null;
  const fig = (
    <Figure draw={shor} state={S} k={`${N}-${aa}-${seed}`} height={compact ? 460 : 540}
      label={`Shor's order finding for N = ${N}, a = ${aa}: period ${S.r}, factors ${S.factors?.join(' and ')}`}
      status={[`N ${N}`, `a ${aa}`, `Q ${S.Q}`, `r ${S.r}`, `k ${S.kMeas}`]} />
  );
  if (compact) return fig;
  return (
    <div className="lab-panel">
      <aside className="lab-rail">
        <Section title="Number to factor">
          <p className="lab-note">The same algorithm, at 2,048 bits, breaks RSA. Here N is small enough to compute every amplitude exactly.</p>
          <Seg label="N" value={N} onChange={setN} options={[[15, '15'], [21, '21'], [33, '33'], [35, '35']]} />
        </Section>
        <Section title="Base a">
          <Seg label="a" value={aa} onChange={setA} options={coprimes.map((c) => [c, String(c)])} />
          <button type="button" className="lab-btn" onClick={() => setSeed((s) => s + 1)}><RotateCcw size={14} /> Measure again</button>
        </Section>
        <Section title="What the computer found">
          <Eq>Q = 2<sup>⌈log₂ N²⌉</sup> = {S.Q}</Eq>
          <Eq>read k = {S.kMeas}{S.runs > 1 ? ` (after ${S.runs - 1} run${S.runs > 2 ? 's' : ''} that read 0)` : ''}</Eq>
          <Eq>k / Q = {S.kMeas}/{S.Q} ≈ {S.cf.filter(([, d]) => d > 1 && d < N).map(([n, d]) => `${n}/${d}`).join(' → ') || '—'}</Eq>
          <Eq>{S.viaMultiple ? `${S.viaMultiple} divides r; testing multiples gives r = ${S.rGuess}` : `r = ${S.rGuess ?? S.r}`}</Eq>
          {S.factors ? (
            <Eq><b>{half ? `gcd(${half} ∓ 1, ${N})` : 'gcd'} = {S.factors[0]} × {S.factors[1]}</b></Eq>
          ) : <Eq>{S.why}</Eq>}
        </Section>
        <p className="lab-cite">RSA-2048 in under a week with fewer than a million noisy qubits: Gidney, arXiv 2505.15917 (2025).</p>
      </aside>
      <div className="lab-stage">{fig}</div>
    </div>
  );
}

function LatticePanel({ compact }) {
  const [sigma, setSigma] = useState(0.3);
  const [seed, setSeed] = useState(2);
  const L = useMemo(() => latticeCompute(sigma, seed), [sigma, seed]);
  const fig = (
    <Figure draw={lattice} state={L} k={`${sigma}-${seed}`} height={compact ? 460 : 540}
      label="One lattice, a short basis and a long basis, and Babai rounding of a noisy point with each."
      status={[`σ ${sigma.toFixed(2)}`, `short ${Math.round(L.rateGood * 100)}%`, `long ${Math.round(L.rateBad * 100)}%`, `${L.trials.toLocaleString('en-IN')} trials`]} />
  );
  if (compact) return fig;
  return (
    <div className="lab-panel">
      <aside className="lab-rail">
        <Section title="Noise">
          <p className="lab-note">ML-KEM's public key is t = A·s + e: a lattice point pushed by small noise e. Turn the noise up.</p>
          <Slider label="σ" value={sigma} min={0.1} max={0.6} step={0.01} onChange={setSigma} fmt={(v) => v.toFixed(2)} />
          <button type="button" className="lab-btn" onClick={() => setSeed((s) => s + 1)}><RotateCcw size={14} /> New noisy point</button>
        </Section>
        <Section title="Decode by rounding (Babai)">
          <Eq><span className="dot teal" /> short basis (the secret): <b>{Math.round(L.rateGood * 100)}%</b> correct</Eq>
          <Eq><span className="dot orange" /> long basis (public): <b>{Math.round(L.rateBad * 100)}%</b> correct</Eq>
          <p className="lab-note">Over {L.trials.toLocaleString('en-IN')} noisy points. Both bases span the same lattice; only the short one decodes. ML-KEM-768 plays this game in 768 dimensions, where no known algorithm, classical or quantum, closes the gap.</p>
        </Section>
      </aside>
      <div className="lab-stage">{fig}</div>
    </div>
  );
}

function KemPanel({ compact }) {
  const [name, setName] = useState('ML-KEM-768');
  const D = useMemo(() => decryptCompute(name), [name]);
  const fig = (
    <Figure draw={decrypt} state={D} k={name} height={compact ? 460 : 540}
      label={`${name} decryption: ${D.ok} of ${D.pts.length} bits recovered; worst noise ${D.worst}, under the 832 margin.`}
      status={[name, `q 3329`, `noise σ ${D.sd.toFixed(0)}`, `worst ${D.worst}`, `${D.ok}/${D.pts.length} bits`]} />
  );
  if (compact) return fig;
  return (
    <div className="lab-panel">
      <aside className="lab-rail">
        <Section title="Parameter set (FIPS 203)">
          <Seg label="Parameter set" value={name} onChange={setName} options={Object.keys(MLKEM).map((n) => [n, n.replace('ML-KEM-', '')])} />
        </Section>
        <Section title="Parameters">
          <table className="lab-table"><tbody>
            <tr><td>module rank k</td><td>{D.k}</td></tr>
            <tr><td>η₁ / η₂</td><td>{D.eta1} / {D.eta2}</td></tr>
            <tr><td>d<sub>u</sub> / d<sub>v</sub></td><td>{D.du} / {D.dv}</td></tr>
            <tr><td>noise σ (e·r − s·e₁ + e₂ …)</td><td>{D.sd.toFixed(1)}</td></tr>
            <tr><td>v rounding</td><td>± {D.vr.toFixed(0)}</td></tr>
            <tr><td>margin</td><td>q/4 = 832</td></tr>
            <tr><td>decryption failure (FIPS 203)</td><td>{D.fail}</td></tr>
          </tbody></table>
        </Section>
        <Section title="Measured on a laptop">
          <Eq>ML-KEM-768 encapsulate <b>31 µs</b> · X25519 <b>50 µs</b></Eq>
          <p className="lab-note">OpenSSL 3.5.4, bench/pqc_bench.py. Post-quantum key exchange costs no speed; it costs knowing where every key is.</p>
        </Section>
      </aside>
      <div className="lab-stage">{fig}</div>
    </div>
  );
}

const CRYPTO_OP = /^(xor|eor|rol|ror|shl|shr|lsl|lsr|add|movabs|movk|imul|mul)\b/;
const ascii = (hex) => hex.replace(/^0x/, '').match(/.{2}/g).map((b) => String.fromCharCode(parseInt(b, 16))).join('');

function DetectorPanel({ compact }) {
  const [which, setWhich] = useState(0);
  const [alpha, setAlpha] = useState(0.1);
  const run = data.runs[which];
  const cal = data.calibration[run.arch];
  const S = useMemo(() => ({ cal, run, alpha }), [cal, run, alpha]);
  const sel = useMemo(() => bhSelect(run.p, alpha), [run, alpha]);
  const label = { siphash_x86_64: 'SipHash · x86-64', siphash_aarch64: 'SipHash · AArch64', xxhash_x86_64: 'xxHash · x86-64', lz4_x86_64: 'LZ4 · x86-64' };
  const fig = (
    <Figure draw={certify} state={S} k={`${which}`} height={compact ? 460 : 540}
      label={`Detector on ${label[run.binary]}: ${sel.count} of ${run.functions} functions certified at alpha ${alpha}.`}
      status={[label[run.binary], `${run.functions} functions`, `α ${alpha.toFixed(2)}`, `${sel.count} certified`]} />
  );
  if (compact) return fig;
  return (
    <div className="lab-panel">
      <aside className="lab-rail">
        <Section title="Stripped binary">
          <p className="lab-note">Statically linked, symbols removed: nothing names the crypto. Two contain SipHash; xxHash and LZ4 are look-alike negatives.</p>
          <div className="lab-list">
            {data.runs.map((r, i) => (
              <button key={r.binary} type="button" className={i === which ? 'on' : ''} onClick={() => setWhich(i)}>
                <span>{label[r.binary]}</span><span className="mono">{bhSelect(r.p, alpha).count}/{r.functions}</span>
              </button>
            ))}
          </div>
        </Section>
        <Section title="False-alarm cap">
          <Slider label="α" value={alpha} min={0.01} max={0.3} step={0.01} onChange={setAlpha} fmt={(v) => v.toFixed(2)} />
          <p className="lab-note">Benjamini-Hochberg keeps only functions under the line α·k/m. On average at most α of what it reports is wrong, whatever the binary.</p>
        </Section>
        <Section title="Top-ranked function, disassembled">
          <ol className="lab-asm">
            {run.top_function.insns.slice(0, 16).map((ins, i) => {
              const c = ins.match(/, (0x[0-9a-f]{16})$/);
              return (
                <li key={`${i}-${ins}`} className={CRYPTO_OP.test(ins) ? 'hot' : ''}>
                  {ins}{c && <em> "{ascii(c[1])}"</em>}
                </li>
              );
            })}
          </ol>
        </Section>
      </aside>
      <div className="lab-stage">{fig}</div>
    </div>
  );
}

const CLOCK = [
  ['2026', 'V.E.R.A.: certified core built', 'discover · certify · plan · prove'],
  ['2027', 'DST: CII inventory and quantum-risk assessment', 'one scan, ranked by months of slack'],
  ['FY 2027–28', 'Vendor CBOMs mandatory in procurement', 'CycloneDX 1.7, checked against CERT-In Table 9'],
  ['2029', 'Critical infrastructure quantum-resilient', 'a PQC plan per asset, with an owner'],
  ['2030 → 2035', 'NIST deprecates, then disallows, RSA and ECC', 'FIPS 203 / 204 / 205 targets'],
];
function ClockPanel() {
  return (
    <div className="lab-clock">
      <ol>
        {CLOCK.map(([y, what, how], i) => (
          <li key={y} style={{ '--i': i }}><span className="y">{y}</span><span className="w">{what}</span><span className="h">{how}</span></li>
        ))}
      </ol>
      <p className="lab-cite">DST Task Force, Implementation of Quantum Safe Ecosystem in India (Feb 2026) · CERT-In CBOM guidelines v2.0 · NIST IR 8547.</p>
    </div>
  );
}

/* ---------------------------------------------------------------- walkthrough */
const CHAPTERS = [
  { id: 'intro', title: 'Introduction', body: (
    <>
      <p>Every bank, grid and telecom network runs on cryptography it cannot fully list. V.E.R.A. finds all of it, in source,
        packages, containers, HSMs, cloud and inside stripped binaries, and proves how often it is wrong.</p>
      <p>This walkthrough shows the real mathematics behind that, one step at a time. Every figure is computed live or
        measured on the shipped product.</p>
    </>
  ), view: 'detector' },
  { id: 'threat', title: 'The threat', body: (
    <>
      <p>Shor's algorithm turns factoring into finding a period. Each cell is a value of <code>7<sup>x</sup> mod 15</code>. Measuring
        collapses the register onto cells a period apart; the quantum Fourier transform turns that spacing into sharp peaks.</p>
      <p>Traffic recorded today can be decrypted once the machine exists: <b>harvest now, decrypt later</b>.</p>
    </>
  ), view: 'shor' },
  { id: 'lattice', title: 'The replacement', body: (
    <>
      <p>ML-KEM hides a secret in a lattice behind noise. The short basis (teal) decodes a noisy point; the long public basis
        (orange), spanning the same lattice, lands on the wrong point.</p>
      <p>That gap, at 768 dimensions, is what no known algorithm closes.</p>
    </>
  ), view: 'lattice' },
  { id: 'mlkem', title: 'Why it still works', body: (
    <>
      <p>Each message bit sits at 0 or 1665 on a circle of 3,329 values. Encryption adds noise; the key holder decodes by half
        circle. With ML-KEM-768's parameters the noise never reaches the 832 margin.</p>
    </>
  ), view: 'kem' },
  { id: 'detector', title: 'Reading the black box', body: (
    <>
      <p>A stripped SipHash binary: no names, no imports. V.E.R.A. scores every function, compares each score with thousands of
        known non-crypto functions, and certifies only what clears the Benjamini-Hochberg line.</p>
      <p>The top function loads <code>0x7465646279746573</code> = "tedbytes": SipHash's own constant, read from machine code.</p>
    </>
  ), view: 'detector' },
  { id: 'clock', title: "India's clock", body: (
    <>
      <p>The deadline is set. V.E.R.A. turns each asset into months of slack against the milestone that binds it, with the fix,
        its cost and its owner.</p>
    </>
  ), view: 'clock' },
];

function Walkthrough({ onEnter }) {
  const [i, setI] = useState(0);
  const ch = CHAPTERS[i];
  useEffect(() => {
    const onKey = (e) => {
      if (e.target.closest?.('input, textarea')) return;
      if (e.key === ' ' || e.key === 'ArrowRight') { e.preventDefault(); setI((v) => Math.min(CHAPTERS.length - 1, v + 1)); }
      if (e.key === 'ArrowLeft') setI((v) => Math.max(0, v - 1));
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  const view = { shor: <ShorPanel compact />, lattice: <LatticePanel compact />, kem: <KemPanel compact />, detector: <DetectorPanel compact />, clock: <ClockPanel /> }[ch.view];
  return (
    <div className="lab-walk">
      <aside className="lab-story">
        <div className="lab-chapnav">
          <button type="button" className="lab-icon" aria-label="Previous chapter" disabled={i === 0} onClick={() => setI(i - 1)}><ArrowLeft size={16} /></button>
          <span>Chapter {i + 1} of {CHAPTERS.length}: {ch.title}</span>
          <button type="button" className="lab-icon" aria-label="Next chapter" disabled={i === CHAPTERS.length - 1} onClick={() => setI(i + 1)}><ArrowRight size={16} /></button>
        </div>
        <ol className="lab-toc">
          {CHAPTERS.map((c, j) => (
            <li key={c.id}><button type="button" className={j === i ? 'on' : ''} onClick={() => setI(j)}><span className="mono">{String(j + 1).padStart(2, '0')}</span>{c.title}</button></li>
          ))}
        </ol>
        <div className="lab-body" key={ch.id}>{ch.body}</div>
        <div className="lab-progress"><span style={{ width: `${((i + 1) / CHAPTERS.length) * 100}%` }} /></div>
        <div className="lab-actions">
          {i < CHAPTERS.length - 1
            ? <button type="button" className="lab-btn primary" onClick={() => setI(i + 1)}>Continue <ArrowRight size={16} /></button>
            : <button type="button" className="lab-btn primary" onClick={onEnter}>Enter V.E.R.A. <ArrowRight size={16} /></button>}
          <span className="lab-hint">Press Space to continue</span>
        </div>
      </aside>
      <div className="lab-stage">{view}</div>
    </div>
  );
}

const TABS = [['walk', 'Walkthrough'], ['shor', 'Shor'], ['lattice', 'Lattice'], ['kem', 'ML-KEM'], ['detector', 'Detector'], ['clock', "India's clock"]];

export default function Landing({ onEnter }) {
  const [tab, setTab] = useState('walk');
  return (
    <div className="lab">
      <header className="lab-top">
        <div className="lab-brand"><Mark size={28} /><span className="lab-word">V.E.R.A.</span><span className="lab-sub">Lab</span></div>
        <nav className="lab-tabs" aria-label="Views">
          {TABS.map(([id, text]) => (
            <button key={id} type="button" className={tab === id ? 'on' : ''} aria-current={tab === id ? 'page' : undefined} onClick={() => setTab(id)}>{text}</button>
          ))}
        </nav>
        <button type="button" className="lab-enter" onClick={onEnter}>Enter V.E.R.A. <ArrowRight size={16} /></button>
      </header>
      <div className="lab-head">
        <h1>India's first <em>certified</em> crypto-discovery engine</h1>
        <p>Verified Enumeration of Risky Algorithms. Built for SIH 2026, problem statement SIH26164 (NTRO). Everything below is live
          mathematics or a measurement of the shipped product.</p>
      </div>
      <main className="lab-main">
        {tab === 'walk' && <Walkthrough onEnter={onEnter} />}
        {tab === 'shor' && <ShorPanel />}
        {tab === 'lattice' && <LatticePanel />}
        {tab === 'kem' && <KemPanel />}
        {tab === 'detector' && <DetectorPanel />}
        {tab === 'clock' && <ClockPanel />}
      </main>
      <footer className="lab-foot">
        <span>Runs on this machine · nothing on this page is fetched from the internet</span>
        <span className="mono">github.com/dhruva137/V.E.R.A · github.com/dhruva137/indicrypt-bench</span>
      </footer>
    </div>
  );
}
