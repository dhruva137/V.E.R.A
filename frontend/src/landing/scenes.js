/* The mathematics and the canvas renderers behind the V.E.R.A. lab (landing page).
 *
 * Nothing here is decoration. Each renderer draws a real computation:
 *   shor      order finding for a^x mod N over the Q = 2^ceil(log2 N^2) register Shor prescribes, the exact
 *             measurement-conditioned QFT spectrum, and continued fractions back to r and the factors
 *   lattice   one 2-D lattice under a short and a long basis; Babai rounding of the same noisy target with each
 *   decrypt   ML-KEM decryption on Z_3329 with the noise of the chosen FIPS 203 parameter set
 *   certify   the shipped detector's calibration scores and a Benjamini-Hochberg selection at a live alpha
 * Renderers are draw(ctx, w, h, t, s): t is seconds since the view (re)started, s the view's state.
 */

export const PAL = {
  paper: '#faf8f5', ink: '#141414', mute: '#6b6b6b', hair: 'rgba(20,20,20,0.14)', faint: 'rgba(20,20,20,0.06)',
  red: '#c8102e', orange: '#e0632a', indigo: '#3f3d8f', teal: '#0f766e', gold: '#b7791f', green: '#15803d',
};

const clamp = (x, a = 0, b = 1) => Math.max(a, Math.min(b, x));
export const ease = (x) => { const c = clamp(x); return c < 0.5 ? 4 * c * c * c : 1 - (-2 * c + 2) ** 3 / 2; };
const mix = (a, b, t) => a + (b - a) * t;
/* warm sequential ramp, paper → orange → indigo (the palette of Epoch's wave surfaces) */
export function ramp(t) {
  const stops = [[250, 222, 196], [224, 99, 42], [63, 61, 143]];
  const u = clamp(t) * 2, i = Math.min(1, Math.floor(u)), f = u - i;
  const [a, b] = [stops[i], stops[i + 1]];
  return `rgb(${Math.round(mix(a[0], b[0], f))},${Math.round(mix(a[1], b[1], f))},${Math.round(mix(a[2], b[2], f))})`;
}

export function mulberry(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const gaussFrom = (rnd) => () => Math.sqrt(-2 * Math.log(rnd() + 1e-12)) * Math.cos(2 * Math.PI * rnd());
const mono = (px, w = 400) => `${w} ${px}px "JetBrains Mono", ui-monospace, monospace`;

/* ================================================================ Shor */
const gcd = (a, b) => { a = Math.abs(a); b = Math.abs(b); while (b) [a, b] = [b, a % b]; return a; };
const modpow = (b, e, m) => { let r = 1, x = b % m; while (e > 0) { if (e & 1) r = (r * x) % m; x = (x * x) % m; e = Math.floor(e / 2); } return r; };

/* continued-fraction convergents of k/Q; the first denominator d < N with a^d ≡ 1 is the period */
function convergents(k, Q) {
  const out = []; let h0 = 0, h1 = 1, k0 = 1, k1 = 0, n = k, d = Q;
  while (d) {
    const a = Math.floor(n / d);
    [h0, h1] = [h1, a * h1 + h0]; [k0, k1] = [k1, a * k1 + k0];
    out.push([h1, k1]); [n, d] = [d, n - a * d];
  }
  return out;
}

export function shorCompute(N, a, seed = 3) {
  const common = gcd(a, N);
  const Q = 2 ** Math.ceil(Math.log2(N * N));
  const f = new Array(Q);
  let v = 1;
  for (let x = 0; x < Q; x += 1) { f[x] = v; v = (v * a) % N; }
  let r = 1;
  if (common === 1) while (modpow(a, r, N) !== 1) r += 1;
  const rnd = mulberry(seed);
  const x0 = Math.floor(rnd() * Q), f0 = f[x0];
  const xs = []; for (let x = 0; x < Q; x += 1) if (f[x] === f0) xs.push(x);
  const P = new Float64Array(Q);
  for (let k = 0; k < Q; k += 1) {
    let re = 0, im = 0;
    for (const x of xs) { const th = (2 * Math.PI * x * k) / Q; re += Math.cos(th); im += Math.sin(th); }
    P[k] = (re * re + im * im) / (xs.length * Q);
  }
  // Read k from P; k = 0 carries no information about r, so a run that reads it is simply repeated.
  let kMeas = 0, runs = 0;
  while (kMeas === 0 && runs < 50) {
    runs += 1;
    let u = rnd();
    for (let k = 0; k < Q; k += 1) { u -= P[k]; if (u <= 0) { kMeas = k; break; } }
  }
  const cf = convergents(kMeas, Q);
  let hit = cf.find(([, d]) => d > 0 && d < N && modpow(a, d, N) === 1), viaMultiple = null;
  if (!hit) {
    // A convergent can give a divisor of r (when s and r share a factor); Shor then tests its small multiples.
    for (const [, d] of cf) {
      if (d <= 1 || d >= N) continue;
      for (let j = 2; d * j < N; j += 1) if (modpow(a, d * j, N) === 1) { hit = [0, d * j]; viaMultiple = d; break; }
      if (hit) break;
    }
  }
  const half = common === 1 && r % 2 === 0 ? modpow(a, r / 2, N) : null;
  const good = half !== null && half !== N - 1;
  return {
    N, a, Q, f, r, f0, xs, P, kMeas, runs, rGuess: hit ? hit[1] : null, viaMultiple, cf,
    factors: common > 1 ? [common, N / common] : good ? [gcd(half - 1, N), gcd(half + 1, N)] : null,
    why: common > 1 ? `gcd(${a}, ${N}) = ${common}: a lucky guess, no quantum step needed`
      : r % 2 ? `r = ${r} is odd: choose another a` : half === N - 1 ? `a^(r/2) ≡ −1 (mod N): choose another a` : '',
  };
}

export function shor(ctx, w, h, t, S) {
  ctx.clearRect(0, 0, w, h);
  const cols = 32, shown = Math.min(S.Q, 256), rows = shown / cols;
  const gridH = h * 0.42;
  const cell = Math.min((w - 40) / cols, gridH / rows);
  const gx = (w - cell * cols) / 2, gy = 30;
  ctx.font = mono(11); ctx.fillStyle = PAL.mute; ctx.textAlign = 'left';
  ctx.fillText(`register x = 0 … ${shown - 1}${S.Q > shown ? ` of Q = ${S.Q}` : ` (Q = ${S.Q})`} · colour = ${S.a}^x mod ${S.N}`, gx, 18);
  const fill = ease(t / 2.2);
  for (let x = 0; x < shown; x += 1) {
    if (x / shown > fill) break;
    ctx.fillStyle = ramp(S.f[x] / (S.N - 1));
    ctx.fillRect(gx + (x % cols) * cell + 1, gy + Math.floor(x / cols) * cell + 1, cell - 2, cell - 2);
  }
  const meas = clamp((t - 2.4) / 0.8);
  if (meas > 0) {
    ctx.strokeStyle = PAL.red; ctx.lineWidth = 1.6; ctx.globalAlpha = meas;
    for (let x = 0; x < shown; x += 1) {
      if (S.f[x] !== S.f0) continue;
      ctx.strokeRect(gx + (x % cols) * cell + 0.8, gy + Math.floor(x / cols) * cell + 0.8, cell - 1.6, cell - 1.6);
    }
    ctx.globalAlpha = 1; ctx.fillStyle = PAL.red;
    ctx.fillText(`measure f(x) → ${S.f0}: x collapses onto the red cells, r = ${S.r} apart`, gx, gy + rows * cell + 16);
  }
  const spec = ease((t - 3.4) / 1.6);
  if (spec > 0) {
    const top = gy + rows * cell + 36, base = h - 20, H = base - top, W = cols * cell;
    let pmax = 0; for (let k = 0; k < S.Q; k += 1) pmax = Math.max(pmax, S.P[k]);
    ctx.fillStyle = PAL.mute; ctx.fillText('after the quantum Fourier transform: probability of reading k', gx, top - 4);
    ctx.strokeStyle = PAL.hair; ctx.beginPath(); ctx.moveTo(gx, base); ctx.lineTo(gx + W, base); ctx.stroke();
    const lim = Math.floor(S.Q * spec);
    ctx.beginPath(); ctx.moveTo(gx, base);
    for (let k = 0; k < lim; k += 1) ctx.lineTo(gx + (k / S.Q) * W, base - (S.P[k] / pmax) * (H - 8));
    ctx.lineTo(gx + (lim / S.Q) * W, base); ctx.closePath();
    const g = ctx.createLinearGradient(0, top, 0, base);
    g.addColorStop(0, 'rgba(63,61,143,0.9)'); g.addColorStop(1, 'rgba(224,99,42,0.35)');
    ctx.fillStyle = g; ctx.fill();
    if (spec >= 1) {
      const kx = gx + (S.kMeas / S.Q) * W, right = kx < w * 0.6;
      ctx.strokeStyle = PAL.red; ctx.setLineDash([3, 3]); ctx.beginPath(); ctx.moveTo(kx, top); ctx.lineTo(kx, base); ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle = PAL.red; ctx.textAlign = right ? 'left' : 'right';
      ctx.fillText(`read k = ${S.kMeas}`, kx + (right ? 5 : -5), top + 12); ctx.textAlign = 'left';
    }
  }
}

/* ================================================================ lattice + Babai */
export const LATTICE_GOOD = [[1, 0.18], [-0.22, 1]];
const U = [[5, 3], [3, 2]]; // det 1: a long basis for the same lattice
export const LATTICE_BAD = [
  [U[0][0] * LATTICE_GOOD[0][0] + U[0][1] * LATTICE_GOOD[1][0], U[0][0] * LATTICE_GOOD[0][1] + U[0][1] * LATTICE_GOOD[1][1]],
  [U[1][0] * LATTICE_GOOD[0][0] + U[1][1] * LATTICE_GOOD[1][0], U[1][0] * LATTICE_GOOD[0][1] + U[1][1] * LATTICE_GOOD[1][1]],
];
function babai(B, p) {
  const det = B[0][0] * B[1][1] - B[1][0] * B[0][1];
  const c0 = Math.round((p[0] * B[1][1] - p[1] * B[1][0]) / det);
  const c1 = Math.round((B[0][0] * p[1] - B[0][1] * p[0]) / det);
  return [c0 * B[0][0] + c1 * B[1][0], c0 * B[0][1] + c1 * B[1][1]];
}
const same = (a, b) => Math.abs(a[0] - b[0]) < 1e-9 && Math.abs(a[1] - b[1]) < 1e-9;

export function latticeCompute(sigma, seed = 2) {
  const g = gaussFrom(mulberry(seed));
  const lp = [2 * LATTICE_GOOD[0][0] + LATTICE_GOOD[1][0], 2 * LATTICE_GOOD[0][1] + LATTICE_GOOD[1][1]];
  const target = [lp[0] + sigma * g(), lp[1] + sigma * g()];
  const cloud = Array.from({ length: 220 }, () => [lp[0] + sigma * g(), lp[1] + sigma * g()]);
  const trials = 3000, tg = gaussFrom(mulberry(99));
  let okG = 0, okB = 0;
  for (let i = 0; i < trials; i += 1) {
    const p = [lp[0] + sigma * tg(), lp[1] + sigma * tg()];
    if (same(babai(LATTICE_GOOD, p), lp)) okG += 1;
    if (same(babai(LATTICE_BAD, p), lp)) okB += 1;
  }
  const viaGood = babai(LATTICE_GOOD, target), viaBad = babai(LATTICE_BAD, target);
  return { sigma, lp, target, cloud, viaGood, viaBad, goodOk: same(viaGood, lp), badOk: same(viaBad, lp),
    rateGood: okG / trials, rateBad: okB / trials, trials };
}

export function lattice(ctx, w, h, t, L) {
  ctx.clearRect(0, 0, w, h);
  const sc = Math.min(w, h) / 7.2, ox = w * 0.4, oy = h * 0.64;
  const P = ([x, y]) => [ox + x * sc, oy - y * sc];
  ctx.fillStyle = 'rgba(20,20,20,0.35)';
  for (let i = -9; i <= 9; i += 1) {
    for (let j = -9; j <= 9; j += 1) {
      const [x, y] = P([i * LATTICE_GOOD[0][0] + j * LATTICE_GOOD[1][0], i * LATTICE_GOOD[0][1] + j * LATTICE_GOOD[1][1]]);
      if (x > -6 && x < w + 6 && y > -6 && y < h + 6) ctx.fillRect(x - 1.5, y - 1.5, 3, 3);
    }
  }
  const vec = (v, col, a) => {
    const [x0, y0] = P([0, 0]), [x1, y1] = P(v), an = Math.atan2(y1 - y0, x1 - x0);
    ctx.globalAlpha = a; ctx.strokeStyle = col; ctx.fillStyle = col; ctx.lineWidth = 2.4;
    ctx.beginPath(); ctx.moveTo(x0, y0); ctx.lineTo(x1, y1); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x1 - 9 * Math.cos(an - 0.4), y1 - 9 * Math.sin(an - 0.4));
    ctx.lineTo(x1 - 9 * Math.cos(an + 0.4), y1 - 9 * Math.sin(an + 0.4)); ctx.fill(); ctx.globalAlpha = 1;
  };
  LATTICE_GOOD.forEach((v) => vec(v, PAL.teal, clamp(t / 1)));
  LATTICE_BAD.forEach((v) => vec(v, PAL.orange, clamp((t - 1) / 1)));
  const a3 = clamp((t - 2) / 0.8);
  if (a3 > 0) {
    ctx.globalAlpha = a3 * 0.55; ctx.fillStyle = PAL.indigo;
    for (const c of L.cloud) { const [x, y] = P(c); ctx.fillRect(x - 0.8, y - 0.8, 1.6, 1.6); }
    const [tx, ty] = P(L.target); ctx.globalAlpha = a3;
    ctx.fillStyle = PAL.red; ctx.beginPath(); ctx.arc(tx, ty, 4.5, 0, 7); ctx.fill(); ctx.globalAlpha = 1;
  }
  const ring = (pt, col, a, label, dy) => {
    if (a <= 0) return;
    const [x, y] = P(pt); ctx.globalAlpha = a; ctx.strokeStyle = col; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.arc(x, y, 10, 0, 7); ctx.stroke();
    ctx.font = mono(11); ctx.fillStyle = col;
    const right = x + 14 + ctx.measureText(label).width < w - 4;
    ctx.textAlign = right ? 'left' : 'right'; ctx.fillText(label, right ? x + 14 : x - 14, y + dy);
    ctx.textAlign = 'left'; ctx.globalAlpha = 1;
  };
  ring(L.viaGood, PAL.teal, clamp((t - 3) / 0.8), L.goodOk ? 'short basis → the secret point' : 'short basis → wrong point', -4);
  ring(L.viaBad, PAL.orange, clamp((t - 4) / 0.8), L.badOk ? 'long basis → the secret point' : 'long basis → wrong point', 14);
}

/* ================================================================ ML-KEM decryption */
export const MLKEM = {
  'ML-KEM-512': { k: 2, eta1: 3, eta2: 2, du: 10, dv: 4, fail: '2⁻¹³⁸·⁸' },
  'ML-KEM-768': { k: 3, eta1: 2, eta2: 2, du: 10, dv: 4, fail: '2⁻¹⁶⁴·⁸' },
  'ML-KEM-1024': { k: 4, eta1: 2, eta2: 2, du: 11, dv: 5, fail: '2⁻¹⁷⁴·⁸' },
};
export const Q_KYBER = 3329;

/* Per-coefficient decryption noise e·r − s·e1 + e2 + s·(u rounding), CBD(η) having variance η/2: a normal
 * approximation of that sum, plus the v rounding sampled exactly (uniform within ±q/2^(dv+1)). */
export function decryptCompute(name, seed = 29) {
  const p = MLKEM[name], n = 256, q = Q_KYBER;
  const vs = p.eta1 / 2, v2 = p.eta2 / 2, vdu = (q / 2 ** p.du) ** 2 / 12;
  const sd = Math.sqrt(p.k * n * (vs * vs + vs * v2) + v2 + p.k * n * vs * vdu);
  const vr = q / 2 ** (p.dv + 1);
  const rnd = mulberry(seed), g = gaussFrom(rnd), half = Math.round(q / 2);
  const pts = Array.from({ length: 96 }, () => {
    const bit = rnd() < 0.5 ? 0 : 1, noise = sd * g() + (rnd() * 2 - 1) * vr;
    return { bit, noise, v: (((bit * half + noise) % q) + q) % q };
  });
  const decode = (v) => (Math.min(v, q - v) < q / 4 ? 0 : 1);
  return { name, ...p, sd, vr, pts, q, half,
    ok: pts.filter((x) => decode(x.v) === x.bit).length,
    worst: Math.round(Math.max(...pts.map((x) => Math.abs(x.noise)))) };
}

export function decrypt(ctx, w, h, t, D) {
  ctx.clearRect(0, 0, w, h);
  const cx = w / 2, cy = h / 2 + 6, R = Math.min(w, h) * 0.34, q = D.q;
  const ang = (v) => -Math.PI / 2 + (2 * Math.PI * v) / q;
  ctx.lineWidth = 22;
  ctx.strokeStyle = 'rgba(15,118,110,0.13)'; ctx.beginPath(); ctx.arc(cx, cy, R, ang(-q / 4), ang(q / 4)); ctx.stroke();
  ctx.strokeStyle = 'rgba(224,99,42,0.13)'; ctx.beginPath(); ctx.arc(cx, cy, R, ang(q / 4), ang((3 * q) / 4)); ctx.stroke();
  ctx.lineWidth = 1; ctx.strokeStyle = PAL.hair; ctx.setLineDash([3, 4]);
  ctx.beginPath(); ctx.arc(cx, cy, R, 0, 7); ctx.stroke();
  [q / 4, (3 * q) / 4].forEach((v) => {
    const a = ang(v);
    ctx.beginPath(); ctx.moveTo(cx + (R - 26) * Math.cos(a), cy + (R - 26) * Math.sin(a)); ctx.lineTo(cx + (R + 26) * Math.cos(a), cy + (R + 26) * Math.sin(a)); ctx.stroke();
  });
  ctx.setLineDash([]);
  ctx.font = mono(11); ctx.textAlign = 'center';
  ctx.fillStyle = PAL.teal; ctx.fillText('0 → bit 0', cx, cy - R - 20);
  ctx.fillStyle = PAL.orange; ctx.fillText(`${D.half} → bit 1`, cx, cy + R + 30);
  const noise = ease((t - 0.8) / 1.8);
  D.pts.forEach((p, i) => {
    const a = ang(p.bit * D.half + p.noise * noise), rr = R + ((i % 7) - 3) * 3.2;
    ctx.globalAlpha = clamp(t * 3 - i * 0.015);
    ctx.fillStyle = p.bit ? PAL.orange : PAL.teal;
    ctx.beginPath(); ctx.arc(cx + rr * Math.cos(a), cy + rr * Math.sin(a), 3, 0, 7); ctx.fill();
  });
  ctx.globalAlpha = clamp((t - 2.8) / 0.6);
  ctx.fillStyle = PAL.ink; ctx.font = '600 30px "Fraunces Variable", Georgia, serif';
  ctx.fillText(`${D.ok} / ${D.pts.length}`, cx, cy - 2);
  ctx.font = mono(11); ctx.fillStyle = PAL.mute;
  ctx.fillText('bits recovered', cx, cy + 18);
  ctx.fillText(`worst noise ${D.worst} < q/4 = 832`, cx, cy + 36);
  ctx.globalAlpha = 1;
}

/* ================================================================ certification */
export function bhSelect(p, alpha) {
  const m = p.length, idx = p.map((_, i) => i).sort((a, b) => p[a] - p[b]);
  let kmax = 0;
  idx.forEach((i, r) => { if (p[i] <= (alpha * (r + 1)) / m) kmax = r + 1; });
  const sel = new Array(m).fill(false);
  for (let r = 0; r < kmax; r += 1) sel[idx[r]] = true;
  return { sel, idx, count: kmax };
}

export function certify(ctx, w, h, t, S) {
  ctx.clearRect(0, 0, w, h);
  const { cal, run, alpha } = S, sel = bhSelect(run.p, alpha);
  const L = 40, W = w - L - 14, histTop = 26, histH = h * 0.36;
  const maxC = Math.max(...cal.counts), bw = W / cal.counts.length, grow = ease(t / 1.4);
  ctx.font = mono(11); ctx.fillStyle = PAL.mute; ctx.textAlign = 'left';
  ctx.fillText(`calibration: ${cal.n.toLocaleString('en-IN')} known non-crypto ${run.arch} functions · detector score`, L, 16);
  cal.counts.forEach((c, i) => {
    const bh = (c / maxC) * (histH - 6) * grow;
    ctx.fillStyle = ramp(0.25 + (i / cal.counts.length) * 0.6);
    ctx.fillRect(L + i * bw + 0.5, histTop + histH - bh, bw - 1, bh);
  });
  ctx.strokeStyle = PAL.hair; ctx.beginPath(); ctx.moveTo(L, histTop + histH); ctx.lineTo(L + W, histTop + histH); ctx.stroke();
  ctx.fillStyle = PAL.mute;
  [['0', 0], ['0.5', 0.5], ['1', 1]].forEach(([lab, x]) => {
    ctx.textAlign = x === 1 ? 'right' : x ? 'center' : 'left'; ctx.fillText(lab, L + x * W, histTop + histH + 14);
  });
  ctx.textAlign = 'left';
  const topI = run.scores.indexOf(Math.max(...run.scores));
  const mk = clamp((t - 1.4) / 0.8);
  if (mk > 0) {
    const x = L + run.scores[topI] * W, right = x < w * 0.55;
    ctx.globalAlpha = mk; ctx.strokeStyle = PAL.red; ctx.lineWidth = 2;
    ctx.beginPath(); ctx.moveTo(x, histTop - 4); ctx.lineTo(x, histTop + histH); ctx.stroke();
    ctx.fillStyle = PAL.red; ctx.textAlign = right ? 'left' : 'right';
    ctx.fillText(`top function: score ${run.scores[topI].toFixed(3)} → p = ${run.p[topI].toFixed(4)}`, x + (right ? 6 : -6), histTop + 8);
    ctx.globalAlpha = 1; ctx.textAlign = 'left'; ctx.lineWidth = 1;
  }
  const top = histTop + histH + 46, H = h - top - 22, m = run.p.length, pmax = 1;
  const X = (r) => L + ((r + 0.5) / m) * W, Y = (p) => top + H - (Math.min(p, pmax) / pmax) * H;
  ctx.fillStyle = PAL.mute;
  ctx.fillText(`Benjamini-Hochberg over ${m} functions: sorted p-values against α·k/m`, L, top - 10);
  ctx.strokeStyle = PAL.hair; ctx.setLineDash([2, 3]); ctx.strokeRect(L, top, W, H); ctx.setLineDash([]);
  ctx.globalAlpha = clamp((t - 2) / 0.8); ctx.strokeStyle = PAL.red; ctx.lineWidth = 1.6;
  ctx.beginPath(); ctx.moveTo(X(0), Y(alpha / m)); ctx.lineTo(X(m - 1), Y(alpha)); ctx.stroke();
  ctx.fillStyle = PAL.red; ctx.textAlign = 'right'; ctx.fillText(`α = ${alpha.toFixed(2)}`, L + W - 4, Y(alpha) - 6);
  ctx.globalAlpha = 1; ctx.textAlign = 'left'; ctx.lineWidth = 1;
  sel.idx.forEach((i, r) => {
    const a = clamp((t - 2.4) * 5 - r * 0.12);
    if (a <= 0) return;
    const x = X(r), y = Y(run.p[i]);
    ctx.globalAlpha = a;
    if (sel.sel[i]) {
      ctx.fillStyle = 'rgba(200,16,46,0.15)'; ctx.beginPath(); ctx.arc(x, y, 10 + 2 * Math.sin(t * 3), 0, 7); ctx.fill();
      ctx.fillStyle = PAL.red; ctx.beginPath(); ctx.arc(x, y, 5, 0, 7); ctx.fill();
    } else {
      ctx.strokeStyle = PAL.ink; ctx.lineWidth = 1.2; ctx.beginPath(); ctx.arc(x, y, 3, 0, 7); ctx.stroke();
    }
    ctx.globalAlpha = 1;
  });
}
