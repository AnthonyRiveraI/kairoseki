// Kairoseki video: the pixel world, painted at 480x270 real pixels and shown 4x without smoothing.
// Everything is a pure function of the timeline time t (seconds), so any frame can be rendered alone.
(function () {
  const W = 480, H = 270, HORIZON = 168;
  // scene starts, kept in sync with narration.json and the composition's data-start values
  const S = { s1: 0, s2: 5, s3: 13, s4: 22, s5: 31, s6: 40, s7: 48, s8: 54, end: 60 };
  const CUTS = [S.s2, S.s3, S.s4, S.s5, S.s6, S.s7, S.s8];

  let world, veil, img, buf;
  const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
  const P = {
    sky: ["#070b1d", "#0b1026", "#111a3a", "#18244d", "#22305f"].map(hex),
    sea: ["#081530", "#0d1f45", "#15306a", "#1f4a8c", "#2f6db0", "#4c88c4"].map(hex),
    foam: hex("#e8f1ff"), shine: hex("#9fd3f0"), star: hex("#c9d6ff"),
    rock: ["#0a0f1f", "#1b2238", "#2a3450", "#3a4663", "#5b6b8c", "#8fa3c7", "#c9d6ff", "#e8f1ff"].map(hex),
    moon: ["#8a93b8", "#b9c2dc", "#dfe6f5", "#f4f7ff"].map(hex),
    metal: ["#1b2238", "#3a4663", "#6b7a99", "#a9b6d0", "#e8f1ff"].map(hex),
    gold: ["#5a3a10", "#8a5a1a", "#d9a441", "#f2c94c", "#fff1b8"].map(hex),
    wood: ["#24150a", "#3b2412", "#5a3a1a", "#8a5a2b", "#b07a3f"].map(hex),
    sail: ["#8f7f5e", "#c8b48a", "#e6d8b6", "#f4ecd8"].map(hex),
    dark: ["#07080f", "#10121e", "#1a1d2e", "#2a2f45", "#3c4260"].map(hex),
    glass: ["#0f2e2a", "#1e4a3a", "#2f7a5a", "#5fb08a", "#bfeedd"].map(hex),
    snail: ["#2f3a1c", "#4f6630", "#7f9e4a", "#b4cf78", "#e1f0b0"].map(hex),
    shell: ["#4a2408", "#7a3e12", "#b5651d", "#e0913a", "#f6c56b"].map(hex),
    cream: ["#8a7f6a", "#c8bfa8", "#efe8d6", "#ffffff"].map(hex),
    cloud: ["#1c2550", "#2a3768", "#3e4f86", "#5a6ca6"].map(hex),
    red: hex("#ff6b6b"), redDark: hex("#b62324"), outline: hex("#05070f"), parchment: hex("#f4ecd8"), white: hex("#ffffff"),
  };
  const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5].map((v) => (v + 0.5) / 16);
  const bayer = (x, y) => BAYER[(y & 3) * 4 + (x & 3)];
  const clamp01 = (v) => Math.max(0, Math.min(1, v));
  const ease = (k) => k * k * (3 - 2 * k);
  const LIGHT = (() => { const l = [-0.55, -0.65, 0.52]; const m = Math.hypot(...l); return l.map((v) => v / m); })();

  function put(x, y, c) {
    x |= 0; y |= 0;
    if (x < 0 || y < 0 || x >= W || y >= H) return;
    const i = (y * W + x) * 4;
    buf[i] = c[0]; buf[i + 1] = c[1]; buf[i + 2] = c[2]; buf[i + 3] = 255;
  }
  const tone = (pal, v, x, y) => pal[Math.max(0, Math.min(pal.length - 1, Math.floor(v * pal.length + bayer(x, y) - 0.5)))];
  function hash(x, y) {
    let n = (x * 374761393 + y * 668265263) | 0;
    n = Math.imul(n ^ (n >>> 13), 1274126177);
    return ((n ^ (n >>> 16)) >>> 0) / 4294967295;
  }
  function noise(x, y) {
    const xi = Math.floor(x), yi = Math.floor(y), xf = x - xi, yf = y - yi;
    const s = (a, b, t) => a + (b - a) * t * t * (3 - 2 * t);
    return s(s(hash(xi, yi), hash(xi + 1, yi), xf), s(hash(xi, yi + 1), hash(xi + 1, yi + 1), xf), yf);
  }
  const sphereLight = (nx, ny, nz) => clamp01(nx * LIGHT[0] + ny * LIGHT[1] + nz * LIGHT[2]);
  function sprite(rows, x, y, colors) {
    rows.forEach((row, j) => [...row].forEach((ch, k) => { if (colors[ch]) put(x + k, y + j, colors[ch]); }));
  }

  // ------------------------------------------------------------------ sky and sea
  function drawSky(t) {
    for (let y = 0; y < HORIZON; y++) {
      const g = y / HORIZON;
      for (let x = 0; x < W; x++) {
        const glow = Math.max(0, 1 - Math.hypot(x - 392, y - 46) / 90) * 0.35;
        put(x, y, tone(P.sky, g * 0.85 + glow, x, y));
      }
    }
    for (let i = 0; i < 90; i++) {
      const sx = Math.floor(hash(i, 1) * W), sy = Math.floor(hash(i, 2) * (HORIZON - 30));
      if (Math.hypot(sx - 392, sy - 46) < 26) continue;
      if (Math.sin(t * (1.5 + hash(i, 3) * 3) + hash(i, 4) * 6.28) <= -0.2) continue;
      put(sx, sy, P.star);
      if (hash(i, 5) > 0.82) { put(sx - 1, sy, P.sky[4]); put(sx + 1, sy, P.sky[4]); put(sx, sy - 1, P.sky[4]); put(sx, sy + 1, P.sky[4]); }
    }
    for (let y = 30; y < 63; y++) for (let x = 376; x < 409; x++) {
      const dx = (x - 392) / 16, dy = (y - 46) / 16, r2 = dx * dx + dy * dy;
      if (r2 > 1) continue;
      let l = clamp01(-dx * 0.6 - dy * 0.5 + Math.sqrt(1 - r2) * 0.7);
      if (noise(x * 0.35, y * 0.35) > 0.62) l -= 0.25;
      put(x, y, tone(P.moon, l, x, y));
    }
  }
  // soft pixel clouds drifting across the sky (and over the moon)
  function drawClouds(t) {
    const clouds = [[0, 34, 0.9, 1.0], [180, 58, 0.6, 0.8], [330, 22, 1.2, 1.1]];
    for (const [base, cy, speed, size] of clouds) {
      const cx = ((base + t * speed * 6) % (W + 120)) - 60;
      const blobs = [[0, 0, 14], [12, 3, 11], [-12, 3, 10], [22, 6, 7], [-22, 6, 6]];
      for (let y = Math.floor(cy - 16 * size); y <= cy + 12 * size; y++) for (let x = Math.floor(cx - 32 * size); x <= cx + 32 * size; x++) {
        let inside = false, top = 1;
        for (const [bx, by, r] of blobs) {
          const d = Math.hypot(x - (cx + bx * size), (y - (cy + by * size)) * 1.6) / (r * size);
          if (d <= 1) { inside = true; top = Math.min(top, (y - (cy + by * size - r * size)) / (2 * r * size)); }
        }
        if (inside && y < cy + 8 * size) put(x, y, tone(P.cloud, 0.95 - top * 0.9, x, y)); // moonlit tops
      }
    }
  }
  // a far island with a palm on the horizon
  function drawIsland() {
    for (let x = 178; x <= 238; x++) {
      const h = Math.round(Math.sqrt(Math.max(0, 1 - ((x - 208) / 30) ** 2)) * 7);
      for (let y = HORIZON - h; y < HORIZON; y++) put(x, y, y === HORIZON - h ? P.dark[3] : P.dark[2]);
    }
    for (let j = 0; j < 14; j++) put(214 + Math.round(j * 0.25), HORIZON - 7 - j, P.dark[3]); // trunk
    for (const [dx, dy] of [[-1, 0], [1, 0], [0, -1]]) for (let k = 1; k <= 8; k++) {
      put(217 + dx * k, HORIZON - 21 + Math.round(k * k * 0.06) + dy, P.dark[3]);
    }
  }
  function drawShootingStar(t, t0) {
    const k = (t - t0) / 0.6;
    if (k < 0 || k > 1) return;
    const x = 330 - k * 110, y = 14 + k * 40;
    for (let i = 0; i < 18; i++) if (bayer(x + i, y) > i / 18) put(x + i * 1.0, y - i * 0.36, i < 3 ? P.white : P.star);
  }

  function drawSea(t) {
    for (let y = HORIZON; y < H; y++) {
      const d = (y - HORIZON) / (H - HORIZON);
      for (let x = 0; x < W; x++) {
        const w = Math.sin(x * 0.07 + t * 1.8 + y * 0.55) * 0.5 + Math.sin(x * 0.023 - t * 1.1 + y * 0.19) * 0.5;
        let c = tone(P.sea, 0.82 - d * 0.62 + w * 0.12, x, y);
        const col = 5 + (y - HORIZON) * 0.22;
        if (Math.abs(x - 392 + Math.sin(y * 0.9 + t * 3) * 3) < col && w > 0.35 && (y & 1) === 0) c = w > 0.7 ? P.foam : P.shine;
        else if (w > 0.9 && hash(x >> 2, y) > 0.7) c = P.shine;
        put(x, y, c);
      }
    }
  }

  // ------------------------------------------------------------------ the seastone
  function drawRock(cx, cy, rx, ry) {
    const inside = (x, y) => {
      const dx = (x - cx) / rx, dy = (y - cy) / ry, a = Math.atan2(dy, dx);
      const edge = 1 + 0.06 * Math.sin(a * 3 + 1.3) + 0.04 * Math.sin(a * 7 + 0.4) + 0.025 * Math.sin(a * 13);
      return dx * dx + dy * dy <= edge * edge;
    };
    for (let y = Math.floor(cy - ry - 3); y <= cy + ry + 3; y++) for (let x = Math.floor(cx - rx - 3); x <= cx + rx + 3; x++) {
      if (!inside(x, y)) {
        if (inside(x + 1, y) || inside(x - 1, y) || inside(x, y + 1) || inside(x, y - 1)) put(x, y, P.rock[0]);
        continue;
      }
      const dx = (x - cx) / rx, dy = (y - cy) / ry, r2 = Math.min(0.999, dx * dx + dy * dy);
      const bump = (noise(x * 0.16, y * 0.16) - 0.5) * 0.38;
      let l = sphereLight(dx + bump, dy + bump, Math.sqrt(1 - r2)) * 0.92 + 0.04;
      if (noise(x * 0.32 + 9, y * 0.32) > 0.76) l -= 0.16;
      if (r2 > 0.86) l *= 0.7;
      let c = tone(P.rock.slice(1, 7), l, x, y);
      const hx = (x - (cx - rx * 0.38)) / (rx * 0.16), hy = (y - (cy - ry * 0.42)) / (ry * 0.14);
      if (hx * hx + hy * hy < 1) c = hx * hx + hy * hy < 0.35 ? P.rock[7] : P.rock[6];
      put(x, y, c);
    }
  }
  function drawRing(cx, cy, r, th, pal) {
    for (let y = Math.floor(cy - r - th - 1); y <= cy + r + th + 1; y++) for (let x = Math.floor(cx - r - th - 1); x <= cx + r + th + 1; x++) {
      const dx = x - cx, dy = y - cy, d = Math.hypot(dx, dy), u = (d - r) / th;
      if (Math.abs(u) > 1) { if (Math.abs(u) < 1 + 1.3 / th) put(x, y, P.outline); continue; }
      const nx = (dx / (d || 1)) * u, ny = (dy / (d || 1)) * u;
      put(x, y, tone(pal, sphereLight(nx, ny, Math.sqrt(1 - u * u)), x, y));
    }
  }
  function drawOval(cx, cy, rx, ry, th, pal) {
    for (let y = Math.floor(cy - ry - th - 1); y <= cy + ry + th + 1; y++) for (let x = Math.floor(cx - rx - th - 1); x <= cx + rx + th + 1; x++) {
      const dx = (x - cx) / rx, dy = (y - cy) / ry, d = Math.hypot(dx, dy), u = ((d - 1) * Math.min(rx, ry)) / th;
      if (Math.abs(u) > 1) { if (Math.abs(u) < 1 + 1.2 / th) put(x, y, P.outline); continue; }
      const nx = (dx / (d || 1)) * u, ny = (dy / (d || 1)) * u;
      put(x, y, tone(pal, sphereLight(nx, ny, Math.sqrt(1 - u * u)), x, y));
    }
  }
  function drawChain(x0, y0, x1, y1, links, sag, pal) {
    for (let i = 0; i <= links; i++) {
      const k = i / links, x = x0 + (x1 - x0) * k, y = y0 + (y1 - y0) * k + Math.sin(k * Math.PI) * sag;
      if (i % 2 === 0) drawOval(x, y, 3.6, 2.4, 1.2, pal);
      else for (let j = -4; j <= 4; j++) { put(x + j, y - 1, P.outline); put(x + j, y + 2, P.outline); put(x + j, y, pal[3]); put(x + j, y + 1, pal[1]); }
    }
  }
  function drawSeastone(cx, cy, s) {
    drawChain(cx + 50 * s, cy + 6 * s, cx + 92 * s, cy + 18 * s, 6, 10 * s, P.metal);
    drawRock(cx, cy, 58 * s, 40 * s);
    drawRing(cx + 104 * s, cy + 18 * s, 11 * s, 3.2 * s, P.gold);
    drawRing(cx + 128 * s, cy + 24 * s, 11 * s, 3.2 * s, P.gold);
  }
  // the seastone falls from the sky onto something, then chains wrap the catch
  function dropSeastone(x, landY, tDrop, t) {
    if (t < tDrop) return;
    const rockY = Math.min(landY, -60 + ((t - tDrop) / 0.45) ** 2 * (landY + 60));
    drawRock(x, rockY - 14, 32, 22);
    if (t >= tDrop + 0.45) {
      const spin = (t - tDrop) * 3;
      for (let i = 0; i < 10; i++) {
        const a = spin + (i / 10) * Math.PI * 2;
        drawOval(x + Math.cos(a) * 38, landY - 12 + Math.sin(a) * 10, 3.6, 2.4, 1.2, P.metal);
      }
      drawRing(x - 34, landY, 7, 2.4, P.gold);
      drawRing(x + 34, landY, 7, 2.4, P.gold);
    }
    drawSplash(x, landY + 6, tDrop + 0.45, t, 80);
  }
  function drawSplash(x, y, t0, t, n) {
    const dt = t - t0;
    if (dt < 0 || dt > 1.2) return;
    for (let i = 0; i < n; i++) {
      const a = -Math.PI * (0.1 + hash(i, 7) * 0.8), v = 40 + hash(i, 8) * 60;
      const px = x + Math.cos(a) * v * dt, py = y + Math.sin(a) * v * dt + 90 * dt * dt;
      put(px, py, hash(i, 9) > 0.5 ? P.foam : P.shine);
      if (hash(i, 10) > 0.6) put(px + 1, py, P.shine);
    }
  }

  // ------------------------------------------------------------------ polygons and ships
  function fillPoly(pts, shade) {
    let minY = Infinity, maxY = -Infinity;
    for (const p of pts) { minY = Math.min(minY, p[1]); maxY = Math.max(maxY, p[1]); }
    for (let y = Math.floor(minY); y <= maxY; y++) {
      const xs = [];
      for (let i = 0; i < pts.length; i++) {
        const a = pts[i], b = pts[(i + 1) % pts.length];
        if ((a[1] <= y && b[1] > y) || (b[1] <= y && a[1] > y)) xs.push(a[0] + ((y - a[1]) / (b[1] - a[1])) * (b[0] - a[0]));
      }
      xs.sort((p, q) => p - q);
      for (let k = 0; k + 1 < xs.length; k += 2) for (let x = Math.ceil(xs[k]); x <= xs[k + 1]; x++) put(x, y, shade(x, y, minY, maxY));
    }
  }
  function outlinePoly(pts) {
    for (let i = 0; i < pts.length; i++) {
      const a = pts[i], b = pts[(i + 1) % pts.length], n = Math.ceil(Math.hypot(b[0] - a[0], b[1] - a[1]));
      for (let k = 0; k <= n; k++) put(a[0] + ((b[0] - a[0]) * k) / n, a[1] + ((b[1] - a[1]) * k) / n, P.outline);
    }
  }
  function drawShip(cx, cy, s, t, pirate) {
    cy += Math.round(Math.sin(t * 2.2 + (pirate ? 1.7 : 0)) * 1.5);
    const wood = pirate ? P.dark : P.wood, cloth = pirate ? P.dark : P.sail;
    const hull = [[cx - 34 * s, cy - 6 * s], [cx + 36 * s, cy - 6 * s], [cx + 28 * s, cy + 8 * s], [cx - 24 * s, cy + 8 * s]];
    fillPoly(hull, (x, y, a, b) => ((y - a) % 3 === 0 ? wood[1] : tone(wood.slice(1), 1 - (y - a) / (b - a), x, y)));
    outlinePoly(hull);
    for (let y = cy - 52 * s; y < cy - 6 * s; y++) { put(cx - 1, y, wood[3]); put(cx, y, wood[2]); put(cx + 1, y, P.outline); }
    const sail = [[cx + 2, cy - 48 * s], [cx + 26 * s, cy - 40 * s], [cx + 24 * s, cy - 12 * s], [cx + 2, cy - 12 * s]];
    fillPoly(sail, (x, y) => tone(cloth.slice(1), 0.85 - ((x - cx) / (26 * s)) * 0.5 + Math.sin(y * 0.4) * 0.05, x, y));
    outlinePoly(sail);
    const back = [[cx - 2, cy - 44 * s], [cx - 20 * s, cy - 36 * s], [cx - 18 * s, cy - 14 * s], [cx - 2, cy - 14 * s]];
    fillPoly(back, (x, y) => tone(cloth.slice(1), 0.55 + Math.sin(y * 0.4) * 0.05, x, y));
    outlinePoly(back);
    const flagY = cy - 56 * s;
    for (let k = 0; k < 9 * s; k++) for (let j = 0; j < 6 * s; j++) put(cx + 1 + k, flagY + j + Math.round(Math.sin(t * 6 + k * 0.6)), pirate ? P.dark[1] : P.shine);
    const mx = Math.round(cx + 13 * s), my = Math.round(cy - 31 * s);
    if (pirate) sprite(["..####..", ".######.", "##.##.##", "########", ".######.", "..#..#..", "#......#", ".#....#."], mx - 4, my - 4, { "#": P.parchment });
    else sprite(["...#...", ".#####.", "#.....#", "#.#.#.#", "#.....#", "#.###.#", ".#####."], mx - 3, my - 3, { "#": P.sea[2] });
    // the crew: a robot sailor for the agent, a tricorn pirate with an eyepatch for the attacker
    const crewX = Math.round(cx - 18 * s), crewY = Math.round(cy - 6 * s) - 12;
    if (pirate) sprite(
      [".kkkkkkk.", "kkkkkkkkk", "..gfffff.", "..fpfef..", "..fffff..", "...fmf...", ".rwrwrwr.", ".wrwrwrw.", ".rwrwrwr.", "..d...d.."],
      crewX - 4, crewY, { k: P.dark[0], g: P.gold[3], f: hex("#e8b48a"), p: P.dark[0], e: P.outline, m: P.redDark, r: P.redDark, w: P.parchment, d: P.dark[1] },
    );
    else sprite(
      ["....a....", "....g....", "..ooooo..", ".obbbbbo.", ".obebebo.", ".obbbbbo.", "..ooooo..", ".osssssso", ".oswswso.", "..o...o.."],
      crewX - 4, crewY, { a: P.outline, g: P.red, o: P.outline, b: P.metal[3], e: P.sea[5], s: P.metal[2], w: P.gold[3] },
    );
    for (let x = cx - 30 * s; x < cx + 32 * s; x++) if (((x + Math.floor(t * 8)) & 3) === 0) put(x, cy + 9 * s, P.foam);
  }

  // ------------------------------------------------------------------ props
  function drawScroll(x, y, t, glow) {
    x = Math.round(x); y = Math.round(y);
    if (glow) for (let j = -11; j <= 11; j++) for (let k = -16; k <= 16; k++) {
      const d = Math.hypot(k / 16, j / 11);
      if (d < 1 && bayer(x + k, y + j) > d + 0.2 + Math.sin(t * 10) * 0.05) put(x + k, y + j, P.gold[3]);
    }
    const bodyW = 18, bodyH = 12, x0 = x - bodyW / 2, y0 = y - bodyH / 2;
    for (let j = 0; j < bodyH; j++) for (let k = 0; k < bodyW; k++) {
      let c = tone(P.sail, 0.95 - (j / bodyH) * 0.35, x0 + k, y0 + j);
      if (j % 3 === 1 && k > 2 && k < bodyW - 3 - (j === 7 ? 6 : 0)) c = P.wood[2];
      put(x0 + k, y0 + j, c);
    }
    for (const side of [-1, 1]) {
      const rx = side < 0 ? x0 - 3 : x0 + bodyW;
      for (let j = -2; j < bodyH + 2; j++) for (let k = 0; k < 3; k++) put(rx + k, y0 + j, tone(P.gold.slice(1), clamp01(0.75 - ((k - 1) / 1.5) * 0.5 - (j / bodyH) * 0.3), rx + k, y0 + j));
      for (let j = -3; j <= bodyH + 2; j++) { put(rx - 1, y0 + j, P.outline); put(rx + 3, y0 + j, P.outline); }
      for (let k = -1; k <= 3; k++) { put(rx + k, y0 - 3, P.outline); put(rx + k, y0 + bodyH + 2, P.outline); }
    }
    for (let k = 0; k < bodyW; k++) { put(x0 + k, y0 - 1, P.outline); put(x0 + k, y0 + bodyH, P.outline); }
    for (let j = -2; j <= 2; j++) for (let k = -2; k <= 2; k++) if (j * j + k * k <= 5) put(x + 4 + k, y + 3 + j, j * j + k * k <= 1 ? P.red : P.redDark);
  }

  // a message in a bottle, floating; its hidden ink glows red when revealed
  function drawBottle(cx, cy, t, reveal) {
    cy += Math.round(Math.sin(t * 2.4) * 1.5);
    const tilt = 0.32, ca = Math.cos(tilt), sa = Math.sin(tilt);
    const L = 30, R = 8; // body length and radius, neck after
    if (reveal > 0) for (let j = -22; j <= 22; j++) for (let k = -30; k <= 30; k++) {
      const d = Math.hypot(k / 30, j / 22);
      if (d < 1 && bayer(cx + k, cy + j) * 1.25 > d + (1 - reveal) * 0.9) put(cx + k, cy + j, hash(k, j) > 0.5 ? P.red : P.redDark);
    }
    for (let y = cy - 24; y <= cy + 24; y++) for (let x = cx - 30; x <= cx + 30; x++) {
      const u = (x - cx) * ca + (y - cy) * sa, v = -(x - cx) * sa + (y - cy) * ca; // bottle space
      let r;
      if (u >= -L / 2 && u <= L / 2) r = R;
      else if (u > L / 2 && u <= L / 2 + 6) r = R - (u - L / 2) * 1.0; // shoulder
      else if (u > L / 2 + 6 && u <= L / 2 + 13) r = 2.5; // neck
      else continue;
      if (Math.abs(v) > r + 1) continue;
      if (Math.abs(v) > r) { put(x, y, P.outline); continue; }
      const nv = v / r, nz = Math.sqrt(Math.max(0, 1 - nv * nv));
      let c = tone(P.glass, sphereLight(0, nv * ca, nz) * 0.8 + 0.1, x, y);
      if (u > L / 2 + 9) c = tone(P.wood.slice(1), 0.6 + nv * -0.3, x, y); // cork
      if (Math.abs(nv + 0.5) < 0.12 && u < L / 2) c = P.glass[4]; // glint
      if (u > -L / 2 + 4 && u < L / 2 - 4 && Math.abs(nv) < 0.45) { // the rolled message inside
        c = tone(P.sail, 0.9 - Math.abs(nv), x, y);
        if (reveal > 0.4 && Math.round(u) % 3 === 0) c = P.red;
      }
      put(x, y, c);
    }
  }

  // a messenger gull carrying a letter; flaps on a two-frame cycle
  function drawGull(x, y, t, stopped) {
    x = Math.round(x); y = Math.round(y);
    const up = Math.floor(t * 7) % 2 === 0;
    // o = outline, w = white, g = grey shade, d = dark wing tip
    const wingsUp = [
      "dd.......................dd",
      "odd.....................ddo",
      ".owgd.................dgwo.",
      "..owwgd.............dgwwo..",
      "...owwwgo.........ogwwwo...",
      "....owwwwo.......owwwwo....",
      ".....owwwwo.....owwwwo.....",
    ];
    const wingsDown = [
      "...........................",
      "...........................",
      "...........................",
      "........ooooo.ooooo........",
      "....ooowwwwwo.owwwwwooo....",
      "..owwwwwggo.....ogggwwwwo..",
      "oddgg..................ggddo",
    ];
    const body = [
      ".....oooooo....",
      "...oowwwwwwoo..",
      "..owwwwwwwoyyo.",
      "oowwwwwwwwwyyyy",
      ".owgggwwwwwoo..",
      "..oogggggoo....",
      "....ooooo......",
    ];
    const pal = { o: P.outline, w: P.cream[3], g: P.cream[1], d: P.dark[3], y: P.gold[3] };
    sprite(up ? wingsUp : wingsDown, x - 13, y - 9, pal);
    sprite(body, x - 7, y - 3, pal);
    put(x + 4, y - 1, P.outline); // eye
    // the letter it carries
    sprite(["oooooooooo", "oppppppppo", "opoppppopo", "oppoppoppo", "opppoopppo", "oooooooooo"], x - 5, y + 4, { o: P.outline, p: P.parchment });
    if (stopped) { // a "!" bubble: Kairoseki is asking first
      for (let j = -24; j <= -10; j++) for (let k = 6; k <= 18; k++) {
        const edge = j === -24 || j === -10 || k === 6 || k === 18;
        put(x + k, y + j, edge ? P.outline : P.white);
      }
      for (let j = -21; j <= -15; j++) { put(x + 11, y + j, P.redDark); put(x + 12, y + j, P.redDark); }
      put(x + 11, y - 13, P.redDark); put(x + 12, y - 13, P.redDark);
      put(x + 8, y - 9, P.outline); put(x + 7, y - 8, P.outline);
    }
  }

  // the Den Den Mushi: a snail phone with a spiral shell, eye stalks and a handset on its back
  function drawDenDen(cx, cy, t, ringing) {
    const shake = ringing ? (Math.floor(t * 20) % 2 === 0 ? -1 : 1) : 0;
    cx += shake;
    // body: a long soft blob with a raised head on the right
    for (let y = cy - 26; y <= cy + 18; y++) for (let x = cx - 50; x <= cx + 64; x++) {
      const bx = (x - cx - 4) / 50, by = (y - cy - 12) / 8;
      const hx = (x - cx - 48) / 13, hy = (y - cy + 4) / 17;
      const inBody = bx * bx + by * by <= 1, inHead = hx * hx + hy * hy <= 1;
      if (!inBody && !inHead) continue;
      const [nx, ny, r2] = inHead ? [hx, hy, hx * hx + hy * hy] : [bx * 0.5, by, bx * bx * 0.25 + by * by];
      put(x, y, tone(P.snail, sphereLight(nx, ny, Math.sqrt(Math.max(0, 1 - Math.min(1, r2)))) * 0.9 + 0.08, x, y));
    }
    // eye stalks and eyes (blink once in a while)
    const blink = Math.floor(t * 2.5) % 7 === 0;
    for (const [ex, lean] of [[cx + 44, -2], [cx + 54, 2]]) {
      for (let j = 0; j < 14; j++) { put(ex + Math.round((lean * j) / 14), cy - 18 - j, P.snail[1]); put(ex + 1 + Math.round((lean * j) / 14), cy - 18 - j, P.snail[2]); }
      const ey = cy - 34, exx = ex + lean;
      if (blink) for (let k = -3; k <= 3; k++) put(exx + k, ey, P.outline);
      else {
        for (let j = -3; j <= 3; j++) for (let k = -3; k <= 3; k++) if (j * j + k * k <= 10) put(exx + k, ey + j, j * j + k * k > 7 ? P.outline : P.white);
        put(exx + 1, ey, P.outline); put(exx + 1, ey + 1, P.outline);
      }
    }
    sprite(["#....#", ".####."], cx + 46, cy - 4, { "#": P.outline }); // smile
    // shell: shaded sphere with a spiral band
    const scx = cx - 6, scy = cy - 6, sr = 28;
    for (let y = scy - sr - 1; y <= scy + sr + 1; y++) for (let x = scx - sr - 1; x <= scx + sr + 1; x++) {
      const dx = (x - scx) / sr, dy = (y - scy) / sr, r2 = dx * dx + dy * dy;
      if (r2 > 1) { if (r2 < 1.09) put(x, y, P.outline); continue; }
      const r = Math.sqrt(r2), th = Math.atan2(dy, dx) / (Math.PI * 2) + 0.5;
      const band = ((r * 3.2 - th) % 1 + 1) % 1;
      let l = sphereLight(dx, dy, Math.sqrt(1 - r2)) * 0.9 + 0.08;
      if (band < 0.18) l -= 0.32;
      put(x, y, tone(P.shell, l, x, y));
    }
    // handset resting on top of the shell, lifted a little while it rings
    const lift = ringing ? Math.round(Math.abs(Math.sin(t * 18)) * 3) : 0;
    const hy0 = scy - sr - 6 - lift;
    for (let x = scx - 22; x <= scx + 22; x++) for (let j = 0; j < 6; j++) {
      const end = Math.abs(x - scx) > 16;
      const y = hy0 + j - (end ? 2 : 0);
      if (j === 0 || j === 5) put(x, y, P.outline);
      else put(x, y, tone(P.cream, 0.95 - j * 0.15, x, y));
    }
    for (let j = 0; j < 10; j++) put(scx + 20 + Math.round(Math.sin(j * 1.3) * 2), hy0 + 6 + j, P.outline); // curly cord
    if (ringing && Math.floor(t * 6) % 2 === 0) for (const r of [10, 16]) for (let a = -0.9; a <= 0.9; a += 0.12) { // ring waves
      put(scx - 26 - Math.cos(a) * r, hy0 + Math.sin(a) * r, P.gold[3]);
      put(scx + 26 + Math.cos(a) * r, hy0 + Math.sin(a) * r, P.gold[3]);
    }
  }

  // ------------------------------------------------------------------ scenes
  function drawWorld(t) {
    drawSky(t);
    drawShootingStar(t, 2.0);
    drawClouds(t);
    drawIsland();
    drawSea(t);
    if (t < S.s2) {
      drawSeastone(92, 78 + Math.round(Math.sin(t * 2.6) * 2), 0.95);
    } else if (t < S.s4) { // the token theft, without then with Kairoseki
      const attack = t < S.s3, s0 = attack ? S.s2 : S.s3;
      drawShip(78, 192, 1.15, t, false);
      drawShip(410, 182, 0.9, t, true);
      const fly0 = s0 + (attack ? 4.0 : 4.3), fly1 = fly0 + (attack ? 1.6 : 0.9);
      if (t >= fly0) {
        const k = clamp01((t - fly0) / (fly1 - fly0));
        const fx = 100 + (attack ? 300 : 190) * ease(k), fy = 168 - Math.sin(ease(k) * Math.PI) * (attack ? 22 : 24);
        if (attack) {
          if (k < 1) drawScroll(fx, fy, t, true);
          else if (Math.floor(t * 6) % 2 === 0) drawScroll(400, 168, t, true);
        } else {
          const drop = s0 + 5.2;
          drawScroll(t < drop ? fx : 290, t < drop ? fy : 162, t, t < drop + 0.45);
          dropSeastone(290, 170, drop, t);
        }
      }
    } else if (t < S.s5) { // poisoned tool: a message in a bottle with hidden ink
      const reveal = clamp01((t - (S.s4 + 3.0)) / 1.2);
      const drop = S.s4 + 6.0;
      if (t < drop + 0.45) drawBottle(300, 186, t, reveal);
      dropSeastone(300, 190, drop, t);
    } else if (t < S.s6) { // issue -> public PR: the messenger gull is stopped mid-air
      drawShip(90, 194, 1.1, t, false);
      const askAt = S.s5 + 5.0;
      const k = clamp01((t - (S.s5 + 3.6)) / 1.4);
      const gx = 110 + 125 * ease(k), gy = 170 - Math.sin(ease(k) * Math.PI) * 14 + Math.sin(t * 6) * 1.5;
      if (t >= S.s5 + 3.6) drawGull(gx, gy, t, t >= askAt);
    } else if (t < S.s7) { // Den Den Mushi rings
      const ringing = t >= S.s6 + 0.6 && t < S.s6 + 5.2;
      drawDenDen(150, 150, t, ringing);
    } else if (t < S.s8) {
      drawSeastone(30, 228, 0.42);
    } else {
      drawSeastone(170, 92 + Math.round(Math.sin(t * 2.6) * 2), 0.95);
    }
    world.putImageData(img, 0, 0);
  }

  // pixel dissolve between scenes, painted above everything
  function drawVeil(t) {
    veil.clearRect(0, 0, W, H);
    let cover = 0;
    for (const c of CUTS) { const d = Math.abs(t - c); if (d < 0.4) cover = Math.max(cover, 1 - d / 0.4); }
    if (t > S.end - 0.8) cover = Math.max(cover, (t - (S.end - 0.8)) / 0.8);
    if (cover <= 0) return;
    veil.fillStyle = "#05070f";
    for (let by = 0; by < H / 6; by++) for (let bx = 0; bx < W / 6; bx++) if (bayer(bx, by) * 0.85 + hash(bx, by) * 0.15 < cover) veil.fillRect(bx * 6, by * 6, 6, 6);
  }

  window.KairosekiWorld = {
    S,
    init(worldCanvas, veilCanvas) {
      world = worldCanvas.getContext("2d");
      veil = veilCanvas.getContext("2d");
      img = world.createImageData(W, H);
      buf = img.data;
    },
    draw(t) { drawWorld(t); drawVeil(t); },
  };
})();
