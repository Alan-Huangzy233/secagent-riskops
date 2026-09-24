'use strict';
// Replays docs/eval/web-demo-synthetic-7d.json. The page computes nothing
// itself: counters, scores, verdicts and truth all come from the snapshot, and
// the response buttons call the API, which runs the real policy engine and
// executor. Log text is attacker-controlled in principle, so every value is
// inserted with textContent, never as HTML.

const $ = (id) => document.getElementById(id);
const SVG = 'http://www.w3.org/2000/svg';
const HOUR = 3600000;
const WEEK_MS = 45000; // wall-clock length of the replay at 1x
const SCORE_SCALE = 120;

let S = null;
let t0 = 0, t1 = 0, now = 0;
let playing = false, speed = 1, lastFrame = null;
let prefix = [];
let tickerTimes = [];
let shown = 0;
let selectedId = null;
const rows = new Map();

function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}
function svg(tag, attrs) {
  const node = document.createElementNS(SVG, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  return node;
}
const fmt = (n) => Math.round(n).toLocaleString('en-US');
const pct = (x, digits = 1) => `${(100 * x).toFixed(digits)} %`;
const utc = (ms) => new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + ' UTC';
const weekday = (ms) => new Date(ms).toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' });
function chip(cls, text) { return el('span', `chip ${cls}`, text); }

async function load() {
  const response = await fetch('/demo/snapshot.json', { cache: 'no-store' });
  if (!response.ok) throw new Error(`snapshot: HTTP ${response.status}`);
  S = await response.json();
  t0 = Date.parse(S.dataset.start);
  t1 = Date.parse(S.dataset.end);
  for (const incident of S.incidents) incident._last = Date.parse(incident.last);
  tickerTimes = S.ticker.map((line) => Date.parse(line.ts));
  prefix = [0, 1, 2, 3].map((k) => {
    const sums = [0];
    for (const hour of S.hours) sums.push(sums[sums.length - 1] + hour[k]);
    return sums;
  });
  $('seed').textContent = S.dataset.seed;
  $('threshold').textContent = S.scoring.threshold;
  $('tick').textContent = S.scoring.tick_seconds;
  drawChart();
  fillMissed();
  wire();
  const params = new URLSearchParams(location.search);
  setTime(params.get('at') === 'end' ? t1 : t0);
  const wanted = decodeURIComponent(location.hash.slice(1));
  if (wanted && S.incidents.some((i) => i.id === wanted)) {
    select(wanted);
    // ?respond=approve|request presses that button, for links and screenshots.
    const press = { approve: '.response .danger', request: '.response .buttons button' }[params.get('respond')];
    const button = press && document.querySelector(press);
    if (button) button.click();
  }
  if (params.get('autoplay') === '1') play();
}

function valueAt(k, t) {
  const hours = Math.max(0, Math.min(S.hours.length, (t - t0) / HOUR));
  const whole = Math.floor(hours);
  const partial = whole < S.hours.length ? S.hours[whole][k] * (hours - whole) : 0;
  return prefix[k][whole] + partial;
}

function setTime(t) {
  const rewound = t < now;
  now = Math.max(t0, Math.min(t1, t));
  if (rewound) resetList();
  $('n-lines').textContent = fmt(valueAt(0, now));
  $('n-alerts').textContent = fmt(valueAt(1, now));
  $('n-incidents').textContent = fmt(valueAt(2, now));
  $('n-surfaced').textContent = fmt(valueAt(3, now));
  $('clock').textContent = now >= t1 ? 'end of week' : utc(now);
  updateChart();
  updateTicker();
  while (shown < S.incidents.length && S.incidents[shown]._last <= now) addRow(S.incidents[shown++], now < t1);
  $('list-count').textContent = shown;
  $('list-hint').hidden = shown > 0;
  const done = now >= t1;
  $('versus').hidden = !done;
  $('missed').hidden = !done;
  if (done) fillVersus();
}

function resetList() {
  shown = 0;
  rows.clear();
  $('incidents').replaceChildren();
}

function frame(stamp) {
  if (!playing) return;
  if (lastFrame !== null) setTime(now + (stamp - lastFrame) * speed * (t1 - t0) / WEEK_MS);
  lastFrame = stamp;
  if (now >= t1) { stop(); return; }
  requestAnimationFrame(frame);
}
function play() {
  if (now >= t1) setTime(t0 - 1);
  playing = true;
  lastFrame = null;
  $('play').textContent = '❚❚ Pause';
  requestAnimationFrame(frame);
}
function stop() {
  playing = false;
  $('play').textContent = now >= t1 ? '▶ Replay again' : '▶ Resume';
}

function wire() {
  $('play').addEventListener('click', () => (playing ? stop() : play()));
  $('skip').addEventListener('click', () => { stop(); setTime(t1); stop(); });
  for (const button of document.querySelectorAll('.speed button')) {
    button.addEventListener('click', () => {
      speed = Number(button.dataset.speed);
      for (const other of document.querySelectorAll('.speed button')) other.classList.toggle('on', other === button);
    });
  }
  $('truth').addEventListener('change', () => {
    document.body.classList.toggle('hide-truth', !$('truth').checked);
    updateChart();
  });
}

// ---------------------------------------------------------------- chart
let bars = [], dots = [], cursor = null;
function drawChart() {
  const chart = $('chart');
  const width = 1000, height = 120, base = 108;
  const peak = Math.max(...S.hours.map((h) => h[1]), 1);
  const step = width / S.hours.length;
  for (let day = 0; day <= S.dataset.days; day++) {
    const x = day * 24 * step;
    chart.append(svg('line', { class: 'day', x1: x, x2: x, y1: 0, y2: height }));
    if (day < S.dataset.days) {
      const label = svg('text', { x: x + 3, y: 10 });
      label.textContent = weekday(t0 + day * 24 * HOUR);
      chart.append(label);
    }
  }
  bars = S.hours.map((hour, i) => {
    const h = Math.max(1, (hour[1] / peak) * 80);
    const bar = svg('rect', { class: 'bar', x: i * step + 0.5, y: base - h, width: Math.max(1, step - 1), height: h });
    chart.append(bar);
    return bar;
  });
  dots = S.incidents.map((incident) => {
    const dot = svg('circle', { class: 'dot', cx: ((incident._last - t0) / (t1 - t0)) * width, cy: 20, r: 4 });
    const title = svg('title', {});
    title.textContent = `${incident.id} · score ${incident.score}`;
    dot.append(title);
    dot.addEventListener('click', () => select(incident.id));
    chart.append(dot);
    return dot;
  });
  cursor = svg('line', { class: 'cursor', x1: 0, x2: 0, y1: 0, y2: height });
  chart.append(cursor);
}
function updateChart() {
  if (!cursor) return;
  const x = ((now - t0) / (t1 - t0)) * 1000;
  cursor.setAttribute('x1', x);
  cursor.setAttribute('x2', x);
  const hour = (now - t0) / HOUR;
  bars.forEach((bar, i) => bar.setAttribute('opacity', i < hour ? 1 : 0.15));
  const truth = $('truth').checked;
  S.incidents.forEach((incident, i) => {
    dots[i].setAttribute('visibility', incident._last <= now ? 'visible' : 'hidden');
    dots[i].setAttribute('class', `dot ${truth ? incident.truth.label : 'neutral'}`);
  });
}

function updateTicker() {
  let lo = 0, hi = tickerTimes.length;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (tickerTimes[mid] <= now) lo = mid + 1; else hi = mid; }
  const lines = S.ticker.slice(Math.max(0, lo - 5), lo);
  const box = $('ticker');
  if (!lines.length) return;
  box.replaceChildren(...lines.map((line) => el('div', null, `${line.ts.replace('T', ' ').slice(0, 19)}  ${line.host.padEnd(10)}  ${line.message}`)));
}

// ---------------------------------------------------------------- list
function addRow(incident, animate) {
  const li = el('li');
  if (!animate) li.style.animation = 'none';
  li.dataset.id = incident.id;
  const top = el('div', 'row1');
  top.append(chip(incident.priority, incident.priority), el('span', 'id', incident.id),
    el('span', 'muted', `score ${incident.score}`));
  const verdict = incident.model ? incident.model.verdict : 'none';
  top.append(chip(verdict, incident.model ? `Claude: ${verdict}` : 'not judged'));
  const second = el('div', 'row2');
  second.append(chip(`truth ${incident.truth.label}`, incident.truth.label),
    document.createTextNode(` ${incident.sources.join(', ')} → ${incident.hosts.join(', ')} · ${incident.alerts} alerts`));
  const bar = el('div', 'minibar');
  const fill = el('div', 'fill');
  const tick = el('div', 'tick');
  tick.style.left = `${(S.scoring.threshold / SCORE_SCALE) * 100}%`;
  bar.append(fill, tick);
  li.append(top, second, bar);
  li.addEventListener('click', () => select(incident.id));
  if (incident.id === selectedId) li.classList.add('selected');
  $('incidents').prepend(li);
  rows.set(incident.id, li);
  requestAnimationFrame(() => { fill.style.width = `${Math.min(100, (incident.score / SCORE_SCALE) * 100)}%`; });
}

// ---------------------------------------------------------------- detail
function select(id) {
  selectedId = id;
  for (const [key, li] of rows) li.classList.toggle('selected', key === id);
  const incident = S.incidents.find((i) => i.id === id);
  $('placeholder').hidden = true;
  const box = $('incident');
  box.hidden = false;
  box.replaceChildren(...renderIncident(incident));
  history.replaceState(null, '', `${location.search}#${id}`);
}

function section(title, ...children) {
  const wrap = el('div');
  wrap.append(el('h3', null, title), ...children);
  return wrap;
}

function renderIncident(incident) {
  const parts = [];
  const head = el('div', 'head');
  head.append(el('h2', null, incident.id), chip(incident.priority, incident.priority),
    el('span', null, `score ${incident.score}`));
  if (incident.model) head.append(chip(incident.model.verdict, `Claude: ${incident.model.verdict}`));
  head.append(chip(`truth ${incident.truth.label}`, `truth: ${incident.truth.label}`));
  parts.push(head);

  const facts = el('div', 'facts');
  const fact = (label, value) => { const d = el('div', null, value); d.prepend(el('span', null, label)); facts.append(d); };
  fact('Source', incident.sources.join(', '));
  fact('Hosts', incident.hosts.join(', '));
  fact('First seen', incident.first.replace('T', ' ').replace('Z', ' UTC'));
  fact('Last seen', incident.last.replace('T', ' ').replace('Z', ' UTC'));
  fact('Alerts merged', fmt(incident.alerts));
  fact('Log records', `${fmt(incident.records)} (${fmt(incident.failed_records)} failed)`);
  parts.push(facts);
  const rules = el('div', 'row1');
  rules.append(el('span', 'muted', 'Rules fired:'), ...incident.rules.map((rule) => chip('rule', rule)));
  parts.push(rules);

  parts.push(section(`Why it was surfaced: score ${incident.score}, threshold ${S.scoring.threshold}`, ...scoreBar(incident)));
  if (incident.model) parts.push(section('Claude’s triage', claudeBox(incident)));
  else parts.push(section('Claude’s triage', el('p', 'muted', 'No recorded call for this incident.')));
  parts.push(section('Evidence (raw sshd lines; lines Claude cited are highlighted)', evidence(incident)));
  parts.push(section(`Accounts tried (${incident.accounts_tried})`, accounts(incident)));
  parts.push(truthBox(incident));
  parts.push(section('Response', response(incident)));
  return parts;
}

function scoreBar(incident) {
  const items = incident.reasons.map((reason) => {
    const match = /^([+-]\d+)\s(.*)$/.exec(reason);
    return match ? { pts: Number(match[1]), text: match[2] } : { pts: 0, text: reason };
  });
  const positive = items.filter((i) => i.pts > 0).reduce((a, i) => a + i.pts, 0);
  const scale = Math.max(positive, S.scoring.threshold, incident.score) * 1.08;
  const bar = el('div', 'scorebar');
  let left = 0, delay = 0;
  for (const item of items.filter((i) => i.pts > 0)) {
    const seg = el('div', 'seg');
    seg.style.position = 'absolute';
    seg.style.left = `${(left / scale) * 100}%`;
    seg.style.width = `${(item.pts / scale) * 100}%`;
    seg.style.animationDelay = `${delay}s`;
    seg.title = `${item.pts > 0 ? '+' : ''}${item.pts} ${item.text}`;
    bar.append(seg);
    left += item.pts;
    delay += 0.25;
  }
  for (const item of items.filter((i) => i.pts < 0)) {
    const seg = el('div', 'seg neg');
    seg.style.position = 'absolute';
    seg.style.left = `${((left + item.pts) / scale) * 100}%`;
    seg.style.width = `${(-item.pts / scale) * 100}%`;
    seg.style.animationDelay = `${delay}s`;
    seg.title = `${item.pts} ${item.text}`;
    bar.append(seg);
    left += item.pts;
    delay += 0.25;
  }
  const tick = el('div', 'tick');
  tick.style.left = `${(S.scoring.threshold / scale) * 100}%`;
  const label = el('div', 'ticklabel', `threshold ${S.scoring.threshold}`);
  label.style.left = tick.style.left;
  bar.append(tick, label);
  const list = el('ul', 'reasons');
  for (const item of items) {
    const li = el('li');
    li.append(el('span', `pts${item.pts < 0 ? ' neg' : ''}`, `${item.pts > 0 ? '+' : ''}${item.pts}`), document.createTextNode(item.text));
    list.append(li);
  }
  return [bar, list];
}

function claudeBox(incident) {
  const m = incident.model;
  const box = el('div', 'claude');
  const top = el('div', 'row1');
  top.append(chip(m.verdict, m.verdict.toUpperCase()), el('span', 'muted', `confidence ${m.confidence}`));
  box.append(top, el('p', null, m.rationale));
  if (m.attack_techniques.length) box.append(el('p', 'meta', `Techniques: ${m.attack_techniques.join(' · ')}`));
  box.append(el('p', 'meta', `${m.model}, recorded call replayed (no API key needed) · $${m.usd.toFixed(3)} · ${m.latency_seconds.toFixed(1)} s · prompt sha256 ${m.prompt_sha256.slice(0, 12)}… · it read the logs, never the score`));
  return box;
}

function evidence(incident) {
  const cited = new Set(incident.model ? incident.model.evidence_ids : []);
  const box = el('div', 'evidence');
  for (const line of incident.evidence) {
    const row = el('div', cited.has(line.event_id) ? 'cited' : null);
    row.append(el('span', 'ts', `${line.ts.replace('T', ' ').slice(0, 19)}  ${line.host.padEnd(10)} `), document.createTextNode(line.message));
    box.append(row);
  }
  if (incident.records > incident.evidence.length) box.append(el('div', 'ts', `… ${fmt(incident.records - incident.evidence.length)} more records in this incident`));
  return box;
}

function scrollable(table) {
  const wrap = el('div', 'table-wrap');
  wrap.append(table);
  return wrap;
}

function accounts(incident) {
  const table = el('table');
  const head = el('tr');
  head.append(el('th', null, 'Account'), el('th', 'num', 'Failed'), el('th', null, 'sshd said “Invalid user”'), el('th', 'num', 'Logins'));
  table.append(head);
  for (const row of incident.accounts) {
    const tr = el('tr');
    tr.append(el('td', 'mono', row.account), el('td', 'num', fmt(row.failed_records)),
      el('td', null, row.sshd_marked_invalid ? 'yes' : 'no (the account exists)'), el('td', 'num', row.successful_logins));
    table.append(tr);
  }
  return scrollable(table);
}

function truthBox(incident) {
  const box = el('div', 'truth-box');
  box.append(el('strong', null, 'Ground truth '), el('span', 'muted', '(kept apart; the pipeline and the model never see it): '));
  if (incident.truth.label === 'benign') box.append(document.createTextNode('benign activity, a false alarm.'));
  else {
    box.append(document.createTextNode(incident.truth.episodes.map((e) =>
      `${e.id} (${e.scenario.replaceAll('_', ' ')}) ${e.detected ? 'caught' : 'not counted as caught: under half its alerts are here'}`).join('; ')));
  }
  return box;
}

// ---------------------------------------------------------------- response
function response(incident) {
  const box = el('div', 'response');
  const action = incident.action;
  if (!action) {
    const why = !incident.model ? 'there is no recorded verdict.'
      : incident.model.verdict === 'dismiss' ? 'Claude dismissed it, so it leaves the analyst’s queue.'
      : 'it stays with the analyst: the playbook acts only on a password that was guessed (a login succeeding from a source never seen for that account).';
    box.append(el('p', null, `No automatic response: ${why}`));
    return box;
  }
  box.append(el('p', null, `Playbook: a login succeeded from a source never seen for that account, so the password was guessed. Plan: `),
    el('p', 'mono', `${action.type} on ${action.host} — disable root login, key-only authentication (medium risk: needs an approval)`));
  box.append(el('p', 'muted', action.lab_copy
    ? `${action.host} has a lab copy in this demo; the executor changes that copy, never a real host.`
    : `There is no lab copy of ${action.host} in this demo, so after approval the executor refuses to run anywhere.`));
  const buttons = el('div', 'buttons');
  const bare = el('button', null, 'Request without approval');
  const approve = el('button', 'danger', 'Approve as security-operator and run');
  buttons.append(bare, approve);
  const out = el('div');
  bare.addEventListener('click', () => respond(incident, false, out, [bare, approve]));
  approve.addEventListener('click', () => respond(incident, true, out, [bare, approve]));
  box.append(buttons, out, scopeForm(incident));
  return box;
}

async function post(path, body) {
  const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.detail || `HTTP ${r.status}`);
  return data;
}

async function respond(incident, approve, out, buttons) {
  buttons.forEach((b) => { b.disabled = true; });
  out.replaceChildren(el('p', 'muted', 'Running…'));
  try {
    const result = await post(`/demo/incidents/${encodeURIComponent(incident.id)}/respond`, { approve });
    out.replaceChildren(...renderResult(result));
  } catch (error) {
    out.replaceChildren(el('p', 'chain bad', `Request failed: ${error.message}`));
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
  }
}

function renderResult(result) {
  const parts = [];
  const steps = el('ol', 'steps');
  for (const step of result.steps) {
    if (step.kind === 'policy') {
      const li = el('li', step.effect);
      li.append(document.createTextNode(`Policy engine (${step.when}): `), el('span', 'code', `${step.effect.toUpperCase()} ${step.reason_code}`), document.createTextNode(` — ${step.message}`));
      steps.append(li);
    } else if (step.kind === 'approval') {
      steps.append(el('li', 'approval', `APPROVED by ${step.approver} (${step.approval_id}), bound to plan ${step.plan_hash.slice(0, 19)}…`));
    } else if (step.kind === 'refused') {
      steps.append(el('li', 'refused', `Executor refused: ${step.reason}`));
    }
  }
  if (result.verification) {
    const v = result.verification;
    const failed = v.checks.filter((c) => !c.ok);
    steps.append(el('li', v.ok ? 'pass' : 'fail', v.ok
      ? `Verification PASS: re-read from the host, all ${v.checks.length} settings are what sshd will use`
      : `Verification FAIL: ${failed.map((c) => `${c.setting} should be ${c.expected} but sshd would use ${c.effective} (from ${c.source})`).join('; ')}`));
  }
  if (result.rollback) {
    const r = result.rollback;
    steps.append(el('li', r.ok ? 'pass' : 'fail', `Rolled back automatically, no person involved: file identical to before ${r.matches_before ? '✓' : '✗'}, settings as before ${r.state_matches_before ? '✓' : '✗'}`));
  }
  parts.push(steps);
  parts.push(el('p', null, `Plan ${result.plan.id} ends as: ${result.status.replace('_', ' ')}`));
  if (result.states) parts.push(section('Settings sshd would use', states(result.states)));
  if (result.diff && result.diff.length) parts.push(section('Change to etc/ssh/sshd_config', diff(result.diff)));
  parts.push(section(`Audit trail: ${result.chain.events} hash-chained events`, timeline(result)));
  return parts;
}

function states(all) {
  const columns = ['before', 'after', 'restored'].filter((c) => all[c]);
  const table = el('table', 'states');
  const head = el('tr');
  head.append(el('th', null, 'Setting'), ...columns.map((c) => el('th', null, c)));
  table.append(head);
  for (const setting of Object.keys(all.before)) {
    const tr = el('tr');
    tr.append(el('td', 'mono', setting));
    for (const column of columns) {
      const value = all[column][setting].value;
      tr.append(el('td', value !== all.before[setting].value ? 'mono changed' : 'mono', value));
    }
    table.append(tr);
  }
  return scrollable(table);
}

function diff(lines) {
  const box = el('div', 'diff');
  for (const line of lines) {
    const cls = line.startsWith('+') && !line.startsWith('+++') ? 'add' : line.startsWith('-') && !line.startsWith('---') ? 'del' : null;
    box.append(el('div', cls, line));
  }
  return box;
}

function timeline(result) {
  const wrap = el('div');
  const table = el('table', 'timeline');
  for (const row of result.timeline) {
    const tr = el('tr', row.segment);
    tr.append(el('td', 'num', row.n), el('td', 'mono', row.time.slice(11, 19)), el('td', 'seg', row.segment),
      el('td', 'mono', row.actor), el('td', null, row.text));
    table.append(tr);
  }
  const chain = el('p', `chain ${result.chain.ok ? 'ok' : 'bad'}`, `${result.chain.ok ? '✓ Chain intact' : '✗ Chain broken'}: ${result.chain.message}`);
  const link = el('a', null, 'Download this trail (JSON Lines)');
  const blob = new Blob([result.export.map((r) => JSON.stringify(r)).join('\n') + '\n'], { type: 'application/x-ndjson' });
  link.href = URL.createObjectURL(blob);
  link.download = `audit-${result.incident_id}.jsonl`;
  const hint = el('p', 'muted', 'Check it without this server: python -m app.audit_timeline verify audit-….jsonl');
  wrap.append(scrollable(table), chain, link, hint);
  return wrap;
}

function scopeForm(incident) {
  const wrap = section('Try to authorise it under a different scope');
  wrap.append(el('p', 'muted', 'Type the targets a scope would allow. The plan is approved; only the scope changes. Try *, *.internal, 10.0.0.0/8, a blank list, or a valid-until of “end of November”.'));
  const form = el('form', 'scope-form');
  const targets = el('input');
  targets.value = incident.action.host;
  targets.setAttribute('aria-label', 'Targets, comma-separated');
  const until = el('input');
  until.placeholder = 'default: a week after the data';
  until.setAttribute('aria-label', 'Valid until');
  const l1 = el('label', null, 'Targets (comma-separated)');
  l1.append(targets);
  const l2 = el('label', null, 'Valid until');
  l2.append(until);
  const button = el('button', null, 'Check');
  button.type = 'submit';
  form.append(l1, l2, button);
  const out = el('div', 'scope-result');
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    button.disabled = true;
    try {
      const r = await post(`/demo/incidents/${encodeURIComponent(incident.id)}/scope-check`,
        { targets: targets.value, valid_until: until.value === '' ? null : until.value });
      const line = el('p', `chain ${r.effect === 'allow' ? 'ok' : 'bad'}`);
      line.append(el('span', 'code', `${r.effect.toUpperCase()} ${r.reason_code}`), document.createTextNode(` — ${r.problems.length ? r.problems.join('; ') : r.message}`));
      out.replaceChildren(line);
    } catch (error) {
      out.replaceChildren(el('p', 'chain bad', `Request failed: ${error.message}`));
    } finally {
      button.disabled = false;
    }
  });
  wrap.append(form, out);
  return wrap;
}

// ---------------------------------------------------------------- summary
function fillVersus() {
  const h = S.headline, tr = S.triage;
  $('caught').textContent = `${h.detected} of ${h.episodes}`;
  $('miss').textContent = `${pct(h.miss_rate)} (95 % CI ${pct(h.miss_rate_ci95[0])}–${pct(h.miss_rate_ci95[1])})`;
  $('precision').textContent = h.precision.toFixed(2);
  $('b1').textContent = fmt(h.b1_incidents);
  $('b1-miss').textContent = pct(h.b1_miss_rate);
  const note = $('versus').querySelector('.triage') || el('p', 'muted triage');
  note.textContent = `Claude (${tr.model}) then dismisses ${tr.benign_dismissed} of ${tr.benign_incidents} false alarms and ${tr.attacks_dismissed} of ${tr.attack_incidents} attacks, at about $${tr.usd_per_incident.toFixed(3)} per incident.`;
  $('versus').append(note);
}

function fillMissed() {
  const h = S.headline;
  const missed = S.missed;
  const silent = missed.filter((m) => !m.raised_an_alert).length;
  const others = missed.filter((m) => m.raised_an_alert);
  $('missed-summary').textContent = `${missed.length} of ${h.episodes} attacks were not caught. ${silent} never raised a single alert: the detection rules did not fire, so nothing after them could see those attacks. That is the rule layer's limit, not the reduction's.`;
  const body = $('scenarios');
  for (const [name, row] of Object.entries(S.by_scenario)) {
    const tr = el('tr');
    tr.append(el('td', null, name.replaceAll('_', ' ')), el('td', 'num', row.episodes), el('td', 'num', row.raised_an_alert), el('td', 'num', row['detected_tau_0.5']));
    tr.lastChild.classList.toggle('short', row['detected_tau_0.5'] < row.episodes);
    body.append(tr);
  }
  $('missed-note').textContent = others.map((m) => m.closest_incident
    ? `${m.id} (${m.scenario.replaceAll('_', ' ')}) did raise alerts; the incident holding most of them, ${m.closest_incident.id}, scored ${m.closest_incident.score}${m.closest_incident.surfaced ? ' and was surfaced but held under half of its alerts' : ` and stayed under the threshold of ${S.scoring.threshold}`}.`
    : `${m.id} raised alerts that no incident held.`).join(' ');
}

load().catch((error) => {
  document.querySelector('main').prepend(el('p', 'chain bad', `Could not load the demo data: ${error.message}`));
});
