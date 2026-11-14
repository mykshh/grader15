'use strict';

/*
 * Grader — учёт оценок с авторизацией по почте/паролю.
 * Хранение в PostgreSQL (Neon). Логирование заходов.
 * Запуск: node server.js  (нужна переменная окружения DATABASE_URL)
 */

const http = require('http');
const crypto = require('crypto');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const SESSION_TTL = 1000 * 60 * 60 * 24 * 7; // 7 дней

if (!process.env.DATABASE_URL) {
  console.error('Не задана переменная DATABASE_URL (строка подключения к Neon Postgres).');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Секрет для подписи сессий выводим из строки БД — стабилен между перезапусками.
const SECRET = crypto.createHash('sha256').update(process.env.DATABASE_URL).digest('hex');

// ---------- инициализация таблиц ----------
async function initDB() {
  await pool.query(`CREATE TABLE IF NOT EXISTS users (
    email TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    password_plain TEXT,
    created TIMESTAMPTZ DEFAULT now()
  )`);
  // на случай уже созданной таблицы — добавить колонку, если её нет
  await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_plain TEXT');
  await pool.query(`CREATE TABLE IF NOT EXISTS grades (
    id SERIAL PRIMARY KEY,
    email TEXT NOT NULL,
    subject TEXT,
    percent INT,
    credits INT
  )`);
  await pool.query(`CREATE TABLE IF NOT EXISTS logs (
    id SERIAL PRIMARY KEY,
    ts TIMESTAMPTZ DEFAULT now(),
    ip TEXT, method TEXT, url TEXT, email TEXT, ua TEXT
  )`);
}

// ---------- пароли ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return salt + ':' + hash;
}
function verifyPassword(password, stored) {
  const [salt, hash] = (stored || '').split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(test, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------- сессии ----------
function sign(v) { return crypto.createHmac('sha256', SECRET).update(v).digest('hex'); }
function makeSession(email) {
  const b64 = Buffer.from(JSON.stringify({ email, exp: Date.now() + SESSION_TTL })).toString('base64');
  return b64 + '.' + sign(b64);
}
function readSession(cookieHeader) {
  const sid = parseCookies(cookieHeader).sid;
  if (!sid) return null;
  const [b64, sig] = sid.split('.');
  if (!b64 || !sig || sign(b64) !== sig) return null;
  try {
    const d = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
    return (d.exp && d.exp > Date.now()) ? d.email : null;
  } catch (e) { return null; }
}
function parseCookies(h) {
  const out = {};
  if (!h) return out;
  h.split(';').forEach(p => { const i = p.indexOf('='); if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return out;
}

// ---------- логирование ----------
function clientIP(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return xff.split(',')[0].trim();
  return (req.socket.remoteAddress || '').replace('::ffff:', '');
}
function log(req, email) {
  const ip = clientIP(req);
  const ua = (req.headers['user-agent'] || '-').slice(0, 300);
  console.log(`${new Date().toISOString()} ${ip} ${req.method} ${req.url} ${email || '-'}`);
  pool.query('INSERT INTO logs(ip,method,url,email,ua) VALUES($1,$2,$3,$4,$5)',
    [ip, req.method, req.url, email, ua]).catch(() => {});
}

// ---------- GPA (шкала АУЭС / KZ) ----------
function toGPA(p) {
  p = Number(p);
  if (p >= 95) return { letter: 'A', gpa: 4.00 };
  if (p >= 90) return { letter: 'A-', gpa: 3.67 };
  if (p >= 85) return { letter: 'B+', gpa: 3.33 };
  if (p >= 80) return { letter: 'B', gpa: 3.00 };
  if (p >= 75) return { letter: 'B-', gpa: 2.67 };
  if (p >= 70) return { letter: 'C+', gpa: 2.33 };
  if (p >= 65) return { letter: 'C', gpa: 2.00 };
  if (p >= 60) return { letter: 'C-', gpa: 1.67 };
  if (p >= 55) return { letter: 'D+', gpa: 1.33 };
  if (p >= 50) return { letter: 'D', gpa: 1.00 };
  return { letter: 'F', gpa: 0.00 };
}

// ---------- утилиты ----------
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function body(req) {
  return new Promise(resolve => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > 1e6) req.destroy(); });
    req.on('end', () => resolve(parseForm(d)));
  });
}
function parseForm(str) {
  const out = {};
  if (!str) return out;
  str.split('&').forEach(p => {
    const i = p.indexOf('=');
    const k = decodeURIComponent((i > -1 ? p.slice(0, i) : p).replace(/\+/g, ' '));
    out[k] = i > -1 ? decodeURIComponent(p.slice(i + 1).replace(/\+/g, ' ')) : '';
  });
  return out;
}
function send(res, status, html, headers) {
  res.writeHead(status, Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, headers || {}));
  res.end(html);
}
function redirect(res, location, cookie) {
  const h = { Location: location };
  if (cookie) h['Set-Cookie'] = cookie;
  res.writeHead(302, h); res.end();
}

// ---------- стили ----------
const CSS = `
  :root{--bg:#f4f6f9;--panel:#fff;--ink:#1a2230;--muted:#6b7585;--line:#e3e8ef;
        --brand:#1f6feb;--brand-d:#1559c4;--ok:#1a7f4b;--err:#c23b3b;}
  *{box-sizing:border-box;margin:0;padding:0;}
  body{font-family:-apple-system,"Segoe UI",Roboto,Arial,sans-serif;background:var(--bg);color:var(--ink);min-height:100vh;}
  .bar{background:var(--panel);border-bottom:1px solid var(--line);padding:0 22px;height:56px;
       display:flex;align-items:center;justify-content:space-between;}
  .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px;letter-spacing:-.02em;}
  .brand .dot{width:26px;height:26px;border-radius:7px;background:var(--brand);color:#fff;
       display:flex;align-items:center;justify-content:center;font-size:15px;font-weight:700;}
  .bar .right{font-size:14px;color:var(--muted);display:flex;align-items:center;gap:16px;}
  .bar a{color:var(--muted);text-decoration:none;}
  .bar a:hover{color:var(--brand);}
  .wrap{max-width:760px;margin:0 auto;padding:26px 18px;}
  .center{min-height:calc(100vh - 56px);display:flex;align-items:center;justify-content:center;padding:20px;}
  .login{width:100%;max-width:400px;}
  .login .head{text-align:center;margin-bottom:22px;}
  .login .head .dot{width:46px;height:46px;border-radius:12px;font-size:24px;margin:0 auto 12px;}
  .login .head h1{font-size:20px;}
  .login .head p{color:var(--muted);font-size:14px;margin-top:4px;}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:24px;
         box-shadow:0 1px 3px rgba(20,30,50,.04);}
  h1{font-size:20px;font-weight:700;}
  h2{font-size:13px;color:var(--muted);margin:24px 0 10px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;}
  label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px;font-weight:500;}
  input{width:100%;background:#fff;border:1px solid var(--line);border-radius:9px;padding:11px 13px;
        color:var(--ink);font-size:15px;}
  input:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 3px rgba(31,111,235,.12);}
  button{background:var(--brand);color:#fff;border:none;border-radius:9px;padding:11px 20px;
         font-size:15px;font-weight:600;cursor:pointer;}
  button:hover{background:var(--brand-d);}
  .full{width:100%;margin-top:18px;}
  .msg{padding:10px 13px;border-radius:9px;font-size:14px;margin-bottom:14px;}
  .msg.err{background:#fdecec;color:var(--err);border:1px solid #f6cccc;}
  .foot{text-align:center;margin-top:16px;font-size:14px;color:var(--muted);}
  .link{color:var(--brand);text-decoration:none;font-weight:500;}
  .stat{text-align:center;padding:26px;}
  .stat .big{font-size:44px;font-weight:800;letter-spacing:-.02em;color:var(--brand);}
  .stat .sub{color:var(--muted);font-size:14px;margin-top:4px;}
  table{width:100%;border-collapse:collapse;font-size:14px;}
  th,td{text-align:left;padding:11px 10px;border-bottom:1px solid var(--line);}
  th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em;}
  td.n,th.n{text-align:right;font-variant-numeric:tabular-nums;}
  tr:last-child td{border-bottom:none;}
  .rowform{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:10px;align-items:end;}
  .rowform button{padding:11px 16px;}
  .del{background:transparent;border:1px solid var(--line);color:var(--muted);padding:5px 11px;
       font-size:15px;border-radius:7px;line-height:1;}
  .del:hover{color:var(--err);border-color:var(--err);background:#fff;}
  .ip{font-size:13px;color:var(--muted);}
  .ip b{color:var(--ink);font-variant-numeric:tabular-nums;}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;}
  @media(max-width:520px){.rowform{grid-template-columns:1fr 1fr;}}
`;

// ---------- стили страницы входа (под образец Platonus / АУЭС) ----------
const AUTH_CSS = `
  .pl-body{background:#edeef2;min-height:100vh;display:flex;flex-direction:column;
           align-items:center;justify-content:flex-start;padding:46px 16px 28px;}
  .pl-card{width:100%;max-width:446px;background:#fff;border-radius:10px;
           box-shadow:0 2px 14px rgba(28,40,64,.09);padding:34px 40px 30px;}
  .pl-logo{display:flex;align-items:center;gap:13px;margin-bottom:26px;}
  .pl-logo svg{flex:none;}
  .pl-logo .lt1{font-size:11px;color:#2aa39a;font-weight:600;letter-spacing:.01em;margin-bottom:1px;}
  .pl-logo .lt2{font-size:25px;line-height:1.02;font-weight:800;letter-spacing:-.01em;}
  .pl-logo .lt2 .en{color:#2f8f6e;} .pl-logo .lt2 .un{color:#6a3b8f;}
  .pl-title{font-size:21px;font-weight:700;color:#303a4a;line-height:1.25;margin-bottom:20px;}
  .pl-lab{display:block;font-size:11px;font-weight:700;color:#5a6472;
          text-transform:uppercase;letter-spacing:.04em;margin:16px 0 7px;}
  .pl-labrow{display:flex;justify-content:space-between;align-items:baseline;margin:16px 0 7px;}
  .pl-labrow .pl-lab{margin:0;}
  .pl-forgot{font-size:13px;color:#c8102e;text-decoration:none;font-weight:500;}
  .pl-forgot:hover{text-decoration:underline;}
  .pl-input{width:100%;background:#fff;border:1px solid #d3d8e0;border-radius:7px;
            padding:11px 13px;font-size:15px;color:#1f2733;font-family:inherit;}
  .pl-input:focus{outline:none;border-color:#c8102e;box-shadow:0 0 0 3px rgba(200,16,46,.10);}
  select.pl-input{appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%236b7585' stroke-width='1.6' fill='none' stroke-linecap='round'/%3E%3C/svg%3E");
                   background-repeat:no-repeat;background-position:right 14px center;padding-right:34px;cursor:pointer;}
  .pl-pass{position:relative;}
  .pl-pass .pl-input{padding-right:42px;}
  .pl-eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;
          border:none;padding:6px;cursor:pointer;color:#8a93a1;display:flex;}
  .pl-eye:hover{color:#5a6472;}
  .pl-btn{width:100%;margin-top:20px;background:#c8102e;color:#fff;border:none;border-radius:7px;
          padding:13px;font-size:15px;font-weight:600;cursor:pointer;font-family:inherit;}
  .pl-btn:hover{background:#a90e27;}
  .pl-msg{background:#fdecec;color:#c23b3b;border:1px solid #f6cccc;border-radius:7px;
          padding:10px 13px;font-size:14px;margin-bottom:4px;}
  .pl-div{display:flex;align-items:center;text-align:center;gap:14px;margin:22px 0 16px;
          color:#8a93a1;font-size:13px;}
  .pl-div::before,.pl-div::after{content:"";flex:1;height:1px;background:#e3e8ef;}
  .pl-reg{text-align:center;}
  .pl-reg a{color:#c8102e;text-decoration:none;font-size:15px;font-weight:500;}
  .pl-reg a:hover{text-decoration:underline;}
  .pl-sub{text-align:center;color:#6b7585;font-size:13px;margin:26px 0 12px;}
  .pl-stores{display:flex;justify-content:center;gap:12px;}
  .pl-store{display:inline-flex;align-items:center;gap:7px;background:#20283a;color:#fff;
            text-decoration:none;border-radius:7px;padding:9px 16px;font-size:13px;font-weight:600;}
  .pl-store:hover{background:#2b3550;}
  .pl-store svg{flex:none;}
  .pl-foot{text-align:center;color:#8a93a1;font-size:12px;margin-top:20px;}
  .pl-foot b{color:#c8102e;font-weight:600;}
  @media(max-width:480px){.pl-card{padding:26px 22px;}}
`;

function page(title, inner) {
  return `<!DOCTYPE html><html lang="ru"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Grader</title><style>${CSS}</style></head><body>${inner}</body></html>`;
}
function topbar(email) {
  return `<div class="bar">
    <div class="brand"><span class="dot">G</span>Grader</div>
    <div class="right">${email ? `<span>${esc(email)}</span><a href="/logout">Выйти</a>` : ''}</div>
  </div>`;
}

// ---------- страницы ----------
// логотип Energo University (стилизованный, в виде inline-SVG)
const LOGO = `
  <svg width="58" height="52" viewBox="0 0 58 52" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
    <defs><linearGradient id="eg" x1="0" y1="1" x2="1" y2="0">
      <stop offset="0" stop-color="#27a39a"/><stop offset=".5" stop-color="#2f8f6e"/><stop offset="1" stop-color="#6a3b8f"/>
    </linearGradient></defs>
    <polygon points="29,3 6,49 19,49 29,28" fill="url(#eg)"/>
    <polygon points="29,3 52,49 39,49 29,28" fill="url(#eg)" opacity=".82"/>
    <polygon points="20,33 38,33 34,41 24,41" fill="url(#eg)"/>
  </svg>`;
const EYE = `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/><path d="M3 3l18 18"/></svg>`;
const APPLE = `<svg width="15" height="15" viewBox="0 0 24 24" fill="#fff"><path d="M16.3 12.9c0-2.3 1.9-3.4 2-3.5-1.1-1.6-2.8-1.8-3.4-1.8-1.4-.1-2.8.8-3.5.8-.7 0-1.8-.8-3-.8-1.5 0-2.9.9-3.7 2.3-1.6 2.7-.4 6.8 1.1 9 .7 1.1 1.6 2.3 2.7 2.2 1.1 0 1.5-.7 2.8-.7s1.6.7 2.8.7c1.1 0 1.9-1.1 2.6-2.1.8-1.2 1.1-2.3 1.2-2.4-.1 0-2.3-.9-2.3-3.4zM14.4 6.1c.6-.7 1-1.7.9-2.7-.9 0-1.9.6-2.5 1.3-.5.6-1 1.6-.9 2.6 1 .1 1.9-.5 2.5-1.2z"/></svg>`;
const PLAY = `<svg width="14" height="14" viewBox="0 0 24 24" fill="#fff"><path d="M4 2.5v19l15-9.5z"/></svg>`;

function authPage(mode, error) {
  const isLogin = mode === 'login';
  const inner = `<style>${AUTH_CSS}</style>
  <div class="pl-body">
    <div class="pl-card">
      <div class="pl-logo">${LOGO}
        <div><div class="lt1">Gumarbek Daukeyev</div>
          <div class="lt2"><span class="en">Energo</span><br><span class="un">University</span></div></div>
      </div>
      <div class="pl-title">${isLogin ? 'Войти в личный кабинет<br>АУЭС' : 'Регистрация нового<br>аккаунта'}</div>
      ${error ? `<div class="pl-msg">${esc(error)}</div>` : ''}
      <form method="POST" action="/${isLogin ? 'login' : 'register'}">
        <select class="pl-input" aria-label="Язык">
          <option>Русский</option><option>Қазақша</option><option>English</option>
        </select>
        <label class="pl-lab">Логин</label>
        <input class="pl-input" type="email" name="email" required autocomplete="email" placeholder="you@aues.kz">
        <div class="pl-labrow"><label class="pl-lab">Пароль</label>
          ${isLogin ? '<a class="pl-forgot" href="#">Забыли пароль?</a>' : ''}</div>
        <div class="pl-pass">
          <input class="pl-input" type="password" name="password" required minlength="6" autocomplete="${isLogin ? 'current-password' : 'new-password'}">
          <button type="button" class="pl-eye" aria-label="Показать пароль"
            onclick="var i=this.parentNode.querySelector('input');i.type=i.type==='password'?'text':'password';">${EYE}</button>
        </div>
        <button type="submit" class="pl-btn">${isLogin ? 'Войти' : 'Создать аккаунт'}</button>
      </form>
      <div class="pl-div">Дополнительно</div>
      <div class="pl-reg"><a href="/${isLogin ? 'register' : 'login'}">${isLogin ? 'Регистрация абитуриентов' : 'Войти'}</a></div>
    </div>
    <div class="pl-sub">Установите мобильное приложение</div>
    <div class="pl-stores">
      <a class="pl-store" href="#">${APPLE} App Store</a>
      <a class="pl-store" href="#">${PLAY} Google Play</a>
    </div>
    <div class="pl-foot">©Grader v2.0, 2026 · учебный проект АУЭС</div>
  </div>`;
  return page(isLogin ? 'Вход' : 'Регистрация', inner);
}

async function dashboard(email, req) {
  const r = await pool.query('SELECT id,subject,percent,credits FROM grades WHERE email=$1 ORDER BY id', [email]);
  const list = r.rows;
  let totalCr = 0, weighted = 0;
  const rows = list.map(g => {
    const { letter, gpa } = toGPA(g.percent);
    const cr = Number(g.credits) || 0;
    totalCr += cr; weighted += gpa * cr;
    return `<tr>
      <td>${esc(g.subject)}</td>
      <td class="n">${esc(g.percent)}</td>
      <td class="n">${letter}</td>
      <td class="n">${gpa.toFixed(2)}</td>
      <td class="n">${esc(g.credits)}</td>
      <td class="n"><form method="POST" action="/grade/delete" style="margin:0">
        <input type="hidden" name="id" value="${g.id}">
        <button class="del" type="submit">×</button></form></td>
    </tr>`;
  }).join('');
  const gpaAll = totalCr > 0 ? weighted / totalCr : 0;

  return page('Мои оценки', topbar(email) + `
  <div class="wrap">
    <div class="panel stat">
      <div class="big">${gpaAll.toFixed(2)}</div>
      <div class="sub">Общий GPA · ${list.length} предм. · ${totalCr} кредитов</div>
    </div>

    <h2>Добавить оценку</h2>
    <div class="panel">
      <form method="POST" action="/grade/add" class="rowform">
        <div><label>Предмет</label><input name="subject" required></div>
        <div><label>Процент 0–100</label><input name="percent" type="number" min="0" max="100" required></div>
        <div><label>Кредиты</label><input name="credits" type="number" min="0" step="1" value="3" required></div>
        <button type="submit">Добавить</button>
      </form>
    </div>

    <h2>Мои оценки</h2>
    <div class="panel">
      ${list.length ? `<table>
        <thead><tr><th>Предмет</th><th class="n">%</th><th class="n">Буква</th><th class="n">GPA</th><th class="n">Кр.</th><th></th></tr></thead>
        <tbody>${rows}</tbody></table>`
      : '<p style="color:var(--muted);font-size:14px">Пока пусто. Добавьте первую оценку выше.</p>'}
    </div>
  </div>`);
}

// ---------- роутинг ----------
const server = http.createServer(async (req, res) => {
  const url = req.url.split('?')[0];
  const email = readSession(req.headers.cookie);
  log(req, email);

  try {
    if (req.method === 'GET' && url === '/login') return send(res, 200, authPage('login'));
    if (req.method === 'GET' && url === '/register') return send(res, 200, authPage('register'));

    if (req.method === 'POST' && url === '/register') {
      const f = await body(req);
      const em = (f.email || '').trim().toLowerCase();
      const pw = f.password || '';
      if (!em || pw.length < 6) return send(res, 400, authPage('register', 'Проверьте почту и пароль (от 6 символов).'));
      const exists = await pool.query('SELECT 1 FROM users WHERE email=$1', [em]);
      if (exists.rowCount) return send(res, 400, authPage('register', 'Такая почта уже зарегистрирована.'));
      await pool.query('INSERT INTO users(email,password,password_plain) VALUES($1,$2,$3)', [em, hashPassword(pw), pw]);
      return redirect(res, '/', `sid=${makeSession(em)}; HttpOnly; Path=/; Max-Age=${SESSION_TTL / 1000}; SameSite=Lax`);
    }

    if (req.method === 'POST' && url === '/login') {
      const f = await body(req);
      const em = (f.email || '').trim().toLowerCase();
      const pw = f.password || '';
      const r = await pool.query('SELECT password FROM users WHERE email=$1', [em]);
      if (!r.rowCount || !verifyPassword(pw, r.rows[0].password))
        return send(res, 401, authPage('login', 'Неверная почта или пароль.'));
      return redirect(res, '/', `sid=${makeSession(em)}; HttpOnly; Path=/; Max-Age=${SESSION_TTL / 1000}; SameSite=Lax`);
    }

    if (url === '/logout') return redirect(res, '/login', 'sid=; HttpOnly; Path=/; Max-Age=0');

    if (!email) return redirect(res, '/login');

    if (req.method === 'POST' && url === '/grade/add') {
      const f = await body(req);
      await pool.query('INSERT INTO grades(email,subject,percent,credits) VALUES($1,$2,$3,$4)', [
        email, (f.subject || '').slice(0, 100),
        Math.max(0, Math.min(100, Number(f.percent) || 0)),
        Math.max(0, Number(f.credits) || 0)
      ]);
      return redirect(res, '/');
    }

    if (req.method === 'POST' && url === '/grade/delete') {
      const f = await body(req);
      await pool.query('DELETE FROM grades WHERE id=$1 AND email=$2', [Number(f.id), email]);
      return redirect(res, '/');
    }

    if (req.method === 'GET' && url === '/') return send(res, 200, await dashboard(email, req));

    send(res, 404, page('404', topbar(email) + '<div class="wrap"><h1>Страница не найдена</h1><p class="foot"><a class="link" href="/">На главную</a></p></div>'));
  } catch (e) {
    console.error(e);
    send(res, 500, page('Ошибка', '<div class="wrap"><h1>Ошибка сервера</h1></div>'));
  }
});

initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`Grader запущен: http://localhost:${PORT}`);
  });
}).catch(e => {
  console.error('Не удалось подключиться к базе:', e.message);
  process.exit(1);
});
