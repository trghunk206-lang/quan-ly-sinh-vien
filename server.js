'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { open, tx, readAll, sanitizeImport, importAll, demoData } = require('./db');
const { hashPassword, verifyPassword, randomPassword, dummyHash } = require('./auth');

const PUBLIC = path.join(__dirname, 'public');
const SESSION_TTL = 8 * 3600 * 1000;
const LOGIN_WINDOW = 15 * 60 * 1000;
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.png': 'image/png', '.json': 'application/json; charset=utf-8',
};

class HttpError extends Error {
  constructor(status, message, code) { super(message); this.status = status; this.code = code; }
}
const bad = (msg) => new HttpError(400, msg);

/* ---------- Kiểm tra dữ liệu vào ---------- */
function reqStr(v, label, max) {
  if (typeof v !== 'string' || !v.trim()) throw bad(label + ' không được để trống.');
  const s = v.trim();
  if (s.length > max) throw bad(label + ' quá dài (tối đa ' + max + ' ký tự).');
  return s;
}
function optStr(v, label, max) {
  if (v == null || v === '') return '';
  if (typeof v !== 'string') throw bad(label + ' không hợp lệ.');
  const s = v.trim();
  if (s.length > max) throw bad(label + ' quá dài (tối đa ' + max + ' ký tự).');
  return s;
}
function reqNum(v, label, min, max) {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < min || v > max) throw bad(label + ' phải là số từ ' + min + ' đến ' + max + '.');
  return v;
}
function checkPassword(pw, username) {
  if (typeof pw !== 'string' || pw.length < 8) throw bad('Mật khẩu phải có ít nhất 8 ký tự.');
  if (pw.length > 128) throw bad('Mật khẩu quá dài (tối đa 128 ký tự).');
  if (username && pw.toLowerCase() === String(username).toLowerCase()) throw bad('Mật khẩu không được trùng tên đăng nhập.');
}
function studentFields(b, db) {
  const maSV = reqStr(b.maSV, 'Mã sinh viên', 30);
  if (!/^[A-Za-z0-9._-]+$/.test(maSV)) throw bad('Mã sinh viên chỉ gồm chữ, số và các ký tự . _ -');
  const hoTen = reqStr(b.hoTen, 'Họ tên', 100);
  if (b.gioiTinh !== 'Nam' && b.gioiTinh !== 'Nữ') throw bad('Giới tính không hợp lệ.');
  const lopIn = reqStr(b.lop, 'Lớp', 30);
  const lop = db.prepare('SELECT ma FROM classes WHERE ma = ?').get(lopIn);
  if (!lop) throw bad('Lớp "' + lopIn + '" không tồn tại.');
  const email = optStr(b.email, 'Email', 120);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw bad('Email không hợp lệ.');
  const sdt = optStr(b.sdt, 'Số điện thoại', 20);
  if (sdt && !/^(0|\+84)\d{9}$/.test(sdt)) throw bad('Số điện thoại không hợp lệ (ví dụ 0901234567).');
  return { maSV, hoTen, gioiTinh: b.gioiTinh, lop: lop.ma, email, sdt };
}
function termFields(b) {
  const ten = reqStr(b.ten, 'Tên học kỳ', 60);
  const nam = reqStr(b.nam, 'Năm học', 20);
  if (!/^\d{4}-\d{4}$/.test(nam)) throw bad('Năm học phải có dạng 2025-2026.');
  return { ten, nam };
}
function subjectFields(b) {
  const ten = reqStr(b.ten, 'Tên môn học', 120);
  const tc = reqNum(b.tc, 'Số tín chỉ', 1, 10);
  if (!Number.isInteger(tc)) throw bad('Số tín chỉ phải là số nguyên.');
  return { ten, tc };
}

async function createApp(opts = {}) {
  const env = process.env;
  const cfg = {
    dbFile: opts.dbFile ?? path.join(env.DATA_DIR || path.join(__dirname, 'data'), 'qlsv.sqlite'),
    secureCookie: opts.secureCookie ?? (env.COOKIE_SECURE ? env.COOKIE_SECURE === '1' : env.NODE_ENV === 'production'),
    trustProxy: opts.trustProxy ?? env.TRUST_PROXY === '1',
    adminUsername: (opts.adminUsername ?? env.ADMIN_USERNAME ?? 'admin').trim().toLowerCase(),
    adminPassword: opts.adminPassword ?? env.ADMIN_PASSWORD ?? '',
  };
  const db = open(cfg.dbFile);
  const now = () => Date.now();

  /* ---------- Tạo admin lần đầu ---------- */
  let bootstrap = null;
  if (db.prepare('SELECT COUNT(*) AS n FROM users').get().n === 0) {
    if (!/^[a-z0-9._-]{3,32}$/.test(cfg.adminUsername)) throw new Error('ADMIN_USERNAME không hợp lệ (3–32 ký tự: chữ thường, số, . _ -).');
    const generated = !cfg.adminPassword;
    const password = cfg.adminPassword || randomPassword(16);
    checkPassword(password, cfg.adminUsername);
    db.prepare('INSERT INTO users(username, full_name, role, pass_hash, must_change, created_at) VALUES(?, ?, ?, ?, ?, ?)')
      .run(cfg.adminUsername, 'Quản trị viên', 'admin', await hashPassword(password), generated ? 1 : 0, now());
    bootstrap = { username: cfg.adminUsername, password: generated ? password : null };
  }

  /* ---------- Phiên đăng nhập ---------- */
  const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');
  function newSession(userId) {
    const token = crypto.randomBytes(32).toString('base64url');
    db.prepare('INSERT INTO sessions(token_hash, user_id, expires_at) VALUES(?, ?, ?)').run(sha(token), userId, now() + SESSION_TTL);
    return token;
  }
  function getCookie(req, name) {
    const h = req.headers.cookie;
    if (!h) return null;
    for (const part of h.split(';')) {
      const i = part.indexOf('=');
      if (i > 0 && part.slice(0, i).trim() === name) {
        try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return null; }
      }
    }
    return null;
  }
  function setCookie(res, token, maxAgeSec) {
    let c = 'sid=' + (token || '') + '; Path=/; HttpOnly; SameSite=Strict; Max-Age=' + maxAgeSec;
    if (cfg.secureCookie) c += '; Secure';
    res.setHeader('Set-Cookie', c);
  }
  const userDto = (u) => ({ id: u.id, username: u.username, fullName: u.full_name, role: u.role, maSV: u.ma_sv, mustChange: !!u.must_change });
  function sessionUser(req) {
    const token = getCookie(req, 'sid');
    if (!token) return null;
    const row = db.prepare('SELECT u.id, u.username, u.full_name, u.role, u.ma_sv, u.must_change, u.active, s.expires_at FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?').get(sha(token));
    if (!row) return null;
    if (row.expires_at < now() || !row.active) {
      db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(token));
      return null;
    }
    return { ...row, _token: token };
  }
  const cleanup = setInterval(() => {
    db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now());
    const t = now();
    for (const [k, v] of fails) if (t - v.first > LOGIN_WINDOW) fails.delete(k);
  }, 3600 * 1000);
  cleanup.unref();

  /* ---------- Giới hạn đăng nhập sai ---------- */
  const fails = new Map();
  const blocked = (key, max) => {
    const r = fails.get(key);
    if (!r) return false;
    if (now() - r.first > LOGIN_WINDOW) { fails.delete(key); return false; }
    return r.n >= max;
  };
  const addFail = (key) => {
    const r = fails.get(key);
    if (!r || now() - r.first > LOGIN_WINDOW) fails.set(key, { n: 1, first: now() });
    else r.n++;
  };
  function clientIp(req) {
    if (cfg.trustProxy) {
      const xf = req.headers['x-forwarded-for'];
      if (typeof xf === 'string' && xf) {
        const parts = xf.split(',').map((s) => s.trim()).filter(Boolean);
        if (parts.length) return parts[parts.length - 1];
      }
    }
    return req.socket.remoteAddress || '?';
  }

  /* ---------- Đường dẫn API ---------- */
  const routes = [];
  function route(method, pattern, options, handler) {
    const keys = [];
    const rx = new RegExp('^' + pattern.replace(/:([a-z]+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '$');
    routes.push({ method, rx, keys, ...options, handler });
  }
  const STAFF = ['admin', 'teacher'];
  const ADMIN = ['admin'];
  const exists = (sql, ...a) => !!db.prepare(sql).get(...a);
  const notFound = (what) => new HttpError(404, what + ' không tồn tại.');

  // --- Tài khoản của chính mình
  route('POST', '/api/login', { auth: 'none' }, async ({ body, res, ip }) => {
    const username = typeof body.username === 'string' ? body.username.trim().toLowerCase() : '';
    const password = typeof body.password === 'string' ? body.password : '';
    const uKey = 'u:' + ip + '|' + username, iKey = 'i:' + ip;
    if (blocked(uKey, 5) || blocked(iKey, 30)) throw new HttpError(429, 'Đăng nhập sai quá nhiều lần. Vui lòng thử lại sau 15 phút.');
    const row = username.length <= 64 ? db.prepare('SELECT * FROM users WHERE username = ?').get(username) : undefined;
    let ok = false;
    if (password.length > 0 && password.length <= 200) {
      ok = row ? await verifyPassword(password, row.pass_hash) : (await verifyPassword(password, await dummyHash()), false);
    }
    if (!ok || !row.active) {
      addFail(uKey); addFail(iKey);
      throw new HttpError(401, 'Sai tên đăng nhập hoặc mật khẩu.');
    }
    fails.delete(uKey);
    setCookie(res, newSession(row.id), SESSION_TTL / 1000);
    return { user: userDto(row) };
  });
  route('POST', '/api/logout', { auth: 'none' }, ({ req, res }) => {
    const t = getCookie(req, 'sid');
    if (t) db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(sha(t));
    setCookie(res, '', 0);
    return { ok: true };
  });
  route('GET', '/api/me', { allowMustChange: true }, ({ user }) => ({ user: userDto(user) }));
  route('POST', '/api/change-password', { allowMustChange: true }, async ({ body, user }) => {
    const cur = db.prepare('SELECT pass_hash FROM users WHERE id = ?').get(user.id);
    if (typeof body.current !== 'string' || !(await verifyPassword(body.current, cur.pass_hash))) throw new HttpError(400, 'Mật khẩu hiện tại không đúng.');
    checkPassword(body.next, user.username);
    if (body.next === body.current) throw bad('Mật khẩu mới phải khác mật khẩu hiện tại.');
    db.prepare('UPDATE users SET pass_hash = ?, must_change = 0 WHERE id = ?').run(await hashPassword(body.next), user.id);
    db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').run(user.id, sha(user._token));
    return { user: userDto({ ...user, must_change: 0 }) };
  });

  // --- Đọc dữ liệu
  route('GET', '/api/data', {}, ({ user }) => readAll(db, user.role === 'student' ? (user.ma_sv || '\u0000') : null));

  // --- Sinh viên
  route('POST', '/api/students', { roles: STAFF }, ({ body }) => {
    const s = studentFields(body, db);
    if (exists('SELECT 1 FROM students WHERE ma_sv = ?', s.maSV)) throw new HttpError(409, 'Mã sinh viên "' + s.maSV + '" đã tồn tại.');
    db.prepare('INSERT INTO students(ma_sv, ho_ten, gioi_tinh, lop, email, sdt) VALUES(?, ?, ?, ?, ?, ?)').run(s.maSV, s.hoTen, s.gioiTinh, s.lop, s.email, s.sdt);
    return [201, { ok: true }];
  });
  route('PUT', '/api/students/:ma', { roles: STAFF }, ({ params, body }) => {
    const cur = db.prepare('SELECT ma_sv FROM students WHERE ma_sv = ?').get(params.ma);
    if (!cur) throw notFound('Sinh viên');
    const s = studentFields({ ...body, maSV: cur.ma_sv }, db);
    db.prepare('UPDATE students SET ho_ten = ?, gioi_tinh = ?, lop = ?, email = ?, sdt = ? WHERE ma_sv = ?').run(s.hoTen, s.gioiTinh, s.lop, s.email, s.sdt, cur.ma_sv);
    return { ok: true };
  });
  route('DELETE', '/api/students/:ma', { roles: STAFF }, ({ params }) => {
    const r = db.prepare('DELETE FROM students WHERE ma_sv = ?').run(params.ma);
    if (!r.changes) throw notFound('Sinh viên');
    return { ok: true };
  });
  route('PUT', '/api/students/:ma/scores', { roles: STAFF }, ({ params, body }) => {
    const st = db.prepare('SELECT ma_sv FROM students WHERE ma_sv = ?').get(params.ma);
    if (!st) throw notFound('Sinh viên');
    if (!Array.isArray(body.diem) || body.diem.length > 1000) throw bad('Dữ liệu điểm không hợp lệ.');
    const seen = new Set();
    const rows = body.diem.map((d) => {
      if (!d || typeof d.subjId !== 'string' || seen.has(d.subjId)) throw bad('Dữ liệu điểm không hợp lệ.');
      seen.add(d.subjId);
      if (!exists('SELECT 1 FROM subjects WHERE id = ?', d.subjId)) throw bad('Có môn học không tồn tại.');
      return [d.subjId, reqNum(d.qt, 'Điểm quá trình', 0, 10), reqNum(d.thi, 'Điểm thi', 0, 10)];
    });
    tx(db, () => {
      db.prepare('DELETE FROM scores WHERE ma_sv = ?').run(st.ma_sv);
      const ins = db.prepare('INSERT INTO scores(ma_sv, subject_id, qt, thi) VALUES(?, ?, ?, ?)');
      for (const r of rows) ins.run(st.ma_sv, r[0], r[1], r[2]);
    });
    return { ok: true };
  });

  // --- Lớp học
  route('POST', '/api/classes', { roles: STAFF }, ({ body }) => {
    const ma = reqStr(body.ma, 'Mã lớp', 30).toUpperCase();
    if (!/^[A-Z0-9._-]+$/.test(ma)) throw bad('Mã lớp chỉ gồm chữ, số và các ký tự . _ -');
    const khoa = optStr(body.khoa, 'Khoa', 80);
    if (exists('SELECT 1 FROM classes WHERE ma = ?', ma)) throw new HttpError(409, 'Lớp "' + ma + '" đã tồn tại.');
    db.prepare('INSERT INTO classes(ma, khoa) VALUES(?, ?)').run(ma, khoa);
    return [201, { ok: true }];
  });
  route('DELETE', '/api/classes/:ma', { roles: STAFF }, ({ params }) => {
    const c = db.prepare('SELECT ma FROM classes WHERE ma = ?').get(params.ma);
    if (!c) throw notFound('Lớp');
    const n = db.prepare('SELECT COUNT(*) AS n FROM students WHERE lop = ?').get(c.ma).n;
    if (n) throw new HttpError(409, 'Lớp "' + c.ma + '" còn ' + n + ' sinh viên. Hãy chuyển hoặc xóa sinh viên trước.');
    db.prepare('DELETE FROM classes WHERE ma = ?').run(c.ma);
    return { ok: true };
  });

  // --- Học kỳ
  route('POST', '/api/terms', { roles: STAFF }, ({ body }) => {
    const t = termFields(body);
    const id = 't' + crypto.randomBytes(5).toString('hex');
    db.prepare('INSERT INTO terms(id, ten, nam) VALUES(?, ?, ?)').run(id, t.ten, t.nam);
    return [201, { id }];
  });
  route('PUT', '/api/terms/:id', { roles: STAFF }, ({ params, body }) => {
    const t = termFields(body);
    if (!db.prepare('UPDATE terms SET ten = ?, nam = ? WHERE id = ?').run(t.ten, t.nam, params.id).changes) throw notFound('Học kỳ');
    return { ok: true };
  });
  route('DELETE', '/api/terms/:id', { roles: STAFF }, ({ params }) => {
    if (!db.prepare('DELETE FROM terms WHERE id = ?').run(params.id).changes) throw notFound('Học kỳ');
    return { ok: true };
  });

  // --- Môn học
  route('POST', '/api/subjects', { roles: STAFF }, ({ body }) => {
    const m = subjectFields(body);
    const termId = reqStr(body.termId, 'Học kỳ', 40);
    if (!exists('SELECT 1 FROM terms WHERE id = ?', termId)) throw bad('Học kỳ không tồn tại.');
    const id = 'm' + crypto.randomBytes(5).toString('hex');
    db.prepare('INSERT INTO subjects(id, ten, tc, term_id) VALUES(?, ?, ?, ?)').run(id, m.ten, m.tc, termId);
    return [201, { id }];
  });
  route('PUT', '/api/subjects/:id', { roles: STAFF }, ({ params, body }) => {
    const m = subjectFields(body);
    if (!db.prepare('UPDATE subjects SET ten = ?, tc = ? WHERE id = ?').run(m.ten, m.tc, params.id).changes) throw notFound('Môn học');
    return { ok: true };
  });
  route('DELETE', '/api/subjects/:id', { roles: STAFF }, ({ params }) => {
    if (!db.prepare('DELETE FROM subjects WHERE id = ?').run(params.id).changes) throw notFound('Môn học');
    return { ok: true };
  });

  // --- Quản lý tài khoản (admin)
  route('GET', '/api/users', { roles: ADMIN }, () => ({
    users: db.prepare('SELECT id, username, full_name, role, ma_sv, active, must_change FROM users ORDER BY id').all()
      .map((u) => ({ id: u.id, username: u.username, fullName: u.full_name, role: u.role, maSV: u.ma_sv, active: !!u.active, mustChange: !!u.must_change })),
  }));
  route('POST', '/api/users', { roles: ADMIN }, async ({ body }) => {
    const username = reqStr(body.username, 'Tên đăng nhập', 32).toLowerCase();
    if (!/^[a-z0-9._-]{3,32}$/.test(username)) throw bad('Tên đăng nhập 3–32 ký tự, chỉ gồm chữ không dấu, số và . _ -');
    const fullName = reqStr(body.fullName, 'Họ tên', 100);
    if (!['admin', 'teacher', 'student'].includes(body.role)) throw bad('Vai trò không hợp lệ.');
    checkPassword(body.password, username);
    let maSV = null;
    if (body.role === 'student') {
      const st = db.prepare('SELECT ma_sv FROM students WHERE ma_sv = ?').get(reqStr(body.maSV, 'Mã sinh viên', 30));
      if (!st) throw bad('Mã sinh viên không tồn tại.');
      if (exists('SELECT 1 FROM users WHERE ma_sv = ?', st.ma_sv)) throw new HttpError(409, 'Sinh viên này đã có tài khoản.');
      maSV = st.ma_sv;
    }
    if (exists('SELECT 1 FROM users WHERE username = ?', username)) throw new HttpError(409, 'Tên đăng nhập "' + username + '" đã được dùng.');
    db.prepare('INSERT INTO users(username, full_name, role, pass_hash, ma_sv, must_change, created_at) VALUES(?, ?, ?, ?, ?, 1, ?)')
      .run(username, fullName, body.role, await hashPassword(body.password), maSV, now());
    return [201, { ok: true }];
  });
  route('PUT', '/api/users/:id', { roles: ADMIN }, async ({ params, body, user }) => {
    const target = db.prepare('SELECT * FROM users WHERE id = ?').get(Number(params.id));
    if (!target) throw notFound('Tài khoản');
    const self = target.id === user.id;
    let fullName = target.full_name, role = target.role, active = target.active;
    if (body.fullName !== undefined) fullName = reqStr(body.fullName, 'Họ tên', 100);
    if (body.role !== undefined && body.role !== target.role) {
      if (self) throw bad('Bạn không thể đổi vai trò của chính mình.');
      if (target.role === 'student' || body.role === 'student' || !['admin', 'teacher'].includes(body.role)) throw bad('Chỉ đổi được giữa vai trò Quản trị và Giảng viên.');
      role = body.role;
    }
    if (body.active !== undefined) {
      if (typeof body.active !== 'boolean') throw bad('Trạng thái không hợp lệ.');
      if (self && !body.active) throw bad('Bạn không thể khóa chính mình.');
      active = body.active ? 1 : 0;
      if (active && role === 'student' && !target.ma_sv) throw bad('Tài khoản sinh viên này chưa liên kết với mã sinh viên nào.');
    }
    let password = null;
    const resetting = body.resetPassword === true;
    if (resetting) {
      if (self) throw bad('Hãy dùng chức năng đổi mật khẩu cho tài khoản của bạn.');
      password = randomPassword(12);
    }
    db.prepare('UPDATE users SET full_name = ?, role = ?, active = ? WHERE id = ?').run(fullName, role, active, target.id);
    if (resetting) db.prepare('UPDATE users SET pass_hash = ?, must_change = 1 WHERE id = ?').run(await hashPassword(password), target.id);
    if (resetting || !active || role !== target.role) db.prepare('DELETE FROM sessions WHERE user_id = ?').run(target.id);
    return password ? { ok: true, password } : { ok: true };
  });
  route('DELETE', '/api/users/:id', { roles: ADMIN }, ({ params, user }) => {
    const id = Number(params.id);
    if (id === user.id) throw bad('Bạn không thể xóa chính mình.');
    if (!db.prepare('DELETE FROM users WHERE id = ?').run(id).changes) throw notFound('Tài khoản');
    return { ok: true };
  });

  // --- Sao lưu / khôi phục (admin)
  route('GET', '/api/export', { roles: ADMIN }, () => ({ version: 1, exportedAt: new Date().toISOString(), ...readAll(db) }));
  route('POST', '/api/admin/import', { roles: ADMIN, limit: 10 * 1024 * 1024 }, ({ body }) => {
    const data = sanitizeImport(body);
    if (!data) throw bad('File không hợp lệ. Hãy chọn file sao lưu của ứng dụng này.');
    return { ok: true, counts: importAll(db, data) };
  });
  route('POST', '/api/admin/demo', { roles: ADMIN }, () => ({ ok: true, counts: importAll(db, demoData()) }));
  route('POST', '/api/admin/clear', { roles: ADMIN }, () => ({ ok: true, counts: importAll(db, { students: [], terms: [], subjects: [], classes: [] }) }));

  /* ---------- Xử lý yêu cầu ---------- */
  const SEC_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; font-src https://fonts.gstatic.com https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
  };
  if (cfg.secureCookie) SEC_HEADERS['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains';

  function sendJson(res, status, obj) {
    const buf = Buffer.from(JSON.stringify(obj));
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': buf.length, 'Cache-Control': 'no-store' });
    res.end(buf);
  }
  async function readBody(req, limit) {
    const chunks = [];
    let size = 0;
    for await (const c of req) {
      size += c.length;
      if (size > limit) throw new HttpError(413, 'Dữ liệu gửi lên quá lớn.');
      chunks.push(c);
    }
    if (!size) return {};
    if (!/^application\/json\b/i.test(req.headers['content-type'] || '')) throw new HttpError(415, 'Yêu cầu phải ở dạng JSON.');
    try {
      const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!v || typeof v !== 'object') throw 0;
      return v;
    } catch { throw bad('Dữ liệu JSON không hợp lệ.'); }
  }

  async function handleApi(req, res, url) {
    const method = req.method;
    const ip = clientIp(req);
    if (method !== 'GET' && method !== 'HEAD') {
      if (req.headers['x-requested-with'] !== 'fetch') throw new HttpError(403, 'Yêu cầu bị từ chối.');
      const origin = req.headers.origin;
      if (origin) {
        let h = null;
        try { h = new URL(origin).host; } catch { /* bỏ qua */ }
        const host = (cfg.trustProxy && req.headers['x-forwarded-host']) || req.headers.host;
        if (h !== host) throw new HttpError(403, 'Yêu cầu bị từ chối.');
      }
    }
    let match = null, pathOk = false;
    for (const r of routes) {
      const m = r.rx.exec(url.pathname);
      if (!m) continue;
      pathOk = true;
      if (r.method !== method) continue;
      const params = {};
      r.keys.forEach((k, i) => { try { params[k] = decodeURIComponent(m[i + 1]); } catch { params[k] = ''; } });
      match = { r, params };
      break;
    }
    if (!match) throw new HttpError(pathOk ? 405 : 404, pathOk ? 'Phương thức không được hỗ trợ.' : 'Không tìm thấy.');
    const { r, params } = match;
    let user = null;
    if (r.auth !== 'none') {
      user = sessionUser(req);
      if (!user) throw new HttpError(401, 'Bạn chưa đăng nhập hoặc phiên đã hết hạn.');
      if (user.must_change && !r.allowMustChange) throw new HttpError(403, 'Bạn cần đổi mật khẩu trước khi tiếp tục.', 'must_change');
      if (r.roles && !r.roles.includes(user.role)) throw new HttpError(403, 'Bạn không có quyền thực hiện thao tác này.');
    }
    const body = method === 'POST' || method === 'PUT' ? await readBody(req, r.limit || 1024 * 1024) : {};
    const out = await r.handler({ req, res, params, body, user, ip });
    if (Array.isArray(out)) sendJson(res, out[0], out[1]);
    else sendJson(res, 200, out);
  }

  async function serveStatic(req, res, pathname) {
    if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Phương thức không được hỗ trợ.');
    let rel;
    try { rel = decodeURIComponent(pathname === '/' ? '/index.html' : pathname); } catch { throw new HttpError(404, 'Không tìm thấy.'); }
    const file = path.join(PUBLIC, rel);
    if (rel.includes('\0') || !file.startsWith(PUBLIC + path.sep) || rel.split('/').some((s) => s.startsWith('.'))) throw new HttpError(404, 'Không tìm thấy.');
    let data;
    try { data = await fs.promises.readFile(file); } catch { throw new HttpError(404, 'Không tìm thấy.'); }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream', 'Content-Length': data.length, 'Cache-Control': 'no-cache' });
    res.end(req.method === 'HEAD' ? undefined : data);
  }

  const server = http.createServer(async (req, res) => {
    for (const [k, v] of Object.entries(SEC_HEADERS)) res.setHeader(k, v);
    try {
      const url = new URL(req.url, 'http://localhost');
      if (url.pathname.startsWith('/api/')) await handleApi(req, res, url);
      else await serveStatic(req, res, url.pathname);
    } catch (e) {
      let status = 500, msg = 'Lỗi máy chủ. Vui lòng thử lại sau.', code;
      if (e instanceof HttpError) { status = e.status; msg = e.message; code = e.code; }
      else if (e && /FOREIGN KEY/.test(e.message || '')) { status = 409; msg = 'Dữ liệu đang được sử dụng nên không thể thực hiện thao tác này.'; }
      else if (e && /UNIQUE/.test(e.message || '')) { status = 409; msg = 'Dữ liệu bị trùng.'; }
      else console.error(new Date().toISOString(), req.method, req.url, e);
      if (status === 413) res.setHeader('Connection', 'close');
      if (res.headersSent) { res.end(); return; }
      if (String(req.url).startsWith('/api/')) sendJson(res, status, { error: msg, code });
      else { res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' }); res.end(msg); }
    }
  });
  server.requestTimeout = 30000;
  server.on('close', () => { clearInterval(cleanup); try { db.close(); } catch { /* đã đóng */ } });
  return { server, db, bootstrap, cfg };
}

module.exports = { createApp };

if (require.main === module) {
  (async () => {
    const port = Number(process.env.PORT) || 3000;
    const host = process.env.HOST || '127.0.0.1';
    const app = await createApp();
    if (app.bootstrap) {
      console.log('='.repeat(60));
      console.log('Đã tạo tài khoản quản trị đầu tiên');
      console.log('  Tên đăng nhập: ' + app.bootstrap.username);
      if (app.bootstrap.password) {
        console.log('  Mật khẩu tạm : ' + app.bootstrap.password);
        console.log('  (chỉ hiển thị một lần; bạn sẽ phải đổi khi đăng nhập)');
      } else console.log('  Mật khẩu     : lấy từ biến môi trường ADMIN_PASSWORD');
      console.log('='.repeat(60));
    }
    app.server.listen(port, host, () => console.log('Máy chủ chạy tại http://' + host + ':' + port));
    const stop = () => app.server.close(() => process.exit(0));
    process.on('SIGTERM', stop);
    process.on('SIGINT', stop);
  })().catch((e) => { console.error(e.message || e); process.exit(1); });
}
