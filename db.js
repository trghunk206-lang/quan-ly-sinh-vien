'use strict';
const { DatabaseSync } = require('node:sqlite');
const fs = require('node:fs');
const path = require('node:path');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS classes (
  ma TEXT PRIMARY KEY COLLATE NOCASE,
  khoa TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS terms (
  id TEXT PRIMARY KEY, ten TEXT NOT NULL, nam TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subjects (
  id TEXT PRIMARY KEY, ten TEXT NOT NULL,
  tc INTEGER NOT NULL CHECK (tc BETWEEN 1 AND 10),
  term_id TEXT NOT NULL REFERENCES terms(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS students (
  ma_sv TEXT PRIMARY KEY COLLATE NOCASE,
  ho_ten TEXT NOT NULL,
  gioi_tinh TEXT NOT NULL CHECK (gioi_tinh IN ('Nam','Nữ')),
  lop TEXT NOT NULL REFERENCES classes(ma),
  email TEXT NOT NULL DEFAULT '',
  sdt TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS scores (
  ma_sv TEXT NOT NULL REFERENCES students(ma_sv) ON DELETE CASCADE,
  subject_id TEXT NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  qt REAL NOT NULL CHECK (qt BETWEEN 0 AND 10),
  thi REAL NOT NULL CHECK (thi BETWEEN 0 AND 10),
  PRIMARY KEY (ma_sv, subject_id)
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  full_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','teacher','student')),
  pass_hash TEXT NOT NULL,
  ma_sv TEXT REFERENCES students(ma_sv) ON DELETE CASCADE,
  active INTEGER NOT NULL DEFAULT 1,
  must_change INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS users_ma_sv ON users(ma_sv) WHERE ma_sv IS NOT NULL;
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
`;

function open(file) {
  if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
  const db = new DatabaseSync(file);
  db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
  db.exec(SCHEMA);
  return db;
}

function tx(db, fn) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const r = fn();
    db.exec('COMMIT');
    return r;
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch { /* đã rollback */ }
    throw e;
  }
}

/** Đọc toàn bộ dữ liệu theo dạng giao diện dùng. onlyMa: chỉ lấy dữ liệu của 1 sinh viên. */
function readAll(db, onlyMa) {
  const where = onlyMa ? ' WHERE ma_sv = ?' : '';
  const args = onlyMa ? [onlyMa] : [];
  const rows = db.prepare('SELECT ma_sv, ho_ten, gioi_tinh, lop, email, sdt FROM students' + where + ' ORDER BY ma_sv').all(...args);
  const scores = db.prepare('SELECT ma_sv, subject_id, qt, thi FROM scores' + where + ' ORDER BY rowid').all(...args);
  const byMa = new Map();
  for (const sc of scores) {
    const k = sc.ma_sv.toLowerCase();
    if (!byMa.has(k)) byMa.set(k, []);
    byMa.get(k).push({ subjId: sc.subject_id, qt: sc.qt, thi: sc.thi });
  }
  const students = rows.map((s) => ({
    maSV: s.ma_sv, hoTen: s.ho_ten, gioiTinh: s.gioi_tinh, lop: s.lop, email: s.email, sdt: s.sdt,
    diem: byMa.get(s.ma_sv.toLowerCase()) || [],
  }));
  let classes = db.prepare('SELECT ma, khoa FROM classes ORDER BY rowid').all();
  if (onlyMa) {
    const mine = new Set(students.map((s) => s.lop.toLowerCase()));
    classes = classes.filter((c) => mine.has(c.ma.toLowerCase()));
  }
  const terms = db.prepare('SELECT id, ten, nam FROM terms ORDER BY rowid').all();
  const subjects = db.prepare('SELECT id, ten, tc, term_id FROM subjects ORDER BY rowid').all()
    .map((m) => ({ id: m.id, ten: m.ten, tc: m.tc, termId: m.term_id }));
  return { students, terms, subjects, classes };
}

/** Làm sạch dữ liệu nhập từ file sao lưu. Trả về null nếu sai định dạng. */
function sanitizeImport(o) {
  if (!o || typeof o !== 'object' || !Array.isArray(o.students) || !Array.isArray(o.terms) || !Array.isArray(o.subjects)) return null;
  if (o.students.length > 50000 || o.terms.length > 500 || o.subjects.length > 5000) return null;
  const str = (v, max) => String(v == null ? '' : v).trim().slice(0, max);
  const clamp = (x, a, b) => Math.max(a, Math.min(b, x));
  const idOk = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{1,40}$/.test(v);
  const codeOk = (v) => typeof v === 'string' && /^[A-Za-z0-9._-]{1,30}$/.test(v);

  const terms = [];
  const tIds = new Set();
  for (const t of o.terms) {
    if (!t || !idOk(t.id) || tIds.has(t.id)) continue;
    tIds.add(t.id);
    terms.push({ id: t.id, ten: str(t.ten, 60) || 'Học kỳ', nam: str(t.nam, 20) });
  }
  const subjects = [];
  const sIds = new Set();
  for (const m of o.subjects) {
    if (!m || !idOk(m.id) || sIds.has(m.id) || !tIds.has(m.termId)) continue;
    sIds.add(m.id);
    subjects.push({ id: m.id, ten: str(m.ten, 120) || 'Môn học', tc: clamp(parseInt(m.tc, 10) || 1, 1, 10), termId: m.termId });
  }
  const classes = [];
  const haveClass = new Set();
  const addClass = (ma, khoa) => {
    const k = ma.toLowerCase();
    if (haveClass.has(k)) return;
    haveClass.add(k);
    classes.push({ ma, khoa });
  };
  if (Array.isArray(o.classes)) for (const c of o.classes) if (c && codeOk(c.ma)) addClass(c.ma, str(c.khoa, 80));

  const students = [];
  const seen = new Set();
  for (const s of o.students) {
    if (!s || !codeOk(s.maSV) || seen.has(s.maSV.toLowerCase())) continue;
    seen.add(s.maSV.toLowerCase());
    const lop = codeOk(s.lop) ? s.lop : 'KHAC';
    addClass(lop, '');
    const diem = [];
    const dSeen = new Set();
    for (const d of Array.isArray(s.diem) ? s.diem : []) {
      if (!d || !sIds.has(d.subjId) || dSeen.has(d.subjId)) continue;
      const qt = Number(d.qt), thi = Number(d.thi);
      if (!Number.isFinite(qt) || !Number.isFinite(thi)) continue;
      dSeen.add(d.subjId);
      diem.push({ subjId: d.subjId, qt: clamp(qt, 0, 10), thi: clamp(thi, 0, 10) });
    }
    students.push({
      maSV: s.maSV, hoTen: str(s.hoTen, 100) || s.maSV, gioiTinh: s.gioiTinh === 'Nữ' ? 'Nữ' : 'Nam',
      lop, email: str(s.email, 120), sdt: str(s.sdt, 20), diem,
    });
  }
  return { students, terms, subjects, classes };
}

/** Thay toàn bộ dữ liệu học vụ. Tài khoản sinh viên được nối lại nếu mã SV còn tồn tại, ngược lại bị khóa. */
function importAll(db, d) {
  return tx(db, () => {
    const links = db.prepare('SELECT id, ma_sv FROM users WHERE ma_sv IS NOT NULL').all();
    db.exec('UPDATE users SET ma_sv = NULL');
    db.exec('DELETE FROM scores; DELETE FROM subjects; DELETE FROM terms; DELETE FROM students; DELETE FROM classes;');
    const insClass = db.prepare('INSERT INTO classes(ma, khoa) VALUES(?, ?)');
    const insTerm = db.prepare('INSERT INTO terms(id, ten, nam) VALUES(?, ?, ?)');
    const insSubj = db.prepare('INSERT INTO subjects(id, ten, tc, term_id) VALUES(?, ?, ?, ?)');
    const insStu = db.prepare('INSERT INTO students(ma_sv, ho_ten, gioi_tinh, lop, email, sdt) VALUES(?, ?, ?, ?, ?, ?)');
    const insScore = db.prepare('INSERT INTO scores(ma_sv, subject_id, qt, thi) VALUES(?, ?, ?, ?)');
    for (const c of d.classes) insClass.run(c.ma, c.khoa);
    for (const t of d.terms) insTerm.run(t.id, t.ten, t.nam);
    for (const m of d.subjects) insSubj.run(m.id, m.ten, m.tc, m.termId);
    for (const s of d.students) {
      insStu.run(s.maSV, s.hoTen, s.gioiTinh, s.lop, s.email, s.sdt);
      for (const x of s.diem) insScore.run(s.maSV, x.subjId, x.qt, x.thi);
    }
    const has = db.prepare('SELECT ma_sv FROM students WHERE ma_sv = ?');
    const relink = db.prepare('UPDATE users SET ma_sv = ? WHERE id = ?');
    const lock = db.prepare('UPDATE users SET active = 0 WHERE id = ?');
    const kill = db.prepare('DELETE FROM sessions WHERE user_id = ?');
    for (const l of links) {
      const row = has.get(l.ma_sv);
      if (row) relink.run(row.ma_sv, l.id);
      else { lock.run(l.id); kill.run(l.id); }
    }
    return { students: d.students.length, terms: d.terms.length, subjects: d.subjects.length, classes: d.classes.length };
  });
}

/** Dữ liệu mẫu cố định (không ngẫu nhiên giữa các lần nạp). */
function demoData() {
  const rng = (seed) => () => {
    seed |= 0; seed = (seed + 0x6D2B79F5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const R = rng(20241029);
  const r1 = (x) => Math.round(x * 10) / 10;
  const clamp = (x, a, b) => Math.max(a, Math.min(b, x));
  const classes = [
    { ma: 'CNTT1', khoa: 'Công nghệ thông tin' }, { ma: 'CNTT2', khoa: 'Công nghệ thông tin' }, { ma: 'HTTT1', khoa: 'Hệ thống thông tin' },
  ];
  const terms = [
    { id: 't1', ten: 'Học kỳ 1', nam: '2024-2025' }, { id: 't2', ten: 'Học kỳ 2', nam: '2024-2025' }, { id: 't3', ten: 'Học kỳ 1', nam: '2025-2026' },
  ];
  const subjects = [
    { id: 'm1', ten: 'Lập trình C++', tc: 3, termId: 't1' }, { id: 'm2', ten: 'Toán cao cấp A1', tc: 3, termId: 't1' },
    { id: 'm3', ten: 'Anh văn 1', tc: 2, termId: 't1' }, { id: 'm4', ten: 'Cơ sở dữ liệu', tc: 3, termId: 't2' },
    { id: 'm5', ten: 'Lập trình Java', tc: 3, termId: 't2' }, { id: 'm6', ten: 'Toán rời rạc', tc: 3, termId: 't2' },
    { id: 'm7', ten: 'Mạng máy tính', tc: 3, termId: 't3' }, { id: 'm8', ten: 'Hệ điều hành', tc: 3, termId: 't3' },
    { id: 'm9', ten: 'Phân tích thiết kế HTTT', tc: 3, termId: 't3' },
  ];
  const rows = [
    ['SV001', 'Nguyễn Văn An', 'Nam', 'CNTT1', 'an.nv@mail.vn', '0901234001'], ['SV002', 'Trần Thị Bình', 'Nữ', 'CNTT1', 'binh.tt@mail.vn', '0901234002'],
    ['SV003', 'Lê Văn Cường', 'Nam', 'CNTT1', 'cuong.lv@mail.vn', '0901234003'], ['SV004', 'Phạm Thu Dung', 'Nữ', 'CNTT2', 'dung.pt@mail.vn', '0901234004'],
    ['SV005', 'Hoàng Văn Em', 'Nam', 'CNTT2', 'em.hv@mail.vn', '0901234005'], ['SV006', 'Vũ Thị Phượng', 'Nữ', 'CNTT2', 'phuong.vt@mail.vn', '0901234006'],
    ['SV007', 'Đặng Văn Giang', 'Nam', 'HTTT1', 'giang.dv@mail.vn', '0901234007'], ['SV008', 'Bùi Thị Hương', 'Nữ', 'HTTT1', 'huong.bt@mail.vn', '0901234008'],
    ['SV009', 'Đỗ Văn Khánh', 'Nam', 'HTTT1', 'khanh.dv@mail.vn', '0901234009'], ['SV010', 'Ngô Thị Lan', 'Nữ', 'CNTT1', 'lan.nt@mail.vn', '0901234010'],
    ['SV011', 'Dương Văn Minh', 'Nam', 'CNTT2', 'minh.dv@mail.vn', '0901234011'], ['SV012', 'Lý Thị Nga', 'Nữ', 'HTTT1', 'nga.lt@mail.vn', '0901234012'],
  ];
  const students = rows.map((r) => {
    const base = 5.6 + R() * 3;
    const diem = [];
    for (let j = 1; j <= 6; j++) diem.push({ subjId: 'm' + j, qt: r1(clamp(base + (R() - 0.5) * 2, 3, 10)), thi: r1(clamp(base + (R() - 0.5) * 3, 3, 10)) });
    return { maSV: r[0], hoTen: r[1], gioiTinh: r[2], lop: r[3], email: r[4], sdt: r[5], diem };
  });
  return { students, terms, subjects, classes };
}

module.exports = { open, tx, readAll, sanitizeImport, importAll, demoData };
