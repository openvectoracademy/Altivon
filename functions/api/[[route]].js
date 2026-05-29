// AcademIQ — Complete Backend API
// Deploy: Cloudflare Pages + D1 Database

const JWT_SECRET = 'academiq-jwt-production-secret-2026';
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Content-Type': 'application/json'
};

// ==================== JWT HELPERS ====================
async function createToken(payload) {
  const encoder = new TextEncoder();
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = { ...payload, iat: now, exp: now + 86400 };
  const headerB64 = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const payloadB64 = btoa(JSON.stringify(tokenPayload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const signatureInput = `${headerB64}.${payloadB64}`;
  const key = await crypto.subtle.importKey('raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(signatureInput));
  const signatureB64 = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return `${headerB64}.${payloadB64}.${signatureB64}`;
}

async function verifyToken(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const [headerB64, payloadB64, signatureB64] = parts;
    const signatureInput = `${headerB64}.${payloadB64}`;
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', encoder.encode(JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const expectedSig = Uint8Array.from(atob(signatureB64.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const isValid = await crypto.subtle.verify('HMAC', key, expectedSig, encoder.encode(signatureInput));
    if (!isValid) return null;
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ==================== DATABASE HELPERS ====================
async function ensureTables(db) {
  const tables = [
    `CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,password TEXT NOT NULL,role TEXT DEFAULT 'user',is_blocked INTEGER DEFAULT 0,is_approved INTEGER DEFAULT 0,phone TEXT,device_fingerprint TEXT,device_count INTEGER DEFAULT 1,token_version INTEGER DEFAULT 1,read_notifications TEXT DEFAULT '[]',created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS courses (id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,description TEXT,thumbnail TEXT,is_active INTEGER DEFAULT 1,show_in_browse INTEGER DEFAULT 0,subject_area TEXT,difficulty_level TEXT,resources TEXT DEFAULT '[]',created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS subjects (id INTEGER PRIMARY KEY AUTOINCREMENT,course_id INTEGER NOT NULL,name TEXT NOT NULL,has_papers INTEGER DEFAULT 1,sort_order INTEGER DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS papers (id INTEGER PRIMARY KEY AUTOINCREMENT,subject_id INTEGER NOT NULL,name TEXT NOT NULL,sort_order INTEGER DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS chapters (id INTEGER PRIMARY KEY AUTOINCREMENT,paper_id INTEGER NOT NULL,title TEXT NOT NULL,sort_order INTEGER DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS lectures (id INTEGER PRIMARY KEY AUTOINCREMENT,chapter_id INTEGER NOT NULL,course_id INTEGER NOT NULL,title TEXT NOT NULL,yt_video_id TEXT NOT NULL,sort_order INTEGER DEFAULT 0,description TEXT,pdfs TEXT DEFAULT '[]',created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS memberships (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,course_id INTEGER NOT NULL,expires_at DATETIME,is_active INTEGER DEFAULT 0,payment_phone TEXT,payment_method TEXT,payment_trx_id TEXT UNIQUE,payment_status TEXT DEFAULT 'pending',granted_by INTEGER,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id, course_id))`,
    `CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,message TEXT,type TEXT DEFAULT 'info',target_type TEXT DEFAULT 'all',target_id INTEGER,is_banner INTEGER DEFAULT 0,is_active INTEGER DEFAULT 1,expires_at DATETIME,created_by INTEGER,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
    `CREATE TABLE IF NOT EXISTS support_tickets (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,email TEXT NOT NULL,subject TEXT,message TEXT NOT NULL,status TEXT DEFAULT 'open',user_id INTEGER,resolved_at DATETIME,created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`
  ];
  const indexes = [
    `CREATE INDEX IF NOT EXISTS idx_memberships_user ON memberships(user_id)`,
    `CREATE INDEX IF NOT EXISTS idx_memberships_course ON memberships(course_id)`,
    `CREATE INDEX IF NOT EXISTS idx_memberships_trx ON memberships(payment_trx_id)`,
    `CREATE INDEX IF NOT EXISTS idx_subjects_course ON subjects(course_id)`,
    `CREATE INDEX IF NOT EXISTS idx_papers_subject ON papers(subject_id)`,
    `CREATE INDEX IF NOT EXISTS idx_chapters_paper ON chapters(paper_id)`,
    `CREATE INDEX IF NOT EXISTS idx_lectures_chapter ON lectures(chapter_id)`,
    `CREATE INDEX IF NOT EXISTS idx_lectures_course ON lectures(course_id)`
  ];
  for (const sql of [...tables, ...indexes]) { await db.prepare(sql).run(); }
  const admin = await db.prepare('SELECT id FROM users WHERE email = ?').bind('admin@academiq.edu').first();
  if (!admin) {
    await db.prepare('INSERT INTO users (name, email, password, role, is_approved, token_version) VALUES (?, ?, ?, ?, ?, ?)')
      .bind('Admin', 'admin@academiq.edu', 'Admin@2026!', 'admin', 1, 1).run();
  }
}

// ==================== AUTH MIDDLEWARE ====================
async function authenticate(request, db) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return { error: 'Unauthorized', status: 401 };
  const token = authHeader.slice(7);
  const payload = await verifyToken(token);
  if (!payload) return { error: 'Invalid or expired token', status: 401 };
  const user = await db.prepare('SELECT * FROM users WHERE id = ?').bind(payload.id).first();
  if (!user) return { error: 'User not found', status: 401 };
  if (user.is_blocked) return { error: 'Account blocked', status: 403 };
  if (user.token_version !== payload.tv) return { error: 'Session expired', status: 401 };
  return { user, status: 200 };
}

async function requireAdmin(request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return auth;
  if (auth.user.role !== 'admin') return { error: 'Admin access required', status: 403 };
  return auth;
}

// ==================== HANDLERS ====================
async function handleLogin(request, db) {
  const { email, password, device_fingerprint } = await request.json();
  if (!email || !password) return { status: 400, body: { error: 'Email and password required' } };
  const user = await db.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user || user.password !== password) return { status: 401, body: { error: 'Invalid credentials' } };
  if (user.is_blocked) return { status: 403, body: { error: 'Account blocked' } };
  if (!user.is_approved) return { status: 403, body: { error: 'Account pending approval' } };
  if (device_fingerprint) {
    if (user.device_fingerprint && user.device_fingerprint !== device_fingerprint) {
      return { status: 403, body: { error: 'Account active on another device. Please log out there first.' } };
    }
    if (!user.device_fingerprint) {
      await db.prepare('UPDATE users SET device_fingerprint = ? WHERE id = ?').bind(device_fingerprint, user.id).run();
    }
  }
  await db.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').bind(user.id).run();
  const updated = await db.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
  const token = await createToken({ id: user.id, email: user.email, role: user.role, tv: updated.token_version });
  return { body: { token, user: { id: user.id, name: user.name, email: user.email, role: user.role, phone: user.phone } } };
}

async function handleSignup(request, db) {
  const { name, email, password, phone, device_fingerprint } = await request.json();
  if (!name || !email || !password) return { status: 400, body: { error: 'All fields required' } };
  if (password.length < 6) return { status: 400, body: { error: 'Password min 6 characters' } };
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) return { status: 409, body: { error: 'Email already registered' } };
  if (device_fingerprint) {
    const count = await db.prepare('SELECT COUNT(*) as c FROM users WHERE device_fingerprint = ?').bind(device_fingerprint).first();
    if (count && count.c >= 3) return { status: 403, body: { error: 'Max 3 accounts per device' } };
  }
  await db.prepare('INSERT INTO users (name, email, password, phone, device_fingerprint) VALUES (?, ?, ?, ?, ?)')
    .bind(name, email, password, phone || null, device_fingerprint || null).run();
  return { status: 201, body: { message: 'Account created. Awaiting admin approval.' } };
}

async function handleLogout(request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare('UPDATE users SET device_fingerprint = NULL, token_version = token_version + 1 WHERE id = ?').bind(auth.user.id).run();
  return { body: { message: 'Logged out' } };
}

async function getPublicCourses(request, db) {
  const url = new URL(request.url);
  const subject = url.searchParams.get('subject_area');
  const difficulty = url.searchParams.get('difficulty');
  const search = url.searchParams.get('search');
  const limit = parseInt(url.searchParams.get('limit') || '20');
  let query = 'SELECT * FROM courses WHERE is_active = 1 AND show_in_browse = 1';
  const params = [];
  if (subject) { query += ' AND subject_area = ?'; params.push(subject); }
  if (difficulty) { query += ' AND difficulty_level = ?'; params.push(difficulty); }
  if (search) { query += ' AND (title LIKE ? OR description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }
  query += ' ORDER BY created_at DESC LIMIT ?'; params.push(limit);
  const courses = await db.prepare(query).bind(...params).all();
  return { body: courses.results };
}

async function getCourseTree(id, db) {
  const course = await db.prepare('SELECT * FROM courses WHERE id = ?').bind(id).first();
  if (!course) return { status: 404, body: { error: 'Not found' } };
  const subjects = await db.prepare('SELECT * FROM subjects WHERE course_id = ? ORDER BY sort_order').bind(id).all();
  for (const s of subjects.results) {
    const papers = await db.prepare('SELECT * FROM papers WHERE subject_id = ? ORDER BY sort_order').bind(s.id).all();
    for (const p of papers.results) {
      const chapters = await db.prepare('SELECT * FROM chapters WHERE paper_id = ? ORDER BY sort_order').bind(p.id).all();
      for (const ch of chapters.results) {
        const lectures = await db.prepare('SELECT * FROM lectures WHERE chapter_id = ? ORDER BY sort_order').bind(ch.id).all();
        ch.lectures = lectures.results.map(l => ({ ...l, pdfs: JSON.parse(l.pdfs || '[]') }));
      }
      p.chapters = chapters.results;
    }
    s.papers = papers.results;
  }
  course.subjects = subjects.results;
  course.resources = JSON.parse(course.resources || '[]');
  return { body: course };
}

async function getPublicStats(db) {
  const [c, l, u] = await Promise.all([
    db.prepare('SELECT COUNT(*) as c FROM courses WHERE is_active = 1').first(),
    db.prepare('SELECT COUNT(*) as c FROM lectures').first(),
    db.prepare('SELECT COUNT(*) as c FROM users WHERE role = ?').bind('user').first()
  ]);
  return { body: { courses: c.c, lectures: l.c, students: u.c } };
}

async function getSubjectAreas(db) {
  const r = await db.prepare('SELECT DISTINCT subject_area FROM courses WHERE is_active = 1 AND subject_area IS NOT NULL').all();
  return { body: r.results.map(x => x.subject_area) };
}

async function submitContact(request, db) {
  const { name, email, subject, message } = await request.json();
  if (!name || !email || !message) return { status: 400, body: { error: 'Required fields missing' } };
  await db.prepare('INSERT INTO support_tickets (name, email, subject, message) VALUES (?, ?, ?, ?)').bind(name, email, subject || null, message).run();
  return { status: 201, body: { message: 'Sent' } };
}

async function getUserProfile(request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const u = await db.prepare('SELECT id, name, email, role, phone, created_at FROM users WHERE id = ?').bind(auth.user.id).first();
  return { body: u };
}

async function getUserMemberships(request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const m = await db.prepare(`SELECT m.*, c.title as course_title, c.subject_area FROM memberships m JOIN courses c ON m.course_id = c.id WHERE m.user_id = ? ORDER BY m.created_at DESC`).bind(auth.user.id).all();
  return { body: m.results };
}

async function getUserNotifications(request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const n = await db.prepare(`SELECT * FROM notifications WHERE is_active = 1 AND (target_type = 'all' OR (target_type = 'user' AND target_id = ?)) AND (expires_at IS NULL OR expires_at > datetime('now')) ORDER BY created_at DESC LIMIT 50`).bind(auth.user.id).all();
  const readIds = JSON.parse(auth.user.read_notifications || '[]');
  return { body: n.results.map(x => ({ ...x, is_read: readIds.includes(x.id) })) };
}

async function markNotificationRead(request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { notification_id } = await request.json();
  const ids = JSON.parse(auth.user.read_notifications || '[]');
  if (!ids.includes(notification_id)) { ids.push(notification_id); await db.prepare('UPDATE users SET read_notifications = ? WHERE id = ?').bind(JSON.stringify(ids), auth.user.id).run(); }
  return { body: { message: 'Marked' } };
}

async function markAllNotificationsRead(request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const n = await db.prepare(`SELECT id FROM notifications WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`).all();
  await db.prepare('UPDATE users SET read_notifications = ? WHERE id = ?').bind(JSON.stringify(n.results.map(x => x.id)), auth.user.id).run();
  return { body: { message: 'All marked' } };
}

async function getLecture(id, request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const lec = await db.prepare('SELECT * FROM lectures WHERE id = ?').bind(id).first();
  if (!lec) return { status: 404, body: { error: 'Not found' } };
  if (auth.user.role !== 'admin') {
    const mem = await db.prepare(`SELECT id FROM memberships WHERE user_id = ? AND course_id = ? AND is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`).bind(auth.user.id, lec.course_id).first();
    if (!mem) return { status: 403, body: { error: 'Enrollment required' } };
  }
  lec.pdfs = JSON.parse(lec.pdfs || '[]');
  return { body: lec };
}

async function submitPayment(request, db) {
  const auth = await authenticate(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { course_id, phone, method, trx_id } = await request.json();
  if (!course_id || !phone || !method || !trx_id) return { status: 400, body: { error: 'All fields required' } };
  const ex = await db.prepare('SELECT id FROM memberships WHERE user_id = ? AND course_id = ?').bind(auth.user.id, course_id).first();
  if (ex) return { status: 409, body: { error: 'Already enrolled' } };
  const tx = await db.prepare('SELECT id FROM memberships WHERE payment_trx_id = ?').bind(trx_id).first();
  if (tx) return { status: 409, body: { error: 'Transaction ID used' } };
  await db.prepare('INSERT INTO memberships (user_id, course_id, payment_phone, payment_method, payment_trx_id) VALUES (?, ?, ?, ?, ?)').bind(auth.user.id, course_id, phone, method, trx_id).run();
  return { status: 201, body: { message: 'Payment submitted' } };
}

// Admin handlers
async function getAdminStats(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const [c, s, ch, u, pa, am, pp, ot] = await Promise.all([
    db.prepare('SELECT COUNT(*) as c FROM courses').first(),
    db.prepare('SELECT COUNT(*) as c FROM subjects').first(),
    db.prepare('SELECT COUNT(*) as c FROM chapters').first(),
    db.prepare('SELECT COUNT(*) as c FROM users').first(),
    db.prepare('SELECT COUNT(*) as c FROM users WHERE is_approved = 0').first(),
    db.prepare(`SELECT COUNT(*) as c FROM memberships WHERE is_active = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))`).first(),
    db.prepare("SELECT COUNT(*) as c FROM memberships WHERE payment_status = 'pending'").first(),
    db.prepare("SELECT COUNT(*) as c FROM support_tickets WHERE status = 'open'").first()
  ]);
  return { body: { courses: c.c, subjects: s.c, chapters: ch.c, users: u.c, pendingApproval: pa.c, activeMembers: am.c, pendingPayments: pp.c, openTickets: ot.c } };
}

async function getAdminUsers(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const u = await db.prepare('SELECT * FROM users ORDER BY created_at DESC').all();
  return { body: u.results };
}

async function approveUser(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?').bind(id).run();
  return { body: { message: 'Approved' } };
}

async function toggleBlockUser(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const u = await db.prepare('SELECT is_blocked FROM users WHERE id = ?').bind(id).first();
  if (!u) return { status: 404, body: { error: 'Not found' } };
  await db.prepare('UPDATE users SET is_blocked = ? WHERE id = ?').bind(u.is_blocked ? 0 : 1, id).run();
  return { body: { message: u.is_blocked ? 'Unblocked' : 'Blocked' } };
}

async function clearUserDevice(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare('UPDATE users SET device_fingerprint = NULL, token_version = token_version + 1 WHERE id = ?').bind(id).run();
  return { body: { message: 'Device cleared' } };
}

async function deleteUser(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare('DELETE FROM memberships WHERE user_id = ?').bind(id).run();
  await db.prepare('DELETE FROM support_tickets WHERE user_id = ?').bind(id).run();
  await db.prepare('DELETE FROM users WHERE id = ?').bind(id).run();
  return { body: { message: 'Deleted' } };
}

async function getAdminCourses(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const c = await db.prepare('SELECT * FROM courses ORDER BY created_at DESC').all();
  return { body: c.results };
}

async function createCourse(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { title, description, subject_area, difficulty_level, show_in_browse } = await request.json();
  if (!title) return { status: 400, body: { error: 'Title required' } };
  const r = await db.prepare('INSERT INTO courses (title, description, subject_area, difficulty_level, show_in_browse) VALUES (?, ?, ?, ?, ?)').bind(title, description || null, subject_area || null, difficulty_level || null, show_in_browse ? 1 : 0).run();
  return { status: 201, body: { id: r.meta.last_row_id } };
}

async function updateCourse(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const data = await request.json();
  const fields = ['title','description','subject_area','difficulty_level'];
  const updates = [];
  const params = [];
  fields.forEach(f => { if (data[f] !== undefined) { updates.push(`${f} = ?`); params.push(data[f]); } });
  if (data.show_in_browse !== undefined) { updates.push('show_in_browse = ?'); params.push(data.show_in_browse ? 1 : 0); }
  if (data.is_active !== undefined) { updates.push('is_active = ?'); params.push(data.is_active ? 1 : 0); }
  if (!updates.length) return { status: 400, body: { error: 'No updates' } };
  updates.push("updated_at = datetime('now')"); params.push(id);
  await db.prepare(`UPDATE courses SET ${updates.join(', ')} WHERE id = ?`).bind(...params).run();
  return { body: { message: 'Updated' } };
}

async function deleteCourse(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const subs = await db.prepare('SELECT id FROM subjects WHERE course_id = ?').bind(id).all();
  for (const s of subs.results) {
    const papers = await db.prepare('SELECT id FROM papers WHERE subject_id = ?').bind(s.id).all();
    for (const p of papers.results) {
      const chapters = await db.prepare('SELECT id FROM chapters WHERE paper_id = ?').bind(p.id).all();
      for (const ch of chapters.results) { await db.prepare('DELETE FROM lectures WHERE chapter_id = ?').bind(ch.id).run(); }
      await db.prepare('DELETE FROM chapters WHERE paper_id = ?').bind(p.id).run();
    }
    await db.prepare('DELETE FROM papers WHERE subject_id = ?').bind(s.id).run();
  }
  await db.prepare('DELETE FROM subjects WHERE course_id = ?').bind(id).run();
  await db.prepare('DELETE FROM memberships WHERE course_id = ?').bind(id).run();
  await db.prepare('DELETE FROM courses WHERE id = ?').bind(id).run();
  return { body: { message: 'Deleted' } };
}

async function createSubject(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { course_id, name } = await request.json();
  const r = await db.prepare('INSERT INTO subjects (course_id, name) VALUES (?, ?)').bind(course_id, name).run();
  return { status: 201, body: { id: r.meta.last_row_id } };
}

async function createPaper(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { subject_id, name } = await request.json();
  const r = await db.prepare('INSERT INTO papers (subject_id, name) VALUES (?, ?)').bind(subject_id, name).run();
  return { status: 201, body: { id: r.meta.last_row_id } };
}

async function createChapter(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { paper_id, title } = await request.json();
  const r = await db.prepare('INSERT INTO chapters (paper_id, title) VALUES (?, ?)').bind(paper_id, title).run();
  return { status: 201, body: { id: r.meta.last_row_id } };
}

async function getAllLectures(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const l = await db.prepare(`SELECT l.*, ch.title as chapter_title, p.name as paper_name, s.name as subject_name, c.title as course_title FROM lectures l JOIN chapters ch ON l.chapter_id = ch.id JOIN papers p ON ch.paper_id = p.id JOIN subjects s ON p.subject_id = s.id JOIN courses c ON l.course_id = c.id ORDER BY c.title, s.sort_order, p.sort_order, ch.sort_order, l.sort_order`).all();
  return { body: l.results };
}

async function createLecture(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { chapter_id, course_id, title, yt_video_id, description } = await request.json();
  const r = await db.prepare('INSERT INTO lectures (chapter_id, course_id, title, yt_video_id, description) VALUES (?, ?, ?, ?, ?)').bind(chapter_id, course_id, title, yt_video_id, description || null).run();
  return { status: 201, body: { id: r.meta.last_row_id } };
}

async function deleteLecture(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare('DELETE FROM lectures WHERE id = ?').bind(id).run();
  return { body: { message: 'Deleted' } };
}

async function addLecturePdf(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { lecture_id, title, url } = await request.json();
  const lec = await db.prepare('SELECT pdfs FROM lectures WHERE id = ?').bind(lecture_id).first();
  if (!lec) return { status: 404, body: { error: 'Not found' } };
  const pdfs = JSON.parse(lec.pdfs || '[]');
  pdfs.push({ title, url });
  await db.prepare("UPDATE lectures SET pdfs = ?, updated_at = datetime('now') WHERE id = ?").bind(JSON.stringify(pdfs), lecture_id).run();
  return { status: 201, body: { message: 'Added' } };
}

async function deleteLecturePdf(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { lecture_id, index } = await request.json();
  const lec = await db.prepare('SELECT pdfs FROM lectures WHERE id = ?').bind(lecture_id).first();
  const pdfs = JSON.parse(lec.pdfs || '[]');
  pdfs.splice(index, 1);
  await db.prepare("UPDATE lectures SET pdfs = ?, updated_at = datetime('now') WHERE id = ?").bind(JSON.stringify(pdfs), lecture_id).run();
  return { body: { message: 'Removed' } };
}

async function getCourseResources(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const c = await db.prepare('SELECT resources FROM courses WHERE id = ?').bind(id).first();
  return { body: JSON.parse(c.resources || '[]') };
}

async function addResource(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { course_id, title, url } = await request.json();
  const c = await db.prepare('SELECT resources FROM courses WHERE id = ?').bind(course_id).first();
  const resources = JSON.parse(c.resources || '[]');
  resources.push({ title, url });
  await db.prepare("UPDATE courses SET resources = ?, updated_at = datetime('now') WHERE id = ?").bind(JSON.stringify(resources), course_id).run();
  return { status: 201, body: { message: 'Added' } };
}

async function deleteResource(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { course_id, index } = await request.json();
  const c = await db.prepare('SELECT resources FROM courses WHERE id = ?').bind(course_id).first();
  const resources = JSON.parse(c.resources || '[]');
  resources.splice(index, 1);
  await db.prepare("UPDATE courses SET resources = ?, updated_at = datetime('now') WHERE id = ?").bind(JSON.stringify(resources), course_id).run();
  return { body: { message: 'Removed' } };
}

async function getAdminMemberships(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const m = await db.prepare(`SELECT m.*, u.name as user_name, u.email as user_email, c.title as course_title FROM memberships m JOIN users u ON m.user_id = u.id JOIN courses c ON m.course_id = c.id ORDER BY m.created_at DESC`).all();
  return { body: m.results };
}

async function verifyPayment(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const exp = new Date(Date.now() + 365 * 86400000).toISOString();
  await db.prepare("UPDATE memberships SET is_active = 1, expires_at = ?, payment_status = 'verified' WHERE id = ?").bind(exp, id).run();
  return { body: { message: 'Verified' } };
}

async function rejectPayment(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare("UPDATE memberships SET payment_status = 'rejected', is_active = 0 WHERE id = ?").bind(id).run();
  return { body: { message: 'Rejected' } };
}

async function extendMembership(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { days } = await request.json();
  await db.prepare(`UPDATE memberships SET expires_at = datetime(COALESCE(expires_at, 'now'), ? || ' days') WHERE id = ?`).bind(String(days), id).run();
  return { body: { message: 'Extended' } };
}

async function cancelMembership(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare('UPDATE memberships SET is_active = 0 WHERE id = ?').bind(id).run();
  return { body: { message: 'Cancelled' } };
}

async function getAdminNotifications(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const n = await db.prepare('SELECT * FROM notifications ORDER BY created_at DESC').all();
  return { body: n.results };
}

async function createNotification(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const { title, message, type, is_banner } = await request.json();
  await db.prepare('INSERT INTO notifications (title, message, type, is_banner, created_by) VALUES (?, ?, ?, ?, ?)').bind(title, message || null, type || 'info', is_banner ? 1 : 0, auth.user.id).run();
  return { status: 201, body: { message: 'Created' } };
}

async function deleteNotification(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare('DELETE FROM notifications WHERE id = ?').bind(id).run();
  return { body: { message: 'Deleted' } };
}

async function getSupportTickets(request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  const t = await db.prepare('SELECT * FROM support_tickets ORDER BY created_at DESC').all();
  return { body: t.results };
}

async function resolveTicket(id, request, db) {
  const auth = await requireAdmin(request, db);
  if (auth.error) return { status: auth.status, body: { error: auth.error } };
  await db.prepare("UPDATE support_tickets SET status = 'resolved', resolved_at = datetime('now') WHERE id = ?").bind(id).run();
  return { body: { message: 'Resolved' } };
}

// ==================== ROUTER ====================
async function handleRequest(request, env) {
  const db = env.SITE_DB;
  const url = new URL(request.url);
  const path = url.pathname.replace('/api', '');
  const method = request.method;

  if (method === 'OPTIONS') return new Response(null, { headers: CORS_HEADERS });
  await ensureTables(db);

  try {
    let response;

    if (method === 'POST' && path === '/auth/login') response = await handleLogin(request, db);
    else if (method === 'POST' && path === '/auth/signup') response = await handleSignup(request, db);
    else if (method === 'POST' && path === '/auth/logout') response = await handleLogout(request, db);
    else if (method === 'GET' && path === '/courses') response = await getPublicCourses(request, db);
    else if (method === 'GET' && path.match(/^\/courses\/(\d+)$/)) response = await getCourseTree(parseInt(path.match(/^\/courses\/(\d+)$/)[1]), db);
    else if (method === 'GET' && path === '/stats') response = await getPublicStats(db);
    else if (method === 'GET' && path === '/subject-areas') response = await getSubjectAreas(db);
    else if (method === 'POST' && path === '/contact') response = await submitContact(request, db);
    else if (method === 'GET' && path === '/user/profile') response = await getUserProfile(request, db);
    else if (method === 'GET' && path === '/user/memberships') response = await getUserMemberships(request, db);
    else if (method === 'GET' && path === '/user/notifications') response = await getUserNotifications(request, db);
    else if (method === 'PUT' && path === '/user/notifications/read') response = await markNotificationRead(request, db);
    else if (method === 'PUT' && path === '/user/notifications/read-all') response = await markAllNotificationsRead(request, db);
    else if (method === 'GET' && path.match(/^\/user\/lecture\/(\d+)$/)) response = await getLecture(parseInt(path.match(/^\/user\/lecture\/(\d+)$/)[1]), request, db);
    else if (method === 'POST' && path === '/payment/submit') response = await submitPayment(request, db);
    else if (method === 'GET' && path === '/admin/stats') response = await getAdminStats(request, db);
    else if (method === 'GET' && path === '/admin/users') response = await getAdminUsers(request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/users\/(\d+)\/approve$/)) response = await approveUser(parseInt(path.match(/^\/admin\/users\/(\d+)\/approve$/)[1]), request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/users\/(\d+)\/block$/)) response = await toggleBlockUser(parseInt(path.match(/^\/admin\/users\/(\d+)\/block$/)[1]), request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/users\/(\d+)\/clear-device$/)) response = await clearUserDevice(parseInt(path.match(/^\/admin\/users\/(\d+)\/clear-device$/)[1]), request, db);
    else if (method === 'DELETE' && path.match(/^\/admin\/users\/(\d+)$/)) response = await deleteUser(parseInt(path.match(/^\/admin\/users\/(\d+)$/)[1]), request, db);
    else if (method === 'GET' && path === '/admin/courses') response = await getAdminCourses(request, db);
    else if (method === 'POST' && path === '/admin/courses') response = await createCourse(request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/courses\/(\d+)$/)) response = await updateCourse(parseInt(path.match(/^\/admin\/courses\/(\d+)$/)[1]), request, db);
    else if (method === 'DELETE' && path.match(/^\/admin\/courses\/(\d+)$/)) response = await deleteCourse(parseInt(path.match(/^\/admin\/courses\/(\d+)$/)[1]), request, db);
    else if (method === 'POST' && path === '/admin/subjects') response = await createSubject(request, db);
    else if (method === 'POST' && path === '/admin/papers') response = await createPaper(request, db);
    else if (method === 'POST' && path === '/admin/chapters') response = await createChapter(request, db);
    else if (method === 'GET' && path === '/admin/all-lectures') response = await getAllLectures(request, db);
    else if (method === 'POST' && path === '/admin/lectures') response = await createLecture(request, db);
    else if (method === 'DELETE' && path.match(/^\/admin\/lectures\/(\d+)$/)) response = await deleteLecture(parseInt(path.match(/^\/admin\/lectures\/(\d+)$/)[1]), request, db);
    else if (method === 'POST' && path === '/admin/lecture-pdfs') response = await addLecturePdf(request, db);
    else if (method === 'DELETE' && path.match(/^\/admin\/lecture-pdfs\/(\d+)$/)) response = await deleteLecturePdf(parseInt(path.match(/^\/admin\/lecture-pdfs\/(\d+)$/)[1]), request, db);
    else if (method === 'GET' && path.match(/^\/admin\/resources\/course\/(\d+)$/)) response = await getCourseResources(parseInt(path.match(/^\/admin\/resources\/course\/(\d+)$/)[1]), request, db);
    else if (method === 'POST' && path === '/admin/resources') response = await addResource(request, db);
    else if (method === 'DELETE' && path.match(/^\/admin\/resources\/(\d+)$/)) response = await deleteResource(parseInt(path.match(/^\/admin\/resources\/(\d+)$/)[1]), request, db);
    else if (method === 'GET' && path === '/admin/memberships') response = await getAdminMemberships(request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/memberships\/(\d+)\/verify-payment$/)) response = await verifyPayment(parseInt(path.match(/^\/admin\/memberships\/(\d+)\/verify-payment$/)[1]), request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/memberships\/(\d+)\/reject-payment$/)) response = await rejectPayment(parseInt(path.match(/^\/admin\/memberships\/(\d+)\/reject-payment$/)[1]), request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/memberships\/(\d+)\/extend$/)) response = await extendMembership(parseInt(path.match(/^\/admin\/memberships\/(\d+)\/extend$/)[1]), request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/memberships\/(\d+)\/cancel$/)) response = await cancelMembership(parseInt(path.match(/^\/admin\/memberships\/(\d+)\/cancel$/)[1]), request, db);
    else if (method === 'GET' && path === '/admin/notifications') response = await getAdminNotifications(request, db);
    else if (method === 'POST' && path === '/admin/notifications') response = await createNotification(request, db);
    else if (method === 'DELETE' && path.match(/^\/admin\/notifications\/(\d+)$/)) response = await deleteNotification(parseInt(path.match(/^\/admin\/notifications\/(\d+)$/)[1]), request, db);
    else if (method === 'GET' && path === '/admin/support-tickets') response = await getSupportTickets(request, db);
    else if (method === 'PUT' && path.match(/^\/admin\/support-tickets\/(\d+)\/resolve$/)) response = await resolveTicket(parseInt(path.match(/^\/admin\/support-tickets\/(\d+)\/resolve$/)[1]), request, db);
    else response = { error: 'Not found', status: 404 };

    return new Response(JSON.stringify(response.body || response), { status: response.status || 200, headers: CORS_HEADERS });
  } catch (err) {
    console.error(err);
    return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500, headers: CORS_HEADERS });
  }
}

export default { async fetch(request, env) { return handleRequest(request, env); } };
