// ─────────────────────────────────────────────────────────────
//  RoofBoard API Server  —  Node.js + Express + SQLite
//  With authentication and role-based permissions
// ─────────────────────────────────────────────────────────────
const express  = require('express');
const Database = require('better-sqlite3');
const cors     = require('cors');
const crypto   = require('crypto');
const path     = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'roofboard.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');

// ── Schema ────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS jobs (
    id                TEXT PRIMARY KEY,
    jobNum            TEXT NOT NULL,
    customer          TEXT NOT NULL,
    address           TEXT DEFAULT '',
    type              TEXT NOT NULL DEFAULT 'comp',
    crew              TEXT,
    tearoffDate       TEXT,
    installDate       TEXT,
    gutterDate        TEXT,
    duration          TEXT DEFAULT '1 day',
    gutterProfile     TEXT,
    gutterMaterial    TEXT,
    gutterScreen      TEXT,
    gutterInstruction TEXT DEFAULT 'na',
    gutterMaterials   TEXT DEFAULT '',
    includesGutters   INTEGER DEFAULT 0,
    reroofComplete    INTEGER DEFAULT 0,
    warranty          INTEGER DEFAULT 0,
    layerStack        TEXT DEFAULT '[]',
    materials         TEXT DEFAULT '',
    notes             TEXT DEFAULT '',
    createdAt         TEXT NOT NULL,
    updatedAt         TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS inspections (
    id        TEXT PRIMARY KEY,
    jobId     TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    type      TEXT NOT NULL DEFAULT 'tearoff',
    date      TEXT,
    sortOrder INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS users (
    id            TEXT PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    passwordHash  TEXT NOT NULL,
    salt          TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'sales',
    fullName      TEXT DEFAULT '',
    active        INTEGER DEFAULT 1,
    mustChangePwd INTEGER DEFAULT 0,
    createdAt     TEXT NOT NULL,
    lastLogin     TEXT
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token     TEXT PRIMARY KEY,
    userId    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expiresAt TEXT NOT NULL,
    createdAt TEXT NOT NULL
  );
`);

// ── Roles ─────────────────────────────────────────────────────
// admin        — full access including user management and delete
// scheduler    — full job access including dates, no delete, no user mgmt
// office_staff — full job edit except scheduling dates, no delete
// sales        — view only + edit notes field only, cannot add jobs

const ROLES = ['admin','scheduler','office_staff','sales'];

// ── Crypto helpers ────────────────────────────────────────────
function newId(p='id'){ return p+'_'+Date.now()+'_'+Math.random().toString(36).slice(2,7); }
function now(){ return new Date().toISOString(); }
function hashPassword(password, salt){
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
function generateSalt(){ return crypto.randomBytes(32).toString('hex'); }
function generateToken(){ return crypto.randomBytes(48).toString('hex'); }
function sessionExpiry(){
  const d = new Date();
  d.setHours(d.getHours()+8); // 8 hour sessions
  return d.toISOString();
}

// ── Seed default admin if no users exist ──────────────────────
const userCount = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
if(userCount === 0){
  const salt = generateSalt();
  const hash = hashPassword('Roofboard2024!', salt);
  db.prepare(`INSERT INTO users (id,username,passwordHash,salt,role,fullName,active,mustChangePwd,createdAt)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(
    newId('u'), 'losgatosroofingadmin', hash, salt, 'admin', 'Administrator', 1, 1, now()
  );
  console.log('Default admin created: losgatosroofingadmin / Roofboard2024!');
}

// ── Parse job row ─────────────────────────────────────────────
function parseJob(row){
  if(!row) return null;
  return {
    ...row,
    includesGutters: !!row.includesGutters,
    reroofComplete:  !!row.reroofComplete,
    warranty:        !!row.warranty,
    layerStack:      JSON.parse(row.layerStack||'[]'),
  };
}

// ── Auth middleware ───────────────────────────────────────────
function requireAuth(req, res, next){
  const token = req.headers['authorization']?.replace('Bearer ','');
  if(!token) return res.status(401).json({error:'Not logged in'});
  const session = db.prepare('SELECT * FROM sessions WHERE token=?').get(token);
  if(!session) return res.status(401).json({error:'Invalid session'});
  if(new Date(session.expiresAt) < new Date()){
    db.prepare('DELETE FROM sessions WHERE token=?').run(token);
    return res.status(401).json({error:'Session expired'});
  }
  const user = db.prepare('SELECT * FROM users WHERE id=?').get(session.userId);
  if(!user||!user.active) return res.status(401).json({error:'User not found or inactive'});
  req.user = user;
  req.token = token;
  next();
}

function requireRole(...roles){
  return (req, res, next) => {
    if(!roles.includes(req.user.role))
      return res.status(403).json({error:'Permission denied'});
    next();
  };
}

// ── Auth routes ───────────────────────────────────────────────

// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if(!username||!password) return res.status(400).json({error:'Username and password required'});
    const user = db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(username.toLowerCase().trim());
    if(!user) return res.status(401).json({error:'Invalid username or password'});
    const hash = hashPassword(password, user.salt);
    if(hash !== user.passwordHash) return res.status(401).json({error:'Invalid username or password'});

    // Clean old sessions for this user
    db.prepare('DELETE FROM sessions WHERE userId=?').run(user.id);

    const token = generateToken();
    db.prepare('INSERT INTO sessions (token,userId,expiresAt,createdAt) VALUES (?,?,?,?)').run(
      token, user.id, sessionExpiry(), now()
    );
    db.prepare('UPDATE users SET lastLogin=? WHERE id=?').run(now(), user.id);

    res.json({
      token,
      role: user.role,
      fullName: user.fullName,
      username: user.username,
      mustChangePwd: !!user.mustChangePwd,
      expiresAt: sessionExpiry(),
    });
  } catch(e){ res.status(500).json({error:e.message}); }
});

// POST /api/auth/logout
app.post('/api/auth/logout', requireAuth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token=?').run(req.token);
  res.json({ok:true});
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', requireAuth, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if(!newPassword||newPassword.length<8)
      return res.status(400).json({error:'New password must be at least 8 characters'});
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    // Skip current password check if mustChangePwd is set (first login)
    if(!user.mustChangePwd){
      if(!currentPassword) return res.status(400).json({error:'Current password required'});
      const hash = hashPassword(currentPassword, user.salt);
      if(hash !== user.passwordHash) return res.status(401).json({error:'Current password incorrect'});
    }
    const newSalt = generateSalt();
    const newHash = hashPassword(newPassword, newSalt);
    db.prepare('UPDATE users SET passwordHash=?,salt=?,mustChangePwd=0 WHERE id=?').run(newHash,newSalt,user.id);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({
    id: req.user.id,
    username: req.user.username,
    role: req.user.role,
    fullName: req.user.fullName,
    mustChangePwd: !!req.user.mustChangePwd,
  });
});

// ── User management (admin only) ──────────────────────────────

// GET /api/users
app.get('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  const users = db.prepare('SELECT id,username,role,fullName,active,mustChangePwd,createdAt,lastLogin FROM users ORDER BY createdAt ASC').all();
  res.json(users.map(u=>({...u,active:!!u.active,mustChangePwd:!!u.mustChangePwd})));
});

// POST /api/users
app.post('/api/users', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const { username, password, role, fullName } = req.body;
    if(!username||!password) return res.status(400).json({error:'Username and password required'});
    if(!ROLES.includes(role)) return res.status(400).json({error:'Invalid role'});
    if(password.length<8) return res.status(400).json({error:'Password must be at least 8 characters'});
    const existing = db.prepare('SELECT id FROM users WHERE username=?').get(username.toLowerCase().trim());
    if(existing) return res.status(409).json({error:'Username already exists'});
    const salt = generateSalt();
    const hash = hashPassword(password, salt);
    const id = newId('u');
    db.prepare(`INSERT INTO users (id,username,passwordHash,salt,role,fullName,active,mustChangePwd,createdAt)
      VALUES (?,?,?,?,?,?,?,?,?)`).run(
      id, username.toLowerCase().trim(), hash, salt, role, fullName||'', 1, 1, now()
    );
    res.status(201).json({id, username:username.toLowerCase().trim(), role, fullName:fullName||'', active:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// PATCH /api/users/:id
app.patch('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const user = db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
    if(!user) return res.status(404).json({error:'User not found'});
    // Prevent admin from deactivating themselves
    if(req.params.id === req.user.id && req.body.active === false)
      return res.status(400).json({error:'Cannot deactivate your own account'});
    const { role, fullName, active, password } = req.body;
    let salt = user.salt, hash = user.passwordHash;
    if(password){
      if(password.length<8) return res.status(400).json({error:'Password must be at least 8 characters'});
      salt = generateSalt();
      hash = hashPassword(password, salt);
    }
    db.prepare(`UPDATE users SET
      role=?,fullName=?,active=?,passwordHash=?,salt=?,mustChangePwd=?
      WHERE id=?`).run(
      role||user.role, fullName||user.fullName,
      active===undefined?user.active:(active?1:0),
      hash, salt,
      password?1:user.mustChangePwd,
      req.params.id
    );
    const updated = db.prepare('SELECT id,username,role,fullName,active,mustChangePwd FROM users WHERE id=?').get(req.params.id);
    res.json({...updated,active:!!updated.active,mustChangePwd:!!updated.mustChangePwd});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// DELETE /api/users/:id (admin only, cannot delete self)
app.delete('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    if(req.params.id === req.user.id)
      return res.status(400).json({error:'Cannot delete your own account'});
    const r = db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
    if(r.changes===0) return res.status(404).json({error:'User not found'});
    res.json({deleted:req.params.id});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Jobs ──────────────────────────────────────────────────────
// TV boards call GET /api/jobs with no auth — read only, no token needed
// All write operations require auth + role checks

// GET /api/jobs — public read (TV boards use this)
app.get('/api/jobs', (req, res) => {
  try {
    const { view, crew, updatedAfter } = req.query;
    let sql = 'SELECT * FROM jobs WHERE 1=1';
    const params = [];
    if(updatedAfter){ sql += ' AND updatedAt > ?'; params.push(updatedAfter); }
    if(view==='install'){
      sql += ' AND installDate IS NOT NULL AND installDate != \'\'';
      sql += ' AND crew IS NOT NULL AND crew != \'\' AND crew NOT IN (\'gutter\',\'removal\')';
      if(crew){ sql += ' AND crew = ?'; params.push(crew); }
    } else if(view==='gutters'){
      sql += ' AND gutterDate IS NOT NULL AND gutterDate != \'\'';
    }
    sql += ' ORDER BY jobNum ASC';
    res.json(db.prepare(sql).all(...params).map(parseJob));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// GET /api/jobs/:id — public read
app.get('/api/jobs/:id', (req, res) => {
  try {
    const row = db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
    if(!row) return res.status(404).json({error:'Not found'});
    res.json(parseJob(row));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// POST /api/jobs — admin, scheduler, office_staff only
app.post('/api/jobs', requireAuth, requireRole('admin','scheduler','office_staff'), (req, res) => {
  try {
    const j = req.body;
    if(!j.jobNum||!j.customer) return res.status(400).json({error:'jobNum and customer required'});
    const id = j.id || newId('j');
    const ts = now();
    db.prepare(`INSERT INTO jobs (
      id,jobNum,customer,address,type,crew,
      tearoffDate,installDate,gutterDate,duration,
      gutterProfile,gutterMaterial,gutterScreen,gutterInstruction,gutterMaterials,
      includesGutters,reroofComplete,warranty,layerStack,materials,notes,
      createdAt,updatedAt
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
      id,j.jobNum,j.customer,j.address||'',j.type||'comp',j.crew||null,
      j.tearoffDate||null,j.installDate||null,j.gutterDate||null,j.duration||'1 day',
      j.gutterProfile||null,j.gutterMaterial||null,j.gutterScreen||null,
      j.gutterInstruction||'na',j.gutterMaterials||'',
      j.includesGutters?1:0,j.reroofComplete?1:0,j.warranty?1:0,
      JSON.stringify(j.layerStack||[]),j.materials||'',j.notes||'',ts,ts
    );
    res.status(201).json(parseJob(db.prepare('SELECT * FROM jobs WHERE id=?').get(id)));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// PATCH /api/jobs/:id — role-based field restrictions enforced here
app.patch('/api/jobs/:id', requireAuth, (req, res) => {
  try {
    const role = req.user.role;
    // Sales can only edit notes
    if(role==='sales'){
      const allowed = ['notes'];
      const attempted = Object.keys(req.body).filter(k=>!allowed.includes(k));
      if(attempted.length>0)
        return res.status(403).json({error:'Sales role can only edit notes'});
    }
    // Office staff cannot edit scheduling dates
    if(role==='office_staff'){
      const restricted = ['tearoffDate','installDate','gutterDate'];
      const attempted = Object.keys(req.body).filter(k=>restricted.includes(k));
      if(attempted.length>0)
        return res.status(403).json({error:'Office staff cannot edit scheduling dates'});
    }
    // Viewers cannot edit anything (shouldn't reach here but double-check)
    if(!['admin','scheduler','office_staff','sales'].includes(role))
      return res.status(403).json({error:'Permission denied'});

    const existing = db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
    if(!existing) return res.status(404).json({error:'Not found'});
    const j = {...parseJob(existing),...req.body};
    db.prepare(`UPDATE jobs SET
      jobNum=?,customer=?,address=?,type=?,crew=?,
      tearoffDate=?,installDate=?,gutterDate=?,duration=?,
      gutterProfile=?,gutterMaterial=?,gutterScreen=?,gutterInstruction=?,gutterMaterials=?,
      includesGutters=?,reroofComplete=?,warranty=?,layerStack=?,materials=?,notes=?,
      updatedAt=?
    WHERE id=?`).run(
      j.jobNum,j.customer,j.address||'',j.type||'comp',j.crew||null,
      j.tearoffDate||null,j.installDate||null,j.gutterDate||null,j.duration||'1 day',
      j.gutterProfile||null,j.gutterMaterial||null,j.gutterScreen||null,
      j.gutterInstruction||'na',j.gutterMaterials||'',
      j.includesGutters?1:0,j.reroofComplete?1:0,j.warranty?1:0,
      JSON.stringify(j.layerStack||[]),j.materials||'',j.notes||'',
      now(),req.params.id
    );
    res.json(parseJob(db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id)));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// DELETE /api/jobs/:id — admin only
app.delete('/api/jobs/:id', requireAuth, requireRole('admin'), (req, res) => {
  try {
    const r = db.prepare('DELETE FROM jobs WHERE id=?').run(req.params.id);
    if(r.changes===0) return res.status(404).json({error:'Not found'});
    res.json({deleted:req.params.id});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Inspections ───────────────────────────────────────────────
app.get('/api/jobs/:jobId/inspections', (req, res) => {
  try {
    res.json(db.prepare('SELECT * FROM inspections WHERE jobId=? ORDER BY sortOrder').all(req.params.jobId));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.put('/api/jobs/:jobId/inspections', requireAuth, requireRole('admin','scheduler','office_staff'), (req, res) => {
  try {
    const jobId = req.params.jobId;
    if(!Array.isArray(req.body)) return res.status(400).json({error:'Expected array'});
    db.transaction(()=>{
      db.prepare('DELETE FROM inspections WHERE jobId=?').run(jobId);
      req.body.forEach((insp,i)=>{
        db.prepare('INSERT INTO inspections (id,jobId,type,date,sortOrder) VALUES (?,?,?,?,?)').run(
          newId('i'),jobId,insp.type||'tearoff',insp.date||null,i
        );
      });
      db.prepare('UPDATE jobs SET updatedAt=? WHERE id=?').run(now(),jobId);
    })();
    res.json(db.prepare('SELECT * FROM inspections WHERE jobId=? ORDER BY sortOrder').all(jobId));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Health ────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({status:'ok', jobs:db.prepare('SELECT COUNT(*) as n FROM jobs').get().n});
});

app.listen(PORT, ()=>console.log(`RoofBoard API on port ${PORT}`));
