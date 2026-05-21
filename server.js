// ─────────────────────────────────────────────────────────────
//  RoofBoard API Server  v5.0
//  Node.js + Express + SQLite
//  Features: Auth, Roles, Crews, Consultants, Roof Materials,
//            Archive, Security hardening
// ─────────────────────────────────────────────────────────────
const express  = require('express');
const Database = require('better-sqlite3');
const cors     = require('cors');
const crypto   = require('crypto');
const path     = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Allowed origin (set to your Netlify URL in Railway Variables) ──
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || '*';

// ── Security headers ──────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  next();
});

// ── CORS ──────────────────────────────────────────────────────
app.use(cors({
  origin: ALLOWED_ORIGIN === '*' ? '*' : (origin, cb) => {
    if(!origin || origin === ALLOWED_ORIGIN) cb(null, true);
    else cb(new Error('Not allowed by CORS'));
  },
  methods: ['GET','POST','PATCH','PUT','DELETE'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

app.use(express.json({ limit: '100kb' }));

// ── Rate limiting (in-memory, resets on server restart) ───────
const loginAttempts = new Map();
const RATE_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS   = 5;

function checkRateLimit(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
  if(now > rec.resetAt) { rec.count = 0; rec.resetAt = now + RATE_WINDOW_MS; }
  rec.count++;
  loginAttempts.set(ip, rec);
  return rec.count <= MAX_ATTEMPTS;
}
function clearRateLimit(ip) { loginAttempts.delete(ip); }

// ── Input sanitization helper ─────────────────────────────────
function sanitize(val) {
  if(typeof val !== 'string') return val;
  return val.replace(/<[^>]*>/g, '').trim().slice(0, 2000);
}
function sanitizeJob(j) {
  const fields = ['jobNum','customer','address','materials','gutterMaterials',
    'notes','gutterScreen','existingRoofNotes','squares','manufacturer',
    'productName','color','installerNotes','tearoffNotes','gutterNotes'];
  const out = {...j};
  fields.forEach(f => { if(out[f]) out[f] = sanitize(out[f]); });
  return out;
}

// ── Database ──────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'roofboard.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ── Schema ────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS roof_materials (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE,
    colorBg   TEXT NOT NULL DEFAULT '#f0f0ec',
    colorText TEXT NOT NULL DEFAULT '#444',
    colorBorder TEXT NOT NULL DEFAULT '#ccc',
    active    INTEGER DEFAULT 1,
    sortOrder INTEGER DEFAULT 0,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS crews (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL,
    type      TEXT NOT NULL CHECK(type IN ('install','gutter','removal')),
    active    INTEGER DEFAULT 1,
    sortOrder INTEGER DEFAULT 0,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS consultants (
    id        TEXT PRIMARY KEY,
    name      TEXT NOT NULL UNIQUE,
    initials  TEXT NOT NULL,
    active    INTEGER DEFAULT 1,
    createdAt TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS jobs (
    id                  TEXT PRIMARY KEY,
    jobNum              TEXT NOT NULL,
    customer            TEXT NOT NULL,
    address             TEXT DEFAULT '',
    newRoofMaterialId   TEXT,
    existingRoofMaterialId TEXT,
    existingDeckType    TEXT DEFAULT '',
    newDeckType         TEXT DEFAULT '',
    existingRoofNotes   TEXT DEFAULT '',
    steepPitch          INTEGER DEFAULT 0,
    removalCrewId       TEXT,
    tearoffDate         TEXT,
    installCrewId       TEXT,
    installDate         TEXT,
    gutterCrewId        TEXT,
    gutterDate          TEXT,
    duration            TEXT DEFAULT '1 day',
    gutterProfile       TEXT,
    gutterMaterial      TEXT,
    gutterScreen        TEXT,
    gutterInstruction   TEXT DEFAULT 'na',
    gutterMaterials     TEXT DEFAULT '',
    includesGutters     INTEGER DEFAULT 0,
    reroofComplete      INTEGER DEFAULT 0,
    warranty            INTEGER DEFAULT 0,
    layerStack          TEXT DEFAULT '[]',
    materials           TEXT DEFAULT '',
    notes               TEXT DEFAULT '',
    startDateApproval   TEXT DEFAULT 'pending',
    consultantId        TEXT,
    backlogCategory     TEXT DEFAULT 'regular',
    archived            INTEGER DEFAULT 0,
    completedAt         TEXT,
    createdAt           TEXT NOT NULL,
    updatedAt           TEXT NOT NULL
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

// ── Seed default roof materials ───────────────────────────────
const matCount = db.prepare('SELECT COUNT(*) as n FROM roof_materials').get().n;
if(matCount === 0){
  const defaults = [
    { name:'Comp',        colorBg:'#FFF9C4', colorText:'#7A6800', colorBorder:'#F0C800', sort:0 },
    { name:'Tile',        colorBg:'#FFE0B2', colorText:'#7A3800', colorBorder:'#F07800', sort:1 },
    { name:'Metal',       colorBg:'#ECEFF1', colorText:'#37474F', colorBorder:'#90A4AE', sort:2 },
    { name:'Wood',        colorBg:'#F5F5F5', colorText:'#555',    colorBorder:'#BDBDBD', sort:3 },
    { name:'Flat/TPO',    colorBg:'#BBDEFB', colorText:'#0D47A1', colorBorder:'#2196F3', sort:4 },
    { name:'Polymer',     colorBg:'#B2DFDB', colorText:'#00695C', colorBorder:'#00897B', sort:5 },
    { name:'Gutters Only',colorBg:'#C8EEE0', colorText:'#085041', colorBorder:'#1D9E75', sort:6 },
    { name:'Repairs',     colorBg:'#FDE6D8', colorText:'#712B13', colorBorder:'#D85A30', sort:7 },
    { name:'Other',       colorBg:'#E8E6FD', colorText:'#3C3489', colorBorder:'#534AB7', sort:8 },
  ];
  const ins = db.prepare('INSERT INTO roof_materials (id,name,colorBg,colorText,colorBorder,active,sortOrder,createdAt) VALUES (?,?,?,?,?,1,?,?)');
  defaults.forEach(m => ins.run(newId('m'), m.name, m.colorBg, m.colorText, m.colorBorder, m.sort, now()));
}

// ── Seed default admin ────────────────────────────────────────
const userCount = db.prepare('SELECT COUNT(*) as n FROM users').get().n;
if(userCount === 0){
  const salt = generateSalt();
  const hash = hashPassword('Roofboard2024!', salt);
  db.prepare(`INSERT INTO users (id,username,passwordHash,salt,role,fullName,active,mustChangePwd,createdAt)
    VALUES (?,?,?,?,?,?,?,?,?)`).run(
    newId('u'),'losgatosroofingadmin',hash,salt,'admin','Administrator',1,1,now()
  );
}

// ── Helpers ───────────────────────────────────────────────────
function newId(p='id'){ return p+'_'+Date.now()+'_'+Math.random().toString(36).slice(2,7); }
function now(){ return new Date().toISOString(); }
function hashPassword(pw,salt){ return crypto.pbkdf2Sync(pw,salt,100000,64,'sha512').toString('hex'); }
function generateSalt(){ return crypto.randomBytes(32).toString('hex'); }
function generateToken(){ return crypto.randomBytes(48).toString('hex'); }
function sessionExpiry(){ const d=new Date(); d.setHours(d.getHours()+8); return d.toISOString(); }

function parseJob(row){
  if(!row) return null;
  // Parse crew fields — handle both legacy string IDs and JSON arrays
  function parseCrews(val){
    if(!val) return [];
    try {
      const parsed = JSON.parse(val);
      if(Array.isArray(parsed)) return parsed.filter(Boolean);
      return [parsed].filter(Boolean);
    } catch {
      return [val].filter(Boolean);
    }
  }
  return {
    ...row,
    includesGutters:  !!row.includesGutters,
    reroofComplete:   !!row.reroofComplete,
    warranty:         !!row.warranty,
    steepPitch:       !!row.steepPitch,
    archived:         !!row.archived,
    layerStack:       JSON.parse(row.layerStack||'[]'),
    removalCrewIds:   parseCrews(row.removalCrewId),
    installCrewIds:   parseCrews(row.installCrewId),
    gutterCrewIds:    parseCrews(row.gutterCrewId),
  };
}

// ── Migration: add new fields (safe to run multiple times) ───
const newCols = [
  ['squares',        'TEXT DEFAULT \'\''],
  ['manufacturer',   'TEXT DEFAULT \'\''],
  ['productName',    'TEXT DEFAULT \'\''],
  ['color',          'TEXT DEFAULT \'\''],
  ['installerNotes', 'TEXT DEFAULT \'\''],
  ['tearoffNotes',   'TEXT DEFAULT \'\''],
  ['gutterNotes',    'TEXT DEFAULT \'\''],
];
newCols.forEach(([col, def]) => {
  try { db.exec(`ALTER TABLE jobs ADD COLUMN ${col} ${def}`); } catch(e) {}
});

// Migrate existing notes → installerNotes (only where installerNotes is empty)
try {
  db.exec(`UPDATE jobs SET installerNotes = notes WHERE notes != '' AND (installerNotes IS NULL OR installerNotes = '')`);
  console.log('Notes migration complete');
} catch(e) { console.error('Notes migration error:', e.message); }


try {
  const jobs = db.prepare('SELECT id, removalCrewId, installCrewId, gutterCrewId FROM jobs').all();
  const update = db.prepare('UPDATE jobs SET removalCrewId=?, installCrewId=?, gutterCrewId=? WHERE id=?');
  db.transaction(() => {
    jobs.forEach(j => {
      function toArray(val) {
        if(!val) return '[]';
        try { const p=JSON.parse(val); if(Array.isArray(p)) return val; return JSON.stringify([val]); }
        catch { return JSON.stringify([val]); }
      }
      update.run(toArray(j.removalCrewId), toArray(j.installCrewId), toArray(j.gutterCrewId), j.id);
    });
  })();
  console.log('Crew migration complete');
} catch(e) { console.error('Crew migration error:', e.message); }

// ── Auth middleware ───────────────────────────────────────────
function requireAuth(req,res,next){
  const token=req.headers['authorization']?.replace('Bearer ','');
  if(!token) return res.status(401).json({error:'Not logged in'});
  const session=db.prepare('SELECT * FROM sessions WHERE token=?').get(token);
  if(!session) return res.status(401).json({error:'Invalid session'});
  if(new Date(session.expiresAt)<new Date()){
    db.prepare('DELETE FROM sessions WHERE token=?').run(token);
    return res.status(401).json({error:'Session expired'});
  }
  const user=db.prepare('SELECT * FROM users WHERE id=?').get(session.userId);
  if(!user||!user.active) return res.status(401).json({error:'User not found or inactive'});
  req.user=user; req.token=token; next();
}
function requireRole(...roles){
  return (req,res,next)=>{
    if(!roles.includes(req.user.role)) return res.status(403).json({error:'Permission denied'});
    next();
  };
}

// ── Auth routes ───────────────────────────────────────────────
app.post('/api/auth/login', (req,res)=>{
  const ip = req.headers['x-forwarded-for']||req.ip||'unknown';
  if(!checkRateLimit(ip)) return res.status(429).json({error:'Too many login attempts. Try again in 15 minutes.'});
  try {
    const {username,password}=req.body;
    if(!username||!password) return res.status(400).json({error:'Username and password required'});
    const user=db.prepare('SELECT * FROM users WHERE username=? AND active=1').get(username.toLowerCase().trim());
    if(!user){ return res.status(401).json({error:'Invalid username or password'}); }
    const hash=hashPassword(password,user.salt);
    if(hash!==user.passwordHash){ return res.status(401).json({error:'Invalid username or password'}); }
    clearRateLimit(ip);
    db.prepare('DELETE FROM sessions WHERE userId=?').run(user.id);
    const token=generateToken();
    db.prepare('INSERT INTO sessions (token,userId,expiresAt,createdAt) VALUES (?,?,?,?)').run(
      token,user.id,sessionExpiry(),now()
    );
    db.prepare('UPDATE users SET lastLogin=? WHERE id=?').run(now(),user.id);
    res.json({token,role:user.role,fullName:user.fullName,username:user.username,mustChangePwd:!!user.mustChangePwd,expiresAt:sessionExpiry()});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/auth/logout',requireAuth,(req,res)=>{
  db.prepare('DELETE FROM sessions WHERE token=?').run(req.token);
  res.json({ok:true});
});

app.post('/api/auth/change-password',requireAuth,(req,res)=>{
  try {
    const {currentPassword,newPassword}=req.body;
    if(!newPassword||newPassword.length<8) return res.status(400).json({error:'Password must be at least 8 characters'});
    const user=db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
    if(!user.mustChangePwd){
      if(!currentPassword) return res.status(400).json({error:'Current password required'});
      if(hashPassword(currentPassword,user.salt)!==user.passwordHash) return res.status(401).json({error:'Current password incorrect'});
    }
    const salt=generateSalt(), hash=hashPassword(newPassword,salt);
    db.prepare('UPDATE users SET passwordHash=?,salt=?,mustChangePwd=0 WHERE id=?').run(hash,salt,user.id);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/auth/me',requireAuth,(req,res)=>{
  res.json({id:req.user.id,username:req.user.username,role:req.user.role,fullName:req.user.fullName,mustChangePwd:!!req.user.mustChangePwd});
});

// ── Users ─────────────────────────────────────────────────────
app.get('/api/users',requireAuth,requireRole('admin'),(req,res)=>{
  const users=db.prepare('SELECT id,username,role,fullName,active,mustChangePwd,createdAt,lastLogin FROM users ORDER BY createdAt ASC').all();
  res.json(users.map(u=>({...u,active:!!u.active,mustChangePwd:!!u.mustChangePwd})));
});

app.post('/api/users',requireAuth,requireRole('admin'),(req,res)=>{
  try {
    const {username,password,role,fullName}=req.body;
    const VALID_ROLES=['admin','scheduler','office_staff','sales','removal_foreman','supplier'];
    if(!username||!password) return res.status(400).json({error:'Username and password required'});
    if(!VALID_ROLES.includes(role)) return res.status(400).json({error:'Invalid role'});
    if(password.length<8) return res.status(400).json({error:'Password must be at least 8 characters'});
    if(db.prepare('SELECT id FROM users WHERE username=?').get(username.toLowerCase().trim())) return res.status(409).json({error:'Username already exists'});
    const salt=generateSalt(), hash=hashPassword(password,salt), id=newId('u');
    db.prepare('INSERT INTO users (id,username,passwordHash,salt,role,fullName,active,mustChangePwd,createdAt) VALUES (?,?,?,?,?,?,?,?,?)').run(
      id,username.toLowerCase().trim(),hash,salt,role,fullName||'',1,1,now()
    );
    res.status(201).json({id,username:username.toLowerCase().trim(),role,fullName:fullName||'',active:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.patch('/api/users/:id',requireAuth,requireRole('admin'),(req,res)=>{
  try {
    const user=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);
    if(!user) return res.status(404).json({error:'Not found'});
    if(req.params.id===req.user.id&&req.body.active===false) return res.status(400).json({error:'Cannot deactivate your own account'});
    const {role,fullName,active,password}=req.body;
    let salt=user.salt, hash=user.passwordHash;
    if(password){ if(password.length<8) return res.status(400).json({error:'Password too short'}); salt=generateSalt(); hash=hashPassword(password,salt); }
    db.prepare('UPDATE users SET role=?,fullName=?,active=?,passwordHash=?,salt=?,mustChangePwd=? WHERE id=?').run(
      role||user.role,fullName??user.fullName,active===undefined?user.active:(active?1:0),hash,salt,password?1:user.mustChangePwd,req.params.id
    );
    const u=db.prepare('SELECT id,username,role,fullName,active,mustChangePwd FROM users WHERE id=?').get(req.params.id);
    res.json({...u,active:!!u.active,mustChangePwd:!!u.mustChangePwd});
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/users/:id',requireAuth,requireRole('admin'),(req,res)=>{
  try {
    if(req.params.id===req.user.id) return res.status(400).json({error:'Cannot delete your own account'});
    const r=db.prepare('DELETE FROM users WHERE id=?').run(req.params.id);
    if(r.changes===0) return res.status(404).json({error:'Not found'});
    res.json({deleted:req.params.id});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Crews ─────────────────────────────────────────────────────
app.get('/api/crews',(req,res)=>{
  try {
    const {type}=req.query;
    let sql='SELECT * FROM crews WHERE active=1';
    const params=[];
    if(type){ sql+=' AND type=?'; params.push(type); }
    sql+=' ORDER BY sortOrder ASC, name ASC';
    res.json(db.prepare(sql).all(...params));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/crews',requireAuth,requireRole('admin','scheduler'),(req,res)=>{
  try {
    const {name,type,sortOrder}=req.body;
    if(!name||!type) return res.status(400).json({error:'Name and type required'});
    if(!['install','gutter','removal'].includes(type)) return res.status(400).json({error:'Invalid type'});
    const id=newId('cr');
    db.prepare('INSERT INTO crews (id,name,type,active,sortOrder,createdAt) VALUES (?,?,?,1,?,?)').run(
      id,sanitize(name),type,sortOrder||0,now()
    );
    res.status(201).json(db.prepare('SELECT * FROM crews WHERE id=?').get(id));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.patch('/api/crews/:id',requireAuth,requireRole('admin','scheduler'),(req,res)=>{
  try {
    const crew=db.prepare('SELECT * FROM crews WHERE id=?').get(req.params.id);
    if(!crew) return res.status(404).json({error:'Not found'});
    const {name,active,sortOrder}=req.body;
    db.prepare('UPDATE crews SET name=?,active=?,sortOrder=? WHERE id=?').run(
      sanitize(name)||crew.name,active===undefined?crew.active:(active?1:0),sortOrder??crew.sortOrder,req.params.id
    );
    res.json(db.prepare('SELECT * FROM crews WHERE id=?').get(req.params.id));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Roof Materials ────────────────────────────────────────────
app.get('/api/roof-materials',(req,res)=>{
  try {
    res.json(db.prepare('SELECT * FROM roof_materials WHERE active=1 ORDER BY sortOrder ASC, name ASC').all());
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/roof-materials',requireAuth,requireRole('admin','scheduler','office_staff'),(req,res)=>{
  try {
    const {name,colorBg,colorText,colorBorder}=req.body;
    if(!name) return res.status(400).json({error:'Name required'});
    const trimmed=sanitize(name);
    const existing=db.prepare('SELECT * FROM roof_materials WHERE name=?').get(trimmed);
    if(existing){ db.prepare('UPDATE roof_materials SET active=1 WHERE id=?').run(existing.id); return res.json(db.prepare('SELECT * FROM roof_materials WHERE id=?').get(existing.id)); }
    const id=newId('m');
    const maxSort=db.prepare('SELECT MAX(sortOrder) as m FROM roof_materials').get().m||0;
    db.prepare('INSERT INTO roof_materials (id,name,colorBg,colorText,colorBorder,active,sortOrder,createdAt) VALUES (?,?,?,?,?,1,?,?)').run(
      id,trimmed,colorBg||'#E8E6FD',colorText||'#3C3489',colorBorder||'#534AB7',maxSort+1,now()
    );
    res.status(201).json(db.prepare('SELECT * FROM roof_materials WHERE id=?').get(id));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.patch('/api/roof-materials/:id',requireAuth,requireRole('admin'),(req,res)=>{
  try {
    const mat=db.prepare('SELECT * FROM roof_materials WHERE id=?').get(req.params.id);
    if(!mat) return res.status(404).json({error:'Not found'});
    const {name,colorBg,colorText,colorBorder,active,sortOrder}=req.body;
    db.prepare('UPDATE roof_materials SET name=?,colorBg=?,colorText=?,colorBorder=?,active=?,sortOrder=? WHERE id=?').run(
      sanitize(name)||mat.name,colorBg||mat.colorBg,colorText||mat.colorText,colorBorder||mat.colorBorder,
      active===undefined?mat.active:(active?1:0),sortOrder??mat.sortOrder,req.params.id
    );
    res.json(db.prepare('SELECT * FROM roof_materials WHERE id=?').get(req.params.id));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Consultants ───────────────────────────────────────────────
app.get('/api/consultants',(req,res)=>{
  try { res.json(db.prepare('SELECT * FROM consultants WHERE active=1 ORDER BY name ASC').all()); }
  catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/consultants',requireAuth,requireRole('admin','scheduler','office_staff'),(req,res)=>{
  try {
    const name=sanitize(req.body.name||'');
    if(!name) return res.status(400).json({error:'Name required'});
    const initials=name.split(' ').map(w=>w[0]||'').join('').toUpperCase().slice(0,3);
    const existing=db.prepare('SELECT * FROM consultants WHERE name=?').get(name);
    if(existing){ db.prepare('UPDATE consultants SET active=1 WHERE id=?').run(existing.id); return res.json({...existing,active:true}); }
    const id=newId('c');
    db.prepare('INSERT INTO consultants (id,name,initials,active,createdAt) VALUES (?,?,?,1,?)').run(id,name,initials,now());
    res.status(201).json(db.prepare('SELECT * FROM consultants WHERE id=?').get(id));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.delete('/api/consultants/:id',requireAuth,requireRole('admin'),(req,res)=>{
  try { db.prepare('UPDATE consultants SET active=0 WHERE id=?').run(req.params.id); res.json({deleted:req.params.id}); }
  catch(e){ res.status(500).json({error:e.message}); }
});

// ── Jobs — read (public for TV boards) ───────────────────────
app.get('/api/jobs',(req,res)=>{
  try {
    const {view,crewId,updatedAfter,archived}=req.query;
    let sql='SELECT * FROM jobs WHERE 1=1';
    const params=[];
    if(archived==='1'){ sql+=' AND archived=1'; }
    else { sql+=' AND archived=0'; }
    if(updatedAfter){ sql+=' AND updatedAt > ?'; params.push(updatedAfter); }
    if(view==='install'){
      sql+=' AND installDate IS NOT NULL AND installDate != \'\'';
      sql+=' AND installCrewId IS NOT NULL AND installCrewId != \'\' AND installCrewId != \'[]\'';
    } else if(view==='gutters'){
      sql+=' AND gutterDate IS NOT NULL AND gutterDate != \'\'';
      sql+=' AND gutterCrewId IS NOT NULL AND gutterCrewId != \'\' AND gutterCrewId != \'[]\'';
    }
    // Note: removal board fetches ALL jobs (no filter) so it can show both scheduled and backlog
    sql+=' ORDER BY jobNum ASC';
    let jobs = db.prepare(sql).all(...params).map(parseJob);
    // Post-filter by crewId if specified (crew is now an array)
    if(crewId){
      jobs = jobs.filter(j=>{
        if(view==='install') return j.installCrewIds.includes(crewId);
        if(view==='gutters') return j.gutterCrewIds.includes(crewId);
        if(view==='removal') return j.removalCrewIds.includes(crewId);
        return true;
      });
    }
    res.json(jobs);
  } catch(e){ res.status(500).json({error:e.message}); }
});
app.get('/api/jobs/:id',(req,res)=>{
  try {
    const row=db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
    if(!row) return res.status(404).json({error:'Not found'});
    res.json(parseJob(row));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Jobs — write (auth required) ─────────────────────────────
const CAN_ADD=['admin','scheduler','office_staff'];
const CAN_EDIT_ALL=['admin','scheduler','office_staff'];
const CAN_EDIT_DATES=['admin','scheduler'];
const CAN_EDIT_NOTES=['admin','scheduler','office_staff','sales'];
const CAN_EDIT_APPROVAL=['admin','scheduler','office_staff','sales'];
const CAN_ASSIGN_REMOVAL=['admin','scheduler','office_staff','removal_foreman'];
const CAN_COMPLETE=['admin','scheduler','office_staff'];
const CAN_ARCHIVE=['admin','scheduler'];
const CAN_DELETE=['admin'];

app.post('/api/jobs',requireAuth,(req,res)=>{
  try {
    if(!CAN_ADD.includes(req.user.role)) return res.status(403).json({error:'Permission denied'});
    const j=sanitizeJob(req.body);
    if(!j.jobNum||!j.customer) return res.status(400).json({error:'jobNum and customer required'});
    const id=j.id||newId('j'), ts=now();
    const removalCrewIds=JSON.stringify(Array.isArray(j.removalCrewIds)?j.removalCrewIds:[]);
    const installCrewIds=JSON.stringify(Array.isArray(j.installCrewIds)?j.installCrewIds:[]);
    const gutterCrewIds=JSON.stringify(Array.isArray(j.gutterCrewIds)?j.gutterCrewIds:[]);
    db.prepare(`INSERT INTO jobs (
      id,jobNum,customer,address,newRoofMaterialId,existingRoofMaterialId,
      existingDeckType,newDeckType,existingRoofNotes,steepPitch,
      removalCrewId,tearoffDate,installCrewId,installDate,gutterCrewId,gutterDate,
      gutterProfile,gutterMaterial,gutterScreen,gutterInstruction,gutterMaterials,
      includesGutters,reroofComplete,warranty,layerStack,materials,notes,
      squares,manufacturer,productName,color,installerNotes,tearoffNotes,gutterNotes,
      startDateApproval,consultantId,backlogCategory,archived,createdAt,updatedAt
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0,?,?)`).run(
      id,j.jobNum,j.customer,j.address||'',
      j.newRoofMaterialId||null,j.existingRoofMaterialId||null,
      j.existingDeckType||'',j.newDeckType||'',j.existingRoofNotes||'',
      j.steepPitch?1:0,
      removalCrewIds,j.tearoffDate||null,
      installCrewIds,j.installDate||null,
      gutterCrewIds,j.gutterDate||null,
      j.gutterProfile||null,j.gutterMaterial||null,j.gutterScreen||null,
      j.gutterInstruction||'na',j.gutterMaterials||'',
      j.includesGutters?1:0,j.reroofComplete?1:0,j.warranty?1:0,
      JSON.stringify(j.layerStack||[]),j.materials||'',j.notes||'',
      j.squares||'',j.manufacturer||'',j.productName||'',j.color||'',
      j.installerNotes||'',j.tearoffNotes||'',j.gutterNotes||'',
      j.startDateApproval||'pending',j.consultantId||null,
      j.backlogCategory||'regular',ts,ts
    );
    res.status(201).json(parseJob(db.prepare('SELECT * FROM jobs WHERE id=?').get(id)));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.patch('/api/jobs/:id',requireAuth,(req,res)=>{
  try {
    const role=req.user.role;
    const body=req.body;

    // Supplier — no edits
    if(role==='supplier') return res.status(403).json({error:'Permission denied'});

    // Removal foreman — only removalCrewIds
    if(role==='removal_foreman'){
      const allowed=['removalCrewIds'];
      const bad=Object.keys(body).filter(k=>!allowed.includes(k));
      if(bad.length>0) return res.status(403).json({error:'Removal foreman can only assign removal crew'});
    }

    // Sales / RC — only notes, installerNotes, approval, consultantId
    if(role==='sales'){
      const allowed=['notes','installerNotes','startDateApproval','consultantId'];
      const bad=Object.keys(body).filter(k=>!allowed.includes(k));
      if(bad.length>0) return res.status(403).json({error:'Roofing Consultant can only edit notes and approval'});
    }

    // Office staff — strip scheduling dates rather than reject
    if(role==='office_staff'){
      delete body.tearoffDate;
      delete body.installDate;
      delete body.gutterDate;
    }

    const existing=db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
    if(!existing) return res.status(404).json({error:'Not found'});
    const ep=parseJob(existing);
    const j={...ep,...sanitizeJob(body)};
    const removalCrewIds=JSON.stringify(Array.isArray(j.removalCrewIds)?j.removalCrewIds:ep.removalCrewIds);
    const installCrewIds=JSON.stringify(Array.isArray(j.installCrewIds)?j.installCrewIds:ep.installCrewIds);
    const gutterCrewIds=JSON.stringify(Array.isArray(j.gutterCrewIds)?j.gutterCrewIds:ep.gutterCrewIds);
    db.prepare(`UPDATE jobs SET
      jobNum=?,customer=?,address=?,newRoofMaterialId=?,existingRoofMaterialId=?,
      existingDeckType=?,newDeckType=?,existingRoofNotes=?,steepPitch=?,
      removalCrewId=?,tearoffDate=?,installCrewId=?,installDate=?,gutterCrewId=?,gutterDate=?,
      gutterProfile=?,gutterMaterial=?,gutterScreen=?,gutterInstruction=?,gutterMaterials=?,
      includesGutters=?,reroofComplete=?,warranty=?,layerStack=?,materials=?,notes=?,
      squares=?,manufacturer=?,productName=?,color=?,installerNotes=?,tearoffNotes=?,gutterNotes=?,
      startDateApproval=?,consultantId=?,backlogCategory=?,updatedAt=?
    WHERE id=?`).run(
      j.jobNum,j.customer,j.address||'',
      j.newRoofMaterialId||null,j.existingRoofMaterialId||null,
      j.existingDeckType||'',j.newDeckType||'',j.existingRoofNotes||'',
      j.steepPitch?1:0,
      removalCrewIds,j.tearoffDate||null,
      installCrewIds,j.installDate||null,
      gutterCrewIds,j.gutterDate||null,
      j.gutterProfile||null,j.gutterMaterial||null,j.gutterScreen||null,
      j.gutterInstruction||'na',j.gutterMaterials||'',
      j.includesGutters?1:0,j.reroofComplete?1:0,j.warranty?1:0,
      JSON.stringify(j.layerStack||[]),j.materials||'',j.notes||'',
      j.squares||'',j.manufacturer||'',j.productName||'',j.color||'',
      j.installerNotes||'',j.tearoffNotes||'',j.gutterNotes||'',
      j.startDateApproval||'pending',j.consultantId||null,
      j.backlogCategory||'regular',now(),req.params.id
    );
    res.json(parseJob(db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id)));
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Mark as complete → archive
app.post('/api/jobs/:id/complete',requireAuth,(req,res)=>{
  try {
    if(!CAN_COMPLETE.includes(req.user.role)) return res.status(403).json({error:'Permission denied'});
    db.prepare('UPDATE jobs SET archived=1,completedAt=?,updatedAt=? WHERE id=?').run(now(),now(),req.params.id);
    res.json({ok:true,completedAt:now()});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Unarchive
app.post('/api/jobs/:id/unarchive',requireAuth,(req,res)=>{
  try {
    if(!CAN_ARCHIVE.includes(req.user.role)) return res.status(403).json({error:'Permission denied'});
    db.prepare('UPDATE jobs SET archived=0,completedAt=NULL,updatedAt=? WHERE id=?').run(now(),req.params.id);
    res.json({ok:true});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// Delete — admin only
app.delete('/api/jobs/:id',requireAuth,requireRole('admin'),(req,res)=>{
  try {
    const r=db.prepare('DELETE FROM jobs WHERE id=?').run(req.params.id);
    if(r.changes===0) return res.status(404).json({error:'Not found'});
    res.json({deleted:req.params.id});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Inspections ───────────────────────────────────────────────
app.get('/api/jobs/:jobId/inspections',(req,res)=>{
  try { res.json(db.prepare('SELECT * FROM inspections WHERE jobId=? ORDER BY sortOrder').all(req.params.jobId)); }
  catch(e){ res.status(500).json({error:e.message}); }
});

app.put('/api/jobs/:jobId/inspections',requireAuth,requireRole('admin','scheduler','office_staff'),(req,res)=>{
  try {
    const jobId=req.params.jobId;
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

// ── Export / Import ───────────────────────────────────────────

// GET /api/export — full database backup as JSON (admin only)
app.get('/api/export',requireAuth,requireRole('admin','scheduler'),(req,res)=>{
  try {
    const data = {
      exportedAt: now(),
      version: 5,
      jobs:         db.prepare('SELECT * FROM jobs').all().map(parseJob),
      inspections:  db.prepare('SELECT * FROM inspections ORDER BY jobId,sortOrder').all(),
      crews:        db.prepare('SELECT * FROM crews').all(),
      consultants:  db.prepare('SELECT * FROM consultants').all(),
      roofMaterials:db.prepare('SELECT * FROM roof_materials').all(),
      users:        db.prepare('SELECT id,username,passwordHash,salt,role,fullName,active,mustChangePwd,createdAt FROM users').all(),
    };
    res.setHeader('Content-Type','application/json');
    res.setHeader('Content-Disposition',`attachment; filename="roofboard-backup-${new Date().toISOString().slice(0,10)}.json"`);
    res.json(data);
  } catch(e){ res.status(500).json({error:e.message}); }
});

// POST /api/import — restore from backup JSON (admin only)
app.post('/api/import',requireAuth,requireRole('admin'),(req,res)=>{
  try {
    const {jobs,inspections,crews,consultants,roofMaterials,users}=req.body;
    let imported={jobs:0,inspections:0,crews:0,consultants:0,roofMaterials:0,users:0};

    db.transaction(()=>{
      // Roof materials — use INSERT OR REPLACE to handle unique name constraint
      if(Array.isArray(roofMaterials)){
        roofMaterials.forEach(m=>{
          db.prepare(`INSERT OR REPLACE INTO roof_materials
            (id,name,colorBg,colorText,colorBorder,active,sortOrder,createdAt)
            VALUES (?,?,?,?,?,?,?,?)`).run(
            m.id,m.name,m.colorBg||'#f0f0ec',m.colorText||'#444',m.colorBorder||'#ccc',
            m.active?1:0,m.sortOrder||0,m.createdAt||now()
          );
          imported.roofMaterials++;
        });
      }

      // Crews
      if(Array.isArray(crews)){
        crews.forEach(c=>{
          db.prepare(`INSERT OR REPLACE INTO crews
            (id,name,type,active,sortOrder,createdAt)
            VALUES (?,?,?,?,?,?)`).run(
            c.id,c.name,c.type,c.active?1:0,c.sortOrder||0,c.createdAt||now()
          );
          imported.crews++;
        });
      }

      // Consultants
      if(Array.isArray(consultants)){
        consultants.forEach(c=>{
          db.prepare(`INSERT OR REPLACE INTO consultants
            (id,name,initials,active,createdAt)
            VALUES (?,?,?,?,?)`).run(
            c.id,c.name,c.initials||'',c.active?1:0,c.createdAt||now()
          );
          imported.consultants++;
        });
      }

      // Jobs
      if(Array.isArray(jobs)){
        jobs.forEach(j=>{
          // Jobs — use INSERT OR REPLACE to handle both new and existing
          const removalCrewIds=JSON.stringify(Array.isArray(j.removalCrewIds)?j.removalCrewIds:(j.removalCrewId?[j.removalCrewId]:[]));
          const installCrewIds=JSON.stringify(Array.isArray(j.installCrewIds)?j.installCrewIds:(j.installCrewId?[j.installCrewId]:[]));
          const gutterCrewIds=JSON.stringify(Array.isArray(j.gutterCrewIds)?j.gutterCrewIds:(j.gutterCrewId?[j.gutterCrewId]:[]));
          db.prepare(`INSERT OR REPLACE INTO jobs (
            id,jobNum,customer,address,newRoofMaterialId,existingRoofMaterialId,
            existingDeckType,newDeckType,existingRoofNotes,steepPitch,
            removalCrewId,tearoffDate,installCrewId,installDate,gutterCrewId,gutterDate,
            gutterProfile,gutterMaterial,gutterScreen,gutterInstruction,gutterMaterials,
            includesGutters,reroofComplete,warranty,layerStack,materials,notes,
            startDateApproval,consultantId,backlogCategory,archived,completedAt,createdAt,updatedAt
          ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
            j.id,j.jobNum,j.customer,j.address||'',j.newRoofMaterialId||null,j.existingRoofMaterialId||null,
            j.existingDeckType||'',j.newDeckType||'',j.existingRoofNotes||'',j.steepPitch?1:0,
            removalCrewIds,j.tearoffDate||null,
            installCrewIds,j.installDate||null,
            gutterCrewIds,j.gutterDate||null,
            j.gutterProfile||null,j.gutterMaterial||null,j.gutterScreen||null,
            j.gutterInstruction||'na',j.gutterMaterials||'',
            j.includesGutters?1:0,j.reroofComplete?1:0,j.warranty?1:0,
            JSON.stringify(j.layerStack||[]),j.materials||'',j.notes||'',
            j.startDateApproval||'pending',j.consultantId||null,j.backlogCategory||'regular',
            j.archived?1:0,j.completedAt||null,j.createdAt||now(),now()
          );
          imported.jobs++;
        });
      }

      // Inspections
      if(Array.isArray(inspections)){
        inspections.forEach(insp=>{
          const jobExists=db.prepare('SELECT id FROM jobs WHERE id=?').get(insp.jobId);
          if(!jobExists) return;
          db.prepare(`INSERT OR REPLACE INTO inspections
            (id,jobId,type,date,sortOrder) VALUES (?,?,?,?,?)`).run(
            insp.id,insp.jobId,insp.type||'tearoff',insp.date||null,insp.sortOrder||0
          );
          imported.inspections++;
        });
      }

      // Users — restore with hashed passwords (never plain text)
      if(Array.isArray(users)){
        users.forEach(u=>{
          if(!u.id||!u.username||!u.passwordHash||!u.salt) return;
          db.prepare(`INSERT OR REPLACE INTO users
            (id,username,passwordHash,salt,role,fullName,active,mustChangePwd,createdAt)
            VALUES (?,?,?,?,?,?,?,?,?)`).run(
            u.id,u.username,u.passwordHash,u.salt,
            u.role||'office_staff',u.fullName||'',
            u.active?1:0,u.mustChangePwd?1:0,u.createdAt||now()
          );
          imported.users++;
        });
      }
    })();

    res.json({ok:true,imported});
  } catch(e){ res.status(500).json({error:e.message}); }
});

// ── Health ────────────────────────────────────────────────────
app.get('/api/health',(_req,res)=>{
  res.json({status:'ok',jobs:db.prepare('SELECT COUNT(*) as n FROM jobs WHERE archived=0').get().n});
});

app.listen(PORT,()=>console.log(`RoofBoard API v5 on port ${PORT}`));
