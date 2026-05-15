// ─────────────────────────────────────────────────────────────
//  RoofBoard API Server  —  Node.js + Express + SQLite
// ─────────────────────────────────────────────────────────────
const express  = require('express');
const Database = require('better-sqlite3');
const cors     = require('cors');
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
`);

// ── Helpers ───────────────────────────────────────────────────
function newId(p){ return p+'_'+Date.now()+'_'+Math.random().toString(36).slice(2,7); }
function now(){ return new Date().toISOString(); }
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

// ── Board routing ─────────────────────────────────────────────
// Removal board : ALL jobs (backlog = no tearoffDate, scheduled = tearoffDate set)
// Install board : jobs where installDate is set AND crew is a number 1-8
// Gutter board  : jobs where gutterDate is set
// No "board" field stored — routing is purely date/crew driven

// GET /api/jobs?view=removal|install|gutters|all&crew=1
app.get('/api/jobs', (req, res) => {
  try {
    const { view, crew, updatedAfter } = req.query;
    let sql = 'SELECT * FROM jobs WHERE 1=1';
    const params = [];

    if(updatedAfter){ sql += ' AND updatedAt > ?'; params.push(updatedAfter); }

    if(view === 'install'){
      sql += ' AND installDate IS NOT NULL AND installDate != ""';
      sql += ' AND crew IS NOT NULL AND crew != "" AND crew NOT IN ("gutter","removal")';
      if(crew){ sql += ' AND crew = ?'; params.push(crew); }
    } else if(view === 'gutters'){
      sql += ' AND gutterDate IS NOT NULL AND gutterDate != ""';
    }
    // 'removal' and 'all' return every job — client handles backlog/scheduled split

    sql += ' ORDER BY jobNum ASC';
    res.json(db.prepare(sql).all(...params).map(parseJob));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.get('/api/jobs/:id', (req, res) => {
  try {
    const row = db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
    if(!row) return res.status(404).json({error:'Not found'});
    res.json(parseJob(row));
  } catch(e){ res.status(500).json({error:e.message}); }
});

app.post('/api/jobs', (req, res) => {
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

app.patch('/api/jobs/:id', (req, res) => {
  try {
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

app.delete('/api/jobs/:id', (req, res) => {
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

app.put('/api/jobs/:jobId/inspections', (req, res) => {
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

app.get('/api/health', (_req, res) => {
  res.json({status:'ok', jobs:db.prepare('SELECT COUNT(*) as n FROM jobs').get().n});
});

app.listen(PORT, ()=>console.log(`RoofBoard API on port ${PORT}`));
