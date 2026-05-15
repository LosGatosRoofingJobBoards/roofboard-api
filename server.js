// ─────────────────────────────────────────────────────────────
//  RoofBoard API Server  —  Node.js + Express + SQLite
//  Deploy to Railway: https://railway.app
// ─────────────────────────────────────────────────────────────
const express  = require('express');
const Database = require('better-sqlite3');
const cors     = require('cors');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ────────────────────────────────────────────────
app.use(cors());
app.use(express.json());

// ── Database setup ────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'roofboard.db');
const db = new Database(DB_PATH);

// Enable WAL mode for better concurrent read performance
db.pragma('journal_mode = WAL');

// ── Schema ────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS jobs (
    id              TEXT PRIMARY KEY,
    jobNum          TEXT NOT NULL,
    customer        TEXT NOT NULL,
    address         TEXT,
    board           TEXT NOT NULL DEFAULT 'install',
    type            TEXT NOT NULL DEFAULT 'comp',
    crew            TEXT,
    installDate     TEXT,
    tearoffDate     TEXT,
    gutterDate      TEXT,
    duration        TEXT,
    gutterType      TEXT,
    gutterInstruction TEXT DEFAULT 'na',
    materials       TEXT,
    gutterMaterials TEXT,
    notes           TEXT,
    includesGutters INTEGER DEFAULT 0,
    reroofComplete  INTEGER DEFAULT 0,
    warranty        INTEGER DEFAULT 0,
    layerStack      TEXT DEFAULT '[]',
    createdAt       TEXT NOT NULL,
    updatedAt       TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS inspections (
    id      TEXT PRIMARY KEY,
    jobId   TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    type    TEXT NOT NULL DEFAULT 'tearoff',
    date    TEXT,
    sortOrder INTEGER DEFAULT 0
  );
`);

// ── Helpers ───────────────────────────────────────────────────
function newId() {
  return 'j_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7);
}
function now() {
  return new Date().toISOString();
}
function parseJob(row) {
  if (!row) return null;
  return {
    ...row,
    includesGutters: !!row.includesGutters,
    reroofComplete:  !!row.reroofComplete,
    warranty:        !!row.warranty,
    layerStack:      JSON.parse(row.layerStack || '[]'),
  };
}

// ── Jobs ──────────────────────────────────────────────────────

// GET /api/jobs  — optional ?board=install|removal|gutters&crew=1&updatedAfter=ISO
app.get('/api/jobs', (req, res) => {
  try {
    let sql  = 'SELECT * FROM jobs WHERE 1=1';
    const params = [];
    if (req.query.board) { sql += ' AND board = ?'; params.push(req.query.board); }
    if (req.query.crew)  { sql += ' AND crew = ?';  params.push(req.query.crew);  }
    if (req.query.updatedAfter) {
      sql += ' AND updatedAt > ?';
      params.push(req.query.updatedAfter);
    }
    sql += ' ORDER BY jobNum ASC';
    const rows = db.prepare(sql).all(...params);
    res.json(rows.map(parseJob));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/jobs/:id
app.get('/api/jobs/:id', (req, res) => {
  try {
    const row = db.prepare('SELECT * FROM jobs WHERE id = ?').get(req.params.id);
    if (!row) return res.status(404).json({ error: 'Job not found' });
    res.json(parseJob(row));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/jobs  — create
app.post('/api/jobs', (req, res) => {
  try {
    const j = req.body;
    if (!j.jobNum || !j.customer) {
      return res.status(400).json({ error: 'jobNum and customer are required' });
    }
    const id = j.id || newId();
    const ts = now();
    db.prepare(`
      INSERT INTO jobs (id,jobNum,customer,address,board,type,crew,
        installDate,tearoffDate,gutterDate,duration,gutterType,
        gutterInstruction,materials,gutterMaterials,notes,
        includesGutters,reroofComplete,warranty,layerStack,createdAt,updatedAt)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `).run(
      id, j.jobNum, j.customer, j.address||'', j.board||'install', j.type||'comp',
      j.crew||null, j.installDate||null, j.tearoffDate||null, j.gutterDate||null,
      j.duration||'1 day', j.gutterType||null, j.gutterInstruction||'na',
      j.materials||'', j.gutterMaterials||'', j.notes||'',
      j.includesGutters?1:0, j.reroofComplete?1:0, j.warranty?1:0,
      JSON.stringify(j.layerStack||[]), ts, ts
    );
    res.status(201).json(parseJob(db.prepare('SELECT * FROM jobs WHERE id=?').get(id)));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/jobs/:id  — update
app.patch('/api/jobs/:id', (req, res) => {
  try {
    const existing = db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
    if (!existing) return res.status(404).json({ error: 'Job not found' });
    const j = { ...parseJob(existing), ...req.body };
    db.prepare(`
      UPDATE jobs SET
        jobNum=?,customer=?,address=?,board=?,type=?,crew=?,
        installDate=?,tearoffDate=?,gutterDate=?,duration=?,gutterType=?,
        gutterInstruction=?,materials=?,gutterMaterials=?,notes=?,
        includesGutters=?,reroofComplete=?,warranty=?,layerStack=?,updatedAt=?
      WHERE id=?
    `).run(
      j.jobNum, j.customer, j.address||'', j.board||'install', j.type||'comp',
      j.crew||null, j.installDate||null, j.tearoffDate||null, j.gutterDate||null,
      j.duration||'1 day', j.gutterType||null, j.gutterInstruction||'na',
      j.materials||'', j.gutterMaterials||'', j.notes||'',
      j.includesGutters?1:0, j.reroofComplete?1:0, j.warranty?1:0,
      JSON.stringify(j.layerStack||[]), now(), req.params.id
    );
    res.json(parseJob(db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id)));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/jobs/:id
app.delete('/api/jobs/:id', (req, res) => {
  try {
    const result = db.prepare('DELETE FROM jobs WHERE id=?').run(req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Job not found' });
    res.json({ deleted: req.params.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Inspections ───────────────────────────────────────────────

// GET /api/jobs/:id/inspections
app.get('/api/jobs/:jobId/inspections', (req, res) => {
  try {
    const rows = db.prepare(
      'SELECT * FROM inspections WHERE jobId=? ORDER BY sortOrder ASC'
    ).all(req.params.jobId);
    res.json(rows);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PUT /api/jobs/:id/inspections  — replace full inspection list
app.put('/api/jobs/:jobId/inspections', (req, res) => {
  try {
    const jobId = req.params.jobId;
    const insps = req.body; // array of { type, date }
    if (!Array.isArray(insps)) return res.status(400).json({ error: 'Expected array' });

    const deleteAll = db.prepare('DELETE FROM inspections WHERE jobId=?');
    const insert    = db.prepare(
      'INSERT INTO inspections (id,jobId,type,date,sortOrder) VALUES (?,?,?,?,?)'
    );
    const transaction = db.transaction(() => {
      deleteAll.run(jobId);
      insps.forEach((insp, i) => {
        insert.run(
          'i_' + Date.now() + '_' + i + '_' + Math.random().toString(36).slice(2,5),
          jobId, insp.type || 'tearoff', insp.date || null, i
        );
      });
      // bump job updatedAt so boards pick up the change
      db.prepare('UPDATE jobs SET updatedAt=? WHERE id=?').run(now(), jobId);
    });
    transaction();
    res.json(db.prepare('SELECT * FROM inspections WHERE jobId=? ORDER BY sortOrder').all(jobId));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── Health check ──────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', jobs: db.prepare('SELECT COUNT(*) as n FROM jobs').get().n });
});

// ── Start ─────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`RoofBoard API running on port ${PORT}`);
  console.log(`Database: ${DB_PATH}`);
});
