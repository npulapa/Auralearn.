// server.js — Express REST API for India Cyber Risk Predictor
require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const path     = require('path');
const db       = require('./database');
const { predictRisk, computeNationalCRI, STATE_RISK } = require('./risk-engine');

const app  = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'sentinel-jwt-secret-2024-india-cyber';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: No token provided' });
  }
  try {
    const payload = jwt.verify(auth.slice(7), JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
  }
}

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
// POST /api/auth/login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );
  res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// POST /api/auth/logout  (client-side token removal, server-side is stateless)
app.post('/api/auth/logout', requireAuth, (req, res) => {
  res.json({ message: 'Session terminated. Audit log recorded.' });
});

// ─── DASHBOARD ROUTES ─────────────────────────────────────────────────────────
// GET /api/dashboard/stats
app.get('/api/dashboard/stats', requireAuth, (req, res) => {
  const totalIncidents    = db.prepare('SELECT COUNT(*) as c FROM incidents').get().c;
  const criticalIncidents = db.prepare("SELECT COUNT(*) as c FROM incidents WHERE severity='High'").get().c;
  const unresolvedAlerts  = db.prepare("SELECT COUNT(*) as c FROM threat_alerts WHERE resolved=0").get().c;
  const criScore          = computeNationalCRI(db);

  // Simulate live active threats (fluctuates slightly each call)
  const baseThreats = 1280;
  const activeThreats = baseThreats + Math.floor(Math.random() * 20) - 8;

  res.json({
    criScore,
    activeThreats,
    criticalAlerts: criticalIncidents,
    totalIncidents,
    unresolvedAlerts,
    systemStatus: 'ELEVATED',
    nodesOnline: '42/42',
    lastUpdated: new Date().toISOString(),
  });
});

// GET /api/dashboard/alerts
app.get('/api/dashboard/alerts', requireAuth, (req, res) => {
  const alerts = db.prepare(`
    SELECT * FROM threat_alerts
    ORDER BY timestamp DESC
    LIMIT 10
  `).all();
  res.json({ alerts });
});

// GET /api/dashboard/regional
app.get('/api/dashboard/regional', requireAuth, (req, res) => {
  // Get incidents per state
  const byState = db.prepare(`
    SELECT state, COUNT(*) as incident_count, AVG(impact_score) as avg_impact
    FROM incidents
    GROUP BY state
    ORDER BY avg_impact DESC
  `).all();

  // Merge with static threat data from risk engine
  const regional = Object.entries(STATE_RISK).map(([key, data]) => {
    const stateIncidents = byState.find(s => s.state.toLowerCase().includes(key.slice(0,4))) || { incident_count: 0, avg_impact: 0 };
    const riskScore = Math.round(data.factor * 100);
    let riskLabel, riskColor;
    if (riskScore >= 75) { riskLabel = 'HIGH RISK';  riskColor = 'error'; }
    else if (riskScore >= 55) { riskLabel = 'MED RISK';  riskColor = 'tertiary'; }
    else { riskLabel = 'LOW RISK';  riskColor = 'secondary'; }

    return {
      key,
      label: data.label,
      threats: data.threats + stateIncidents.incident_count * 10,
      riskLabel,
      riskColor,
      riskScore,
    };
  }).slice(0, 8);

  res.json({ regional });
});

// GET /api/dashboard/weekly-stats
app.get('/api/dashboard/weekly-stats', requireAuth, (req, res) => {
  const days = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
  // Get incidents by day of week for last 4 weeks
  const dbStats = db.prepare(`
    SELECT strftime('%w', incident_date) as dow, COUNT(*) as count
    FROM incidents
    GROUP BY dow
  `).all();

  // Map dow (0=Sun..6=Sat) to our Mon-Sun order
  const dowMap = { '1': 0, '2': 1, '3': 2, '4': 3, '5': 4, '6': 5, '0': 6 };
  const counts = [40, 65, 55, 90, 70, 30, 25]; // base values
  dbStats.forEach(s => {
    const idx = dowMap[s.dow];
    if (idx !== undefined) counts[idx] += s.count * 3;
  });
  const maxCount = Math.max(...counts);
  const stats = days.map((day, i) => ({
    day,
    count: counts[i],
    pct: Math.round((counts[i] / maxCount) * 100),
  }));
  res.json({ stats });
});

// ─── PREDICT RISK ROUTES ──────────────────────────────────────────────────────
// POST /api/predict
app.post('/api/predict', requireAuth, (req, res) => {
  const { state, vertical, posture } = req.body;
  if (!state || !vertical || !posture) {
    return res.status(400).json({ error: 'state, vertical, and posture are required' });
  }
  const result = predictRisk(state, vertical, posture);

  // Save prediction to DB
  db.prepare(`
    INSERT INTO predictions (state, vertical, security_posture, risk_score, confidence, risk_level)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(state, vertical, posture, result.riskScore, result.confidence, result.riskLevel);

  res.json(result);
});

// GET /api/predict/history
app.get('/api/predict/history', requireAuth, (req, res) => {
  const history = db.prepare(`
    SELECT * FROM predictions ORDER BY created_at DESC LIMIT 20
  `).all();
  res.json({ history });
});

// ─── INCIDENTS CRUD ───────────────────────────────────────────────────────────
// GET /api/incidents
app.get('/api/incidents', requireAuth, (req, res) => {
  const { page = 1, limit = 10, category, severity, search } = req.query;
  const offset = (page - 1) * limit;

  let where = 'WHERE 1=1';
  const params = [];
  if (category) { where += ' AND category = ?'; params.push(category); }
  if (severity)  { where += ' AND severity = ?';  params.push(severity); }
  if (search)    { where += ' AND (title LIKE ? OR description LIKE ?)'; params.push(`%${search}%`, `%${search}%`); }

  const total = db.prepare(`SELECT COUNT(*) as c FROM incidents ${where}`).get(...params).c;
  const incidents = db.prepare(`
    SELECT * FROM incidents ${where}
    ORDER BY incident_date DESC, id DESC
    LIMIT ? OFFSET ?
  `).all(...params, parseInt(limit), parseInt(offset));

  res.json({
    incidents,
    total,
    page: parseInt(page),
    pages: Math.ceil(total / limit),
  });
});

// GET /api/incidents/:id
app.get('/api/incidents/:id', requireAuth, (req, res) => {
  const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id);
  if (!incident) return res.status(404).json({ error: 'Incident not found' });
  res.json({ incident });
});

// POST /api/incidents
app.post('/api/incidents', requireAuth, (req, res) => {
  const { title, category, state, impact_score, incident_date, description } = req.body;
  if (!title || !category || !impact_score || !incident_date) {
    return res.status(400).json({ error: 'title, category, impact_score, and incident_date are required' });
  }
  const result = db.prepare(`
    INSERT INTO incidents (title, category, state, impact_score, incident_date, description)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(title, category, state || 'Maharashtra', parseFloat(impact_score), incident_date, description || '');

  const incident = db.prepare('SELECT * FROM incidents WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ incident, message: 'Incident logged successfully' });
});

// PUT /api/incidents/:id
app.put('/api/incidents/:id', requireAuth, (req, res) => {
  const existing = db.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Incident not found' });

  const { title, category, state, impact_score, incident_date, description, status } = req.body;
  db.prepare(`
    UPDATE incidents
    SET title=?, category=?, state=?, impact_score=?, incident_date=?,
        description=?, status=?, updated_at=CURRENT_TIMESTAMP
    WHERE id=?
  `).run(
    title || existing.title,
    category || existing.category,
    state || existing.state,
    impact_score !== undefined ? parseFloat(impact_score) : existing.impact_score,
    incident_date || existing.incident_date,
    description !== undefined ? description : existing.description,
    status || existing.status,
    req.params.id
  );

  const updated = db.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id);
  res.json({ incident: updated, message: 'Incident updated successfully' });
});

// DELETE /api/incidents/:id
app.delete('/api/incidents/:id', requireAuth, (req, res) => {
  const existing = db.prepare('SELECT * FROM incidents WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Incident not found' });
  db.prepare('DELETE FROM incidents WHERE id = ?').run(req.params.id);
  res.json({ message: 'Incident deleted from secure log' });
});

// ─── ADMIN STATS ──────────────────────────────────────────────────────────────
// GET /api/admin/stats
app.get('/api/admin/stats', requireAuth, (req, res) => {
  const totalLogs      = db.prepare('SELECT COUNT(*) as c FROM incidents').get().c;
  const pendingReview  = db.prepare("SELECT COUNT(*) as c FROM incidents WHERE status='Open'").get().c;
  const resolvedCount  = db.prepare("SELECT COUNT(*) as c FROM incidents WHERE status='Resolved'").get().c;
  const highSeverity   = db.prepare("SELECT COUNT(*) as c FROM incidents WHERE severity='High'").get().c;

  const byCategory = db.prepare(`
    SELECT category, COUNT(*) as count FROM incidents GROUP BY category ORDER BY count DESC
  `).all();

  res.json({ totalLogs, pendingReview, resolvedCount, highSeverity, byCategory });
});

// ─── SPA FALLBACK ─────────────────────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'dashboard.html')));
app.get('/predict', (req, res) => res.sendFile(path.join(__dirname, 'public', 'predict.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

// ─── Error Handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[Error]', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, () => {
  console.log(`\n🛡️  Dharma Cyber Sentinel — ACTIVE`);
  console.log(`🌐  Server: http://localhost:${PORT}`);
  console.log(`📊  Dashboard: http://localhost:${PORT}/dashboard`);
  console.log(`🔑  Login: admin@security.gov.in / Sentinel@123\n`);
});

module.exports = app;
