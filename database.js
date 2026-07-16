// database.js — SQLite schema, seed data, and DB access
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const DB_PATH = path.join(__dirname, 'sentinel.db');
const db = new Database(DB_PATH);

// Enable WAL mode for better performance
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// ─── Schema ──────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT DEFAULT 'analyst',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    state TEXT DEFAULT 'Maharashtra',
    impact_score REAL NOT NULL CHECK(impact_score >= 0 AND impact_score <= 10),
    severity TEXT GENERATED ALWAYS AS (
      CASE
        WHEN impact_score >= 7 THEN 'High'
        WHEN impact_score >= 4 THEN 'Medium'
        ELSE 'Low'
      END
    ) STORED,
    incident_date DATE NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'Open',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS threat_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    region TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low')),
    attack_type TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    resolved INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    state TEXT NOT NULL,
    vertical TEXT NOT NULL,
    security_posture TEXT NOT NULL,
    risk_score REAL NOT NULL,
    confidence REAL NOT NULL,
    risk_level TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

// ─── Seed Data ───────────────────────────────────────────────────────────────
function seedIfEmpty() {
  // Seed admin user
  const existingUser = db.prepare('SELECT id FROM users WHERE email = ?').get('admin@security.gov.in');
  if (!existingUser) {
    const hash = bcrypt.hashSync('Sentinel@123', 10);
    db.prepare(`INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)`).run(
      'admin@security.gov.in', hash, 'Arjun Mehta', 'admin'
    );
    db.prepare(`INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)`).run(
      'analyst@security.gov.in', bcrypt.hashSync('Analyst@123', 10), 'Priya Sharma', 'analyst'
    );
    console.log('[DB] Seeded users');
  }

  // Seed incidents
  const incidentCount = db.prepare('SELECT COUNT(*) as c FROM incidents').get().c;
  if (incidentCount === 0) {
    const insertIncident = db.prepare(`
      INSERT INTO incidents (title, category, state, impact_score, incident_date, description)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const incidents = [
      ['Critical SQL Injection Attempt', 'Network Breach', 'Maharashtra', 9.2, '2023-10-24', 'Targeted SQL injection on banking portal in Mumbai Financial District.'],
      ['Targeted Phishing Campaign', 'Phishing Attack', 'Delhi', 5.8, '2023-10-22', 'Mass spear-phishing emails targeting government employees in NCR.'],
      ['Unauthorized Data Access', 'Insider Threat', 'Karnataka', 3.4, '2023-10-20', 'Insider exfiltration of HR records at Bengaluru tech firm.'],
      ['Subdomain Takeover Detected', 'DNS Security', 'Telangana', 2.1, '2023-10-19', 'Dangling CNAME record exploited in Hyderabad PSU.'],
      ['Ransomware Deployment — APT', 'Ransomware', 'Maharashtra', 9.8, '2023-10-17', 'APT group deployed LockBit 3.0 targeting hospital network in Pune.'],
      ['DDoS Attack on Financial Hub', 'Network Breach', 'Delhi', 8.5, '2023-10-15', '180 Gbps DDoS attack targeting payment gateway in Connaught Place.'],
      ['Credential Stuffing on Gov Portal', 'Phishing Attack', 'Karnataka', 6.2, '2023-10-12', 'Automated credential stuffing attempt using 2M leaked credentials.'],
      ['Supply Chain Compromise', 'Network Breach', 'Tamil Nadu', 7.9, '2023-10-10', 'Backdoor inserted into software update package by nation-state actor.'],
      ['Zero-Day Exploit — VPN Gateway', 'Network Breach', 'Telangana', 8.8, '2023-10-08', 'Unpatched CVE-2023-46805 exploited on enterprise VPN in Hyderabad.'],
      ['Data Breach — 2.3M Records', 'Insider Threat', 'Maharashtra', 9.0, '2023-10-05', 'Healthcare database exposed via misconfigured S3 bucket.'],
    ];
    incidents.forEach(i => insertIncident.run(...i));
    console.log('[DB] Seeded incidents');
  }

  // Seed threat alerts
  const alertCount = db.prepare('SELECT COUNT(*) as c FROM threat_alerts').get().c;
  if (alertCount === 0) {
    const insertAlert = db.prepare(`
      INSERT INTO threat_alerts (title, region, severity, attack_type, timestamp)
      VALUES (?, ?, ?, ?, datetime('now', ?))
    `);
    const alerts = [
      ['DDoS in Delhi Region', 'Delhi Financial District', 'critical', 'DDoS', '-2 minutes'],
      ['Credential Stuffing Attempt', 'Bangalore Hub', 'high', 'Credential Stuffing', '-14 minutes'],
      ['Port Sweep Blocked', 'Mumbai Node', 'medium', 'Reconnaissance', '-45 minutes'],
      ['Phishing Kit Deployed', 'Chennai Gateway', 'high', 'Phishing', '-1 hours'],
      ['Malware C2 Callback Detected', 'Pune Data Center', 'critical', 'Malware', '-2 hours'],
      ['Brute Force — SSH', 'Hyderabad Hub', 'medium', 'Brute Force', '-3 hours'],
      ['Suspicious API Calls Detected', 'Mumbai Node', 'low', 'API Abuse', '-4 hours'],
    ];
    alerts.forEach(a => insertAlert.run(...a));
    console.log('[DB] Seeded threat alerts');
  }
}

seedIfEmpty();

module.exports = db;
