// risk-engine.js — Cyber Risk Prediction Algorithm
// Weighted deterministic scoring model for India regional cyber risk

const STATE_RISK = {
  maharashtra: { factor: 0.88, label: 'Maharashtra', threats: 8200 },
  delhi:       { factor: 0.83, label: 'Delhi (NCR)', threats: 7100 },
  karnataka:   { factor: 0.72, label: 'Karnataka',   threats: 5400 },
  telangana:   { factor: 0.68, label: 'Telangana',   threats: 4100 },
  tamilnadu:   { factor: 0.55, label: 'Tamil Nadu',  threats: 2900 },
  gujarat:     { factor: 0.64, label: 'Gujarat',     threats: 3800 },
  rajasthan:   { factor: 0.50, label: 'Rajasthan',   threats: 2200 },
  up:          { factor: 0.58, label: 'Uttar Pradesh', threats: 3100 },
  wb:          { factor: 0.61, label: 'West Bengal', threats: 3500 },
  ap:          { factor: 0.52, label: 'Andhra Pradesh', threats: 2600 },
};

const VERTICAL_RISK = {
  finance:     { factor: 0.92, label: 'BFSI (Finance & Banking)',   cve_count: 142 },
  healthcare:  { factor: 0.78, label: 'Healthcare & Pharma',        cve_count: 87  },
  government:  { factor: 0.85, label: 'Government & PSU',           cve_count: 118 },
  energy:      { factor: 0.80, label: 'Energy & Infrastructure',    cve_count: 97  },
  tech:        { factor: 0.70, label: 'Technology Services',        cve_count: 74  },
  telecom:     { factor: 0.75, label: 'Telecommunications',         cve_count: 82  },
  education:   { factor: 0.55, label: 'Education & Research',       cve_count: 51  },
};

const POSTURE_MULTIPLIER = {
  Basic:        { multiplier: 1.35, label: 'Basic (L1 Compliance)' },
  Intermediate: { multiplier: 1.00, label: 'Intermediate (ISO 27001)' },
  Advanced:     { multiplier: 0.65, label: 'Advanced (Zero Trust)' },
};

const RECOMMENDATIONS = {
  high: [
    { icon: 'vpn_key',      title: 'MFA Enforcement',         desc: 'Implement phishing-resistant FIDO2 keys across all access points.', priority: 'Critical', color: 'tertiary' },
    { icon: 'dns',          title: 'Network Segregation',     desc: 'Isolate OT from corporate IT networks immediately.', priority: 'Critical', color: 'tertiary' },
    { icon: 'history_edu',  title: 'Incident Response Plan',  desc: 'Update and drill Ransomware playbook this week.', priority: 'High', color: 'secondary' },
    { icon: 'security',     title: 'Threat Hunting Exercise', desc: 'Engage CERT-In certified team for proactive threat hunt.', priority: 'High', color: 'secondary' },
    { icon: 'lock',         title: 'Privileged Access Mgmt',  desc: 'Deploy PAM solution with session recording.', priority: 'Medium', color: 'primary' },
  ],
  medium: [
    { icon: 'dns',          title: 'Network Segregation',     desc: 'Segment high-value assets into separate VLANs.', priority: 'High', color: 'tertiary' },
    { icon: 'history_edu',  title: 'Incident Response Plan',  desc: 'Review and update security playbooks quarterly.', priority: 'Medium', color: 'secondary' },
    { icon: 'lock',         title: 'Privileged Access Mgmt',  desc: 'Audit and reduce standing privileges.', priority: 'Medium', color: 'primary' },
    { icon: 'shield',       title: 'Vulnerability Management', desc: 'Implement continuous vulnerability scanning.', priority: 'Low', color: 'primary' },
  ],
  low: [
    { icon: 'shield',       title: 'Security Awareness',      desc: 'Conduct bi-annual security awareness training.', priority: 'Low', color: 'secondary' },
    { icon: 'history_edu',  title: 'Policy Review',           desc: 'Review and update information security policies.', priority: 'Low', color: 'primary' },
    { icon: 'lock',         title: 'Patch Management',        desc: 'Maintain rigorous patch cycle within 72 hours of CVE.', priority: 'Low', color: 'primary' },
  ]
};

const THREAT_INTEL = [
  { cve: 'CVE-2024-9121', actor: null,       ioc: null,        desc: 'Remote Code Execution in Enterprise VPN Gateways', severity: 'critical' },
  { cve: null,             actor: 'IND-APT1', ioc: null,        desc: 'Persistent reconnaissance against healthcare nodes', severity: 'high' },
  { cve: null,             actor: null,       ioc: 'BLOCKED',   desc: 'Known C2 IPs identified in regional subnets', severity: 'medium' },
  { cve: 'CVE-2024-3400', actor: null,       ioc: null,        desc: 'PAN-OS GlobalProtect command injection', severity: 'critical' },
  { cve: null,             actor: 'FIN7',     ioc: null,        desc: 'Financial sector targeted with Carbanak successor malware', severity: 'high' },
];

/**
 * Core risk prediction function
 * @param {string} state - State key (e.g. 'maharashtra')
 * @param {string} vertical - Industry vertical key (e.g. 'finance')
 * @param {string} posture - Security posture ('Basic' | 'Intermediate' | 'Advanced')
 * @returns {object} Prediction result
 */
function predictRisk(state, vertical, posture) {
  const stateData    = STATE_RISK[state]    || STATE_RISK.maharashtra;
  const verticalData = VERTICAL_RISK[vertical] || VERTICAL_RISK.finance;
  const postureData  = POSTURE_MULTIPLIER[posture] || POSTURE_MULTIPLIER.Intermediate;

  // Base score: weighted combination of state and vertical risk factors
  const baseScore = (stateData.factor * 0.45) + (verticalData.factor * 0.55);

  // Apply posture multiplier and scale to 0-100
  const rawScore = baseScore * postureData.multiplier * 100;

  // Clamp between 5 and 98
  const riskScore = Math.min(98, Math.max(5, Math.round(rawScore)));

  // Confidence based on CVE density and known threats
  const confidence = Math.min(99, Math.round(78 + (verticalData.cve_count / 10)));

  // Risk level classification
  let riskLevel, riskCategory;
  if (riskScore >= 75) {
    riskLevel = 'CRITICAL RISK';
    riskCategory = 'high';
  } else if (riskScore >= 50) {
    riskLevel = 'HIGH RISK';
    riskCategory = 'high';
  } else if (riskScore >= 30) {
    riskLevel = 'MEDIUM RISK';
    riskCategory = 'medium';
  } else {
    riskLevel = 'LOW RISK';
    riskCategory = 'low';
  }

  // Select relevant threat intelligence
  const relevantIntel = THREAT_INTEL
    .filter(t => riskScore >= 50 || t.severity !== 'critical')
    .slice(0, 3);

  // Select recommendations
  const recommendations = RECOMMENDATIONS[riskCategory].slice(0, 3);

  return {
    riskScore,
    confidence,
    riskLevel,
    riskCategory,
    stateLabel: stateData.label,
    verticalLabel: verticalData.label,
    postureLabel: postureData.label,
    regionalThreats: stateData.threats,
    cveCount: verticalData.cve_count,
    recommendations,
    threatIntel: relevantIntel,
    analysisTimestamp: new Date().toISOString(),
  };
}

/**
 * Compute national CRI score from DB incidents
 */
function computeNationalCRI(db) {
  const result = db.prepare(`
    SELECT AVG(impact_score) as avg_score, COUNT(*) as total
    FROM incidents WHERE incident_date >= date('now', '-30 days')
  `).get();
  const avgScore = result.avg_score || 7.4;
  return Math.min(99, Math.round(avgScore * 10 + 4));
}

module.exports = { predictRisk, computeNationalCRI, STATE_RISK, VERTICAL_RISK };
