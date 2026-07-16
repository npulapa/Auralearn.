// auth.js — Shared authentication utility for Dharma Cyber Sentinel
const API_BASE = '';  // same-origin

const Auth = {
  getToken() {
    return localStorage.getItem('sentinel_token');
  },
  getUser() {
    try {
      const raw = localStorage.getItem('sentinel_user');
      return raw ? JSON.parse(raw) : null;
    } catch { return null; }
  },
  setSession(token, user) {
    localStorage.setItem('sentinel_token', token);
    localStorage.setItem('sentinel_user', JSON.stringify(user));
  },
  clearSession() {
    localStorage.removeItem('sentinel_token');
    localStorage.removeItem('sentinel_user');
  },
  isLoggedIn() {
    return !!this.getToken();
  },
  checkAuth() {
    if (!this.isLoggedIn()) {
      window.location.href = '/';
      return false;
    }
    return true;
  },
  async logout() {
    try {
      await this.apiRequest('/api/auth/logout', { method: 'POST' });
    } catch {}
    this.clearSession();
    window.location.href = '/';
  },
  async apiRequest(url, options = {}) {
    const token = this.getToken();
    const headers = {
      'Content-Type': 'application/json',
      ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    };
    const response = await fetch(API_BASE + url, { ...options, headers });
    if (response.status === 401) {
      this.clearSession();
      window.location.href = '/';
      throw new Error('Session expired');
    }
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || 'Request failed');
    return data;
  }
};

// Inject user info into header if element exists
function populateUserHeader() {
  const user = Auth.getUser();
  if (!user) return;
  const nameEl = document.getElementById('user-name');
  const roleEl = document.getElementById('user-role');
  if (nameEl) nameEl.textContent = user.name;
  if (roleEl) roleEl.textContent = user.role.toUpperCase();
}
