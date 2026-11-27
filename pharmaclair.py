"""
PharmaClair — Enterprise SaaS Multi-Tenant & Offline-First PWA Server.
Architecture modulaire : schema.py, security.py, platform_saas.py, pharmacy_ops.py, seed_enterprise.py.
Zéro dépendance externe (Python 3.11+ Standard Library uniquement).
"""
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import schema
import security
import platform_saas
import pharmacy_ops
import seed_enterprise

PWA_MANIFEST = json.dumps({
    "name": "PharmaClair — Enterprise SaaS & Officine",
    "short_name": "PharmaClair",
    "start_url": "/",
    "display": "standalone",
    "background_color": "#0f172a",
    "theme_color": "#059669",
    "orientation": "any",
    "description": "Plateforme SaaS Officinale Multi-Tenant & Point de Vente Offline-First",
    "icons": [
        {"src": "/icons/icon-192.svg", "sizes": "192x192", "type": "image/svg+xml"},
        {"src": "/icons/icon-512.svg", "sizes": "512x512", "type": "image/svg+xml"}
    ]
}, indent=2)

PWA_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
  <rect width="512" height="512" rx="100" fill="#059669"/>
  <circle cx="256" cy="256" r="190" fill="#047857"/>
  <rect x="216" y="116" width="80" height="280" rx="20" fill="#ffffff"/>
  <rect x="116" y="216" width="280" height="80" rx="20" fill="#ffffff"/>
</svg>"""

SERVICE_WORKER_JS = """const CACHE_NAME = 'pharmaclair-enterprise-v2';
const ASSETS = ['/', '/index.html', '/workspace', '/platform-admin', '/manifest.webmanifest', '/icons/icon-192.svg', '/icons/icon-512.svg'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE_NAME).then((c) => c.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))));
  self.clients.claim();
});

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (e.request.mode === 'navigate' || url.pathname === '/' || url.pathname === '/workspace' || url.pathname === '/platform-admin') {
    e.respondWith(
      fetch(e.request).then((res) => {
        const clone = res.clone();
        caches.open(CACHE_NAME).then((c) => c.put(e.request, clone));
        return res;
      }).catch(() => caches.match('/'))
    );
    return;
  }
  if (url.pathname.startsWith('/icons/') || url.pathname.endsWith('.webmanifest')) {
    event.respondWith(caches.match(e.request).then((c) => c || fetch(e.request)));
    return;
  }
  e.respondWith(fetch(e.request));
});
"""

HTML_PAGE = """<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="theme-color" content="#059669">
  <link rel="manifest" href="/manifest.webmanifest">
  <link rel="icon" href="/icons/icon-192.svg" type="image/svg+xml">
  <title>PharmaClair — Enterprise SaaS</title>
  <style>
    :root {
      --primary: #059669; --primary-dark: #047857; --primary-light: #ecfdf5;
      --secondary: #0284c7; --secondary-light: #f0f9ff;
      --accent: #d97706; --accent-light: #fef3c7;
      --danger: #dc2626; --danger-light: #fef2f2;
      --bg: #f8fafc; --card: #ffffff; --text: #0f172a; --text-muted: #64748b;
      --border: #e2e8f0; --sidebar-w: 265px;
      --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
      --shadow: 0 4px 6px -1px rgb(0 0 0 / 0.08);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; }
    
    .topbar {
      height: 60px; background: white; border-bottom: 1px solid var(--border);
      display: flex; align-items: center; justify-content: space-between; padding: 0 1.25rem;
      position: sticky; top: 0; z-index: 50; box-shadow: var(--shadow-sm);
    }
    .topbar-left { display: flex; align-items: center; gap: 0.75rem; }
    .brand-logo { width: 32px; height: 32px; border-radius: 8px; }
    .brand-title { font-size: 1.15rem; font-weight: 800; color: var(--primary-dark); }
    .brand-sub { font-size: 0.82rem; font-weight: 600; color: var(--text-muted); padding-left: 0.6rem; border-left: 2px solid var(--border); }
    .topbar-right { display: flex; align-items: center; gap: 0.65rem; }
    
    .status-pill { display: inline-flex; align-items: center; gap: 0.4rem; padding: 0.25rem 0.7rem; border-radius: 9999px; font-size: 0.78rem; font-weight: 600; }
    .status-pill.online { background: #dcfce7; color: #15803d; }
    .status-pill.offline { background: #ffedd5; color: #c2410c; }
    .status-dot { width: 8px; height: 8px; border-radius: 50%; background: currentColor; }
    
    .app-layout { display: flex; flex: 1; height: calc(100vh - 60px); overflow: hidden; }
    .sidebar { width: var(--sidebar-w); background: white; border-right: 1px solid var(--border); overflow-y: auto; padding: 1rem 0.75rem; flex-shrink: 0; }
    .nav-section { font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8; margin: 1.1rem 0.5rem 0.35rem; }
    .nav-section:first-child { margin-top: 0.2rem; }
    .nav-btn {
      display: flex; align-items: center; gap: 0.7rem; padding: 0.58rem 0.75rem;
      border: none; background: transparent; border-radius: 8px; color: #475569;
      font-size: 0.87rem; font-weight: 500; cursor: pointer; text-align: left; width: 100%;
    }
    .nav-btn:hover { background: #f8fafc; color: var(--text); }
    .nav-btn.active { background: var(--primary-light); color: var(--primary-dark); font-weight: 600; }
    
    .content-area { flex: 1; padding: 1.5rem; overflow-y: auto; }
    .content-container { max-width: 1380px; margin: 0 auto; }
    
    .card { background: white; border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; box-shadow: var(--shadow-sm); margin-bottom: 1.5rem; }
    .card-title { font-size: 1.12rem; font-weight: 700; margin-bottom: 1.2rem; display: flex; align-items: center; justify-content: space-between; }
    
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .kpi-card { background: white; border: 1px solid var(--border); border-radius: 12px; padding: 1.25rem; box-shadow: var(--shadow-sm); border-top: 4px solid var(--primary); }
    .kpi-card.sec { border-top-color: var(--secondary); }
    .kpi-card.acc { border-top-color: var(--accent); }
    .kpi-card.dng { border-top-color: var(--danger); }
    .kpi-label { font-size: 0.78rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
    .kpi-val { font-size: 1.65rem; font-weight: 800; margin-top: 0.35rem; }
    .kpi-sub { font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem; }
    
    table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
    th { background: #f8fafc; text-align: left; padding: 0.75rem 1rem; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); }
    td { padding: 0.75rem 1rem; border-bottom: 1px solid var(--border); }
    
    .badge { display: inline-flex; align-items: center; padding: 0.2rem 0.55rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .badge-success { background: #dcfce7; color: #166534; }
    .badge-warning { background: var(--accent-light); color: #92400e; }
    .badge-danger { background: var(--danger-light); color: #991b1b; }
    .badge-info { background: var(--secondary-light); color: #075985; }
    
    input, select, button, textarea { font-size: 0.9rem; border-radius: 8px; }
    input, select, textarea { border: 1px solid var(--border); padding: 0.6rem 0.85rem; width: 100%; outline: none; background: white; }
    .btn { border: none; padding: 0.6rem 1rem; font-weight: 600; cursor: pointer; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; gap: 0.45rem; }
    .btn-primary { background: var(--primary); color: white; }
    .btn-secondary { background: #e2e8f0; color: #334155; }
    .btn-danger { background: var(--danger); color: white; }
    .btn-sm { padding: 0.35rem 0.65rem; font-size: 0.8rem; }
    
    .pos-grid { display: grid; grid-template-columns: 1fr 390px; gap: 1.5rem; }
    .chart-bars { display: flex; align-items: flex-end; gap: 1rem; height: 180px; padding: 1rem 0; border-bottom: 1px solid var(--border); }
    .chart-bar-col { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 0.4rem; height: 100%; justify-content: flex-end; }
    .chart-bar { width: 100%; max-width: 55px; background: linear-gradient(180deg, #3b82f6 0%, #60a5fa 100%); border-radius: 8px 8px 0 0; transition: height 0.3s ease; }
    
    .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(15, 23, 42, 0.65); display: flex; align-items: center; justify-content: center; z-index: 1000; }
    .login-container { max-width: 440px; width: 92vw; background: white; padding: 2.25rem; border-radius: 16px; box-shadow: var(--shadow); }
    .demo-pill { cursor: pointer; display: inline-block; margin: 0.25rem; padding: 0.35rem 0.6rem; background: #e2e8f0; border-radius: 6px; font-weight: 600; font-size: 0.78rem; }
    
    /* Mobile Owner View */
    .mobile-owner-app { display: none; max-width: 480px; margin: 0 auto; min-height: 100vh; background: #f8fafc; padding-bottom: 75px; flex-direction: column; }
    .mobile-hero-card { background: linear-gradient(135deg, #059669 0%, #047857 100%); color: white; border-radius: 16px; margin: 0 1.25rem 1rem; padding: 1.5rem; }
    .mobile-metric-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0.85rem; margin: 0 1.25rem 1.25rem; }
    .mobile-metric-card { background: white; border-radius: 12px; padding: 1.1rem; border: 1px solid var(--border); }
    .mobile-bottom-nav { position: fixed; bottom: 0; left: 0; right: 0; height: 65px; background: white; border-top: 1px solid var(--border); display: flex; justify-content: space-around; align-items: center; z-index: 100; max-width: 480px; margin: 0 auto; }
    .receipt-paper { background: white; width: 380px; max-width: 94vw; border-radius: 12px; padding: 1.75rem; font-family: 'Courier New', monospace; font-size: 0.85rem; }
    .receipt-paper.format-58mm { width: 280px; font-size: 0.75rem; padding: 1.1rem; }
    @media print { body * { visibility: hidden; } .receipt-paper, .receipt-paper * { visibility: visible; } .receipt-paper { position: absolute; left: 0; top: 0; width: 100%; } .no-print { display: none !important; } }
  </style>
</head>
<body>
  <header class="topbar">
    <div class="topbar-left">
      <svg class="brand-logo" viewBox="0 0 512 512"><rect width="512" height="512" rx="100" fill="#059669"/><rect x="216" y="116" width="80" height="280" rx="20" fill="#fff"/><rect x="116" y="216" width="280" height="80" rx="20" fill="#fff"/></svg>
      <div class="brand-title" id="brand-env-title">PharmaClair</div>
      <div class="brand-sub" id="topbar-org-name">Enterprise SaaS</div>
    </div>
    <div class="topbar-right">
      <div class="status-pill online" id="sync-pill"><div class="status-dot"></div><span id="sync-txt">En ligne</span></div>
      <button class="btn btn-secondary btn-sm" onclick="toggleLang()" id="lang-btn">FR / EN</button>
      <button class="btn btn-secondary btn-sm" id="btn-mobile-switch" onclick="toggleMobileOwner()" style="display:none; background:var(--primary-light); color:var(--primary-dark);">📱 Vue Mobile</button>
      <span id="topbar-user" style="font-size:0.85rem; font-weight:600;"></span>
      <button class="btn btn-secondary btn-sm" onclick="logout()">Déconnexion</button>
    </div>
  </header>

  <div class="app-layout" id="desktop-layout">
    <aside class="sidebar" id="sidebar-nav"></aside>
    <main class="content-area">
      <div class="content-container" id="main-content"></div>
    </main>
  </div>

  <!-- MOBILE OWNER APP -->
  <div class="mobile-owner-app" id="mobile-owner-view">
    <div style="padding:1.25rem; display:flex; justify-content:space-between; align-items:center;">
      <div>
        <div style="font-size:0.85rem; color:var(--text-muted);">Bonjour, Docteur</div>
        <div style="font-size:1.3rem; font-weight:800;" id="mob-ph-name">Votre pharmacie</div>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="toggleMobileOwner()">💻 Bureau</button>
    </div>
    <div class="mobile-hero-card">
      <div style="font-size:0.88rem; opacity:0.9;">Ventes aujourd'hui</div>
      <div style="font-size:2.1rem; font-weight:900; margin:0.4rem 0;" id="mob-sales">0 F</div>
      <div style="font-size:0.85rem;" id="mob-trend">+0% par rapport à hier</div>
    </div>
    <div class="mobile-metric-grid">
      <div class="mobile-metric-card"><div class="kpi-label">Bénéfice brut</div><div style="font-size:1.3rem; font-weight:800; margin-top:0.3rem;" id="mob-profit">0 F</div></div>
      <div class="mobile-metric-card"><div class="kpi-label">Transactions</div><div style="font-size:1.3rem; font-weight:800; margin-top:0.3rem;" id="mob-tx">0</div></div>
      <div class="mobile-metric-card"><div class="kpi-label">Employés actifs</div><div style="font-size:1.3rem; font-weight:800; margin-top:0.3rem;" id="mob-emp">0 / 0</div></div>
      <div class="mobile-metric-card"><div class="kpi-label">Écarts de caisse</div><div style="font-size:1.3rem; font-weight:800; margin-top:0.3rem;" id="mob-diff">0 F</div></div>
    </div>
    <div style="margin:0 1.25rem;">
      <div style="font-weight:700; margin-bottom:0.75rem;">Alertes en direct</div>
      <div class="card" style="padding:1rem; margin-bottom:0.75rem;" id="mob-alert-low">⚠️ 0 produits en stock faible</div>
      <div class="card" style="padding:1rem;" id="mob-alert-exp">⏳ 0 lots à péremption imminente</div>
    </div>
  </div>

  <!-- LOGIN MODAL -->
  <div id="login-modal" class="modal-overlay" style="display:none;">
    <div class="login-container">
      <h2 style="text-align:center; margin-bottom:0.5rem;">PharmaClair Enterprise</h2>
      <p style="text-align:center; font-size:0.85rem; color:var(--text-muted); margin-bottom:1.5rem;">Plateforme SaaS Multi-Tenant & Officines</p>
      <form onsubmit="handleLogin(event)">
        <div style="margin-bottom:1rem;"><label style="font-size:0.8rem; font-weight:600;">Identifiant</label><input type="text" id="l-user" required></div>
        <div style="margin-bottom:1.25rem;"><label style="font-size:0.8rem; font-weight:600;">Mot de passe</label><input type="password" id="l-pass" required></div>
        <button type="submit" class="btn btn-primary" style="width:100%;">Se Connecter</button>
      </form>
      <div style="margin-top:1.25rem; background:#f8fafc; padding:0.85rem; border-radius:8px;">
        <div style="font-size:0.78rem; font-weight:700; color:var(--text-muted); margin-bottom:0.4rem;">Environnements de démonstration isolés :</div>
        <span class="demo-pill" onclick="fillL('superadmin','admin123')">⚡ Super Admin (Plateforme)</span>
        <span class="demo-pill" onclick="fillL('commercial1','rep123')">💼 Commercial CRM</span>
        <span class="demo-pill" onclick="fillL('titulaire','admin123')">🏥 Pharmacie A (Owner)</span>
        <span class="demo-pill" onclick="fillL('caissier1','caisse123')">🛒 Pharmacie A (Caissier)</span>
        <span class="demo-pill" onclick="fillL('titulaire_b','admin123')">🏥 Pharmacie B (Owner)</span>
      </div>
    </div>
  </div>

  <!-- RECEIPT MODAL -->
  <div id="receipt-modal" class="modal-overlay" style="display:none;">
    <div class="receipt-paper" id="receipt-box">
      <div id="receipt-body"></div>
      <div style="display:flex; gap:0.5rem; margin-top:1.25rem;" class="no-print">
        <button class="btn btn-primary" style="flex:1;" onclick="window.print()">Imprimer</button>
        <button class="btn btn-secondary" onclick="document.getElementById('receipt-modal').style.display='none'">Fermer</button>
      </div>
    </div>
  </div>

  <script>
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').catch(() => {}));
    }

    let CURRENT_USER = null;
    let LANG = 'fr';
    let CART = [];
    let DRUGS = [];
    let PAY_METHOD = 'cash';

    const PharmaLocalDB = {
      db: null,
      init() {
        return new Promise((res) => {
          const r = indexedDB.open('PharmaClairEnterpriseDB', 1);
          r.onupgradeneeded = (e) => {
            const d = e.target.result;
            if (!d.objectStoreNames.contains('drugs')) d.createObjectStore('drugs', { keyPath: 'id' });
            if (!d.objectStoreNames.contains('outbox')) d.createObjectStore('outbox', { keyPath: 'event_id' });
          };
          r.onsuccess = (e) => { this.db = e.target.result; res(this.db); };
          r.onerror = () => res(null);
        });
      },
      async saveDrugs(drugs) {
        if (!this.db) await this.init();
        if (!this.db) return;
        const tx = this.db.transaction('drugs', 'readwrite');
        tx.objectStore('drugs').clear();
        drugs.forEach(d => tx.objectStore('drugs').put(d));
      },
      async getDrugs() {
        if (!this.db) await this.init();
        if (!this.db) return [];
        return new Promise(res => {
          const req = this.db.transaction('drugs', 'readonly').objectStore('drugs').getAll();
          req.onsuccess = () => res(req.result || []);
          req.onerror = () => res([]);
        });
      },
      async queueOutbox(ev) {
        if (!this.db) await this.init();
        if (!this.db) return;
        const tx = this.db.transaction('outbox', 'readwrite');
        tx.objectStore('outbox').put(ev);
      },
      async getOutbox() {
        if (!this.db) await this.init();
        if (!this.db) return [];
        return new Promise(res => {
          const req = this.db.transaction('outbox', 'readonly').objectStore('outbox').getAll();
          req.onsuccess = () => res(req.result || []);
        });
      },
      async clearOutbox(ids) {
        if (!this.db) await this.init();
        const tx = this.db.transaction('outbox', 'readwrite');
        ids.forEach(id => tx.objectStore('outbox').delete(id));
      }
    };

    async function api(path, method='GET', body=null) {
      const headers = { 'Content-Type': 'application/json' };
      const t = localStorage.getItem('token');
      if (t) headers['Authorization'] = 'Bearer ' + t;
      const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : null });
      if (res.status === 401 || res.status === 403) {
        const txt = await res.text();
        if (txt.includes('Session')) { localStorage.removeItem('token'); showLogin(); }
        throw new Error(txt);
      }
      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: res.statusText }));
        throw new Error(err.error || 'Erreur serveur');
      }
      return await res.json();
    }

    function showLogin() { document.getElementById('login-modal').style.display = 'flex'; }
    function fillL(u, p) { document.getElementById('l-user').value = u; document.getElementById('l-pass').value = p; }
    async function handleLogin(e) {
      e.preventDefault();
      try {
        const res = await api('/login', 'POST', { username: document.getElementById('l-user').value, password: document.getElementById('l-pass').value });
        localStorage.setItem('token', res.token);
        document.getElementById('login-modal').style.display = 'none';
        await initSession();
      } catch (err) { alert('Connexion refusée : ' + err.message); }
    }
    function logout() { localStorage.removeItem('token'); location.reload(); }
    function toggleLang() { LANG = LANG === 'fr' ? 'en' : 'fr'; initSession(); }

    async function initSession() {
      if (!localStorage.getItem('token')) return showLogin();
      try {
        CURRENT_USER = await api('/me');
        document.getElementById('topbar-user').innerText = `${CURRENT_USER.username} (${CURRENT_USER.role})`;
        if (['superadmin', 'sales_rep', 'support'].includes(CURRENT_USER.role)) {
          setupPlatformAdminUI();
        } else {
          setupPharmacyWorkspaceUI();
        }
      } catch (e) { showLogin(); }
    }

    // =========================================================================
    // A. ENVIRONNEMENT ADMINISTRATION PLATEFORME (/platform-admin)
    // =========================================================================
    function setupPlatformAdminUI() {
      document.getElementById('brand-env-title').innerText = 'PharmaClair Admin';
      document.getElementById('topbar-org-name').innerText = 'Platform management';
      document.getElementById('btn-mobile-switch').style.display = 'none';

      const nav = document.getElementById('sidebar-nav');
      nav.innerHTML = `
        <div class="nav-section">PLATEFORME SAAS</div>
        ${CURRENT_USER.role === 'superadmin' ? `<button class="nav-btn active" onclick="loadPlatformDashboard()">Business Overview</button>` : ''}
        ${CURRENT_USER.role === 'superadmin' ? `<button class="nav-btn" onclick="loadOnboardingForm()">Nouvelle Pharmacie (Onboarding)</button>` : ''}
        ${CURRENT_USER.role === 'superadmin' ? `<button class="nav-btn" onclick="loadPlansView()">Plans & Tarification</button>` : ''}
        <div class="nav-section">COMMERCIAL & SUPPORT</div>
        ${['superadmin','sales_rep'].includes(CURRENT_USER.role) ? `<button class="nav-btn" onclick="loadCRMView()">CRM Commercial & Prospects</button>` : ''}
        ${['superadmin','support'].includes(CURRENT_USER.role) ? `<button class="nav-btn" onclick="loadSupportView()">Support Client (Sans PII)</button>` : ''}
      `;
      if (CURRENT_USER.role === 'superadmin') loadPlatformDashboard();
      else if (CURRENT_USER.role === 'sales_rep') loadCRMView();
      else loadSupportView();
    }

    async function loadPlatformDashboard() {
      const d = await api('/api/platform/dashboard');
      const maxMrr = Math.max(...d.monthly_revenue_chart.map(m => m.amount), 1);
      const barsHtml = d.monthly_revenue_chart.map(m => `
        <div class="chart-bar-col">
          <div class="chart-bar" style="height:${Math.max(15, Math.round((m.amount / maxMrr) * 140))}px;" title="${m.amount.toLocaleString()} F"></div>
          <div style="font-size:0.78rem; color:var(--text-muted);">${m.month}</div>
        </div>
      `).join('');

      document.getElementById('main-content').innerHTML = `
        <div style="margin-bottom:1.25rem; display:flex; justify-content:space-between; align-items:center;">
          <div>
            <h2>Business overview</h2>
            <p style="font-size:0.85rem; color:var(--text-muted);">Administration SaaS — Séparation stricte des données privées officinales</p>
          </div>
          <span class="badge badge-success">🔒 Confidentialité Multi-Tenant Active</span>
        </div>

        <div class="kpi-grid">
          <div class="kpi-card"><div class="kpi-label">Monthly recurring revenue</div><div class="kpi-val">${d.mrr.toLocaleString()} F</div><div class="kpi-sub">+15 %</div></div>
          <div class="kpi-card sec"><div class="kpi-label">Active pharmacies</div><div class="kpi-val">${d.active_count} / ${d.total_organizations}</div><div class="kpi-sub">${d.trial_count} en essai • ${d.overdue_count} retard</div></div>
          <div class="kpi-card"><div class="kpi-label">Annual recurring revenue</div><div class="kpi-val">${d.arr.toLocaleString()} F</div><div class="kpi-sub">Annualized</div></div>
          <div class="kpi-card acc"><div class="kpi-label">Outstanding subscriptions</div><div class="kpi-val">${d.outstanding_invoices_amount.toLocaleString()} F</div><div class="kpi-sub">${d.outstanding_invoices_count} unpaid invoices</div></div>
          <div class="kpi-card dng"><div class="kpi-label">Churn rate</div><div class="kpi-val">${d.churn_rate} %</div><div class="kpi-sub">Monthly</div></div>
        </div>

        <div style="display:grid; grid-template-columns:2fr 1fr; gap:1.5rem; margin-bottom:1.5rem;">
          <div class="card" style="margin-bottom:0;">
            <div class="card-title">Subscription revenue</div>
            <div class="chart-bars">${barsHtml}</div>
          </div>
          <div class="card" style="margin-bottom:0;">
            <div class="card-title">Platform health</div>
            <div style="display:flex; flex-direction:column; gap:0.85rem;">
              <div style="display:flex; justify-content:space-between;"><span>Cloud services</span><span class="badge badge-success">${d.system_health.cloud_services}</span></div>
              <div style="display:flex; justify-content:space-between;"><span>Synchronization service</span><span class="badge badge-success">${d.system_health.sync_service}</span></div>
              <div style="display:flex; justify-content:space-between;"><span>Backup service</span><span class="badge badge-success">${d.system_health.backup_service}</span></div>
              <div style="display:flex; justify-content:space-between;"><span>Terminaux enregistrés</span><b>${d.system_health.registered_devices}</b></div>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Customer subscriptions</div>
          <table>
            <thead><tr><th>Pharmacy</th><th>Ville</th><th>Plan</th><th>Status</th><th>Expiration</th><th>Action</th></tr></thead>
            <tbody>
              ${d.organizations.map(o => `
                <tr>
                  <td><b>${o.name}</b><br><small style="color:var(--text-muted)">${o.phone || ''}</small></td>
                  <td>${o.city}</td>
                  <td>${o.plan_name || 'Standard'}</td>
                  <td><span class="badge ${o.subscription_status==='active'?'badge-success':(o.subscription_status==='trial'?'badge-info':'badge-danger')}">${o.subscription_status}</span></td>
                  <td>${o.subscription_expires_at || '-'}</td>
                  <td><button class="btn btn-secondary btn-sm" onclick="extendSub(${o.id}, 30)">+30 jours</button></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      `;
    }

    async function extendSub(phId, days) {
      await api('/api/platform/extend', 'POST', { pharmacy_id: phId, days });
      alert('Abonnement prolongé.');
      loadPlatformDashboard();
    }

    function loadOnboardingForm() {
      document.getElementById('main-content').innerHTML = `
        <div class="card" style="max-width:650px; margin:0 auto;">
          <div class="card-title">Onboarding Nouvelle Pharmacie (Création Tenant Isolé)</div>
          <form onsubmit="submitOnboarding(event)">
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
              <div><label>Nom Commercial</label><input type="text" id="ob-name" required></div>
              <div><label>Ville</label><input type="text" id="ob-city" value="Douala" required></div>
            </div>
            <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem;">
              <div><label>Identifiant Titulaire</label><input type="text" id="ob-user" required></div>
              <div><label>Mot de passe Initial</label><input type="password" id="ob-pass" required></div>
            </div>
            <button type="submit" class="btn btn-primary" style="width:100%;">Créer l'Officine Isolée (14j essai)</button>
          </form>
        </div>
      `;
    }
    async function submitOnboarding(e) {
      e.preventDefault();
      await api('/api/platform/onboard', 'POST', {
        name: document.getElementById('ob-name').value,
        city: document.getElementById('ob-city').value,
        owner_username: document.getElementById('ob-user').value,
        owner_password: document.getElementById('ob-pass').value
      });
      alert('Pharmacie créée avec isolation complète.');
      loadPlatformDashboard();
    }

    async function loadPlansView() {
      const plans = await api('/api/platform/plans');
      document.getElementById('main-content').innerHTML = `
        <div class="card">
          <div class="card-title">Plans d'Abonnement Configurables</div>
          <table>
            <thead><tr><th>Code</th><th>Nom</th><th>Mensuel</th><th>Trimestriel</th><th>Annuel</th><th>Max Succursales</th></tr></thead>
            <tbody>${plans.map(p => `<tr><td><code>${p.code}</code></td><td><b>${p.name}</b></td><td>${p.monthly_price.toLocaleString()} F</td><td>${p.quarterly_price.toLocaleString()} F</td><td>${p.annual_price.toLocaleString()} F</td><td>${p.max_branches}</td></tr>`).join('')}</tbody>
          </table>
        </div>
      `;
    }

    async function loadCRMView() {
      const prospects = await api('/api/platform/crm');
      document.getElementById('main-content').innerHTML = `
        <div class="card">
          <div class="card-title">CRM Commercial Terrain — Pipeline Prospects</div>
          <table>
            <thead><tr><th>Pharmacie</th><th>Contact</th><th>Téléphone</th><th>Ville</th><th>Étape Pipeline</th></tr></thead>
            <tbody>${prospects.map(p => `<tr><td><b>${p.pharmacy_name}</b></td><td>${p.contact_name}</td><td>${p.phone}</td><td>${p.city}</td><td><span class="badge badge-info">${p.stage}</span></td></tr>`).join('')}</tbody>
          </table>
        </div>
      `;
    }

    async function loadSupportView() {
      const tickets = await api('/api/platform/support');
      document.getElementById('main-content').innerHTML = `
        <div class="card">
          <div class="card-title">Centre de Support Technique (Données Patients Masquées)</div>
          <table>
            <thead><tr><th>Pharmacie</th><th>Catégorie</th><th>Priorité</th><th>Sujet</th><th>Description (PII Masquées)</th><th>Statut</th></tr></thead>
            <tbody>${tickets.map(t => `<tr><td><b>${t.pharmacy_name}</b></td><td>${t.category}</td><td>${t.priority}</td><td>${t.subject}</td><td>${t.description_redacted}</td><td><span class="badge badge-warning">${t.status}</span></td></tr>`).join('') || '<tr><td colspan="6" style="text-align:center;">Aucun ticket ouvert.</td></tr>'}</tbody>
          </table>
        </div>
      `;
    }

    // =========================================================================
    // B. ESPACE PRIVÉ DE L'OFFICINE (/workspace)
    // =========================================================================
    function setupPharmacyWorkspaceUI() {
      const r = CURRENT_USER.role;
      const isOwner = (r === 'owner');
      const isFin = ['owner', 'accountant', 'auditor'].includes(r);
      document.getElementById('brand-env-title').innerText = 'PharmaClair';
      document.getElementById('btn-mobile-switch').style.display = isOwner ? 'inline-flex' : 'none';

      const nav = document.getElementById('sidebar-nav');
      nav.innerHTML = `
        <div class="nav-section">PRINCIPAL</div>
        ${isOwner ? `<button class="nav-btn active" onclick="loadOwnerDashboard()">Tableau de bord</button>` : ''}
        ${['owner','cashier','pharmacist','branch_manager'].includes(r) ? `<button class="nav-btn" onclick="loadPOS()">Point de vente</button>` : ''}
        <button class="nav-btn" onclick="loadSalesView()">Ventes et encaissements</button>
        <div class="nav-section">GESTION PHARMACEUTIQUE</div>
        <button class="nav-btn" onclick="loadInventoryView()">Stocks et lots FEFO</button>
        ${['owner','stock','pharmacist','branch_manager'].includes(r) ? `<button class="nav-btn" onclick="loadReceiveView()">Réceptions fournisseurs</button>` : ''}
        ${['owner','pharmacist','branch_manager'].includes(r) ? `<button class="nav-btn" onclick="loadPatientsView()">Patients et ordonnances</button>` : ''}
        ${isFin ? `
          <div class="nav-section">GESTION D'ENTREPRISE</div>
          <button class="nav-btn" onclick="loadFinanceView()">Finances & Compte de Résultat</button>
          <button class="nav-btn" onclick="loadClosingView()">Clôture Z & Dépenses</button>
          <button class="nav-btn" onclick="loadAuditView()">Sécurité & Audit Antifraude</button>
        ` : ''}
        ${isOwner ? `
          <div class="nav-section">ADMINISTRATION</div>
          <button class="nav-btn" onclick="loadBranchesView()">Succursales</button>
          <button class="nav-btn" onclick="loadUsersView()">Personnel & Rôles</button>
          <button class="nav-btn" onclick="loadSettingsView()">Paramètres officine</button>
          <button class="nav-btn" onclick="loadSubscriptionView()">Mon Abonnement (SasPay)</button>
        ` : ''}
      `;
      if (isOwner) loadOwnerDashboard();
      else loadPOS();
    }

    function toggleMobileOwner() {
      const desk = document.getElementById('desktop-layout');
      const mob = document.getElementById('mobile-owner-view');
      if (mob.style.display === 'flex') { mob.style.display = 'none'; desk.style.display = 'flex'; }
      else { mob.style.display = 'flex'; desk.style.display = 'none'; loadOwnerDashboard(); }
    }

    async function loadOwnerDashboard() {
      const s = await api('/owner/stats');
      if (s.pharmacy && s.pharmacy.name) {
        document.getElementById('topbar-org-name').innerText = s.pharmacy.name;
        document.getElementById('mob-ph-name').innerText = s.pharmacy.name;
      }
      document.getElementById('mob-sales').innerText = s.total_revenue_today.toLocaleString() + ' F';
      document.getElementById('mob-trend').innerText = (s.trend_pct >= 0 ? '+' : '') + s.trend_pct + '% par rapport à hier';
      document.getElementById('mob-profit').innerText = s.estimated_profit.toLocaleString() + ' F';
      document.getElementById('mob-tx').innerText = s.count_sales_today;
      document.getElementById('mob-emp').innerText = s.active_employees_ratio;
      document.getElementById('mob-diff').innerText = s.cash_discrepancy.toLocaleString() + ' F';
      document.getElementById('mob-alert-low').innerText = `⚠️ ${s.low_stock_count} produit(s) en stock faible`;
      document.getElementById('mob-alert-exp').innerText = `⏳ ${s.expiring_count} lot(s) à péremption imminente`;

      document.getElementById('main-content').innerHTML = `
        <div class="card-title"><h2>Tableau de bord Direction (${s.today_date})</h2></div>
        <div class="kpi-grid">
          <div class="kpi-card"><div class="kpi-label">Chiffre d'affaires jour</div><div class="kpi-val">${s.total_revenue_today.toLocaleString()} F</div><div class="kpi-sub">${s.trend_pct}% vs hier</div></div>
          <div class="kpi-card sec"><div class="kpi-label">Marge Brute Réelle (COGS)</div><div class="kpi-val">${s.estimated_profit.toLocaleString()} F</div><div class="kpi-sub">Basé sur coût réel des lots</div></div>
          <div class="kpi-card acc"><div class="kpi-label">Transactions</div><div class="kpi-val">${s.count_sales_today}</div><div class="kpi-sub">Panier moyen: ${s.avg_basket_today.toLocaleString()} F</div></div>
          <div class="kpi-card dng"><div class="kpi-label">Lots à Risque (≤ 3 mois)</div><div class="kpi-val">${s.expiring_count}</div><div class="kpi-sub">Stock faible: ${s.low_stock_count}</div></div>
        </div>
        <div class="card">
          <div class="card-title">Dernières Ventes de l'Officine</div>
          <table>
            <thead><tr><th>Ticket</th><th>Heure</th><th>Caissier</th><th>Mode</th><th>Total</th><th>Action</th></tr></thead>
            <tbody>${s.recent_sales.map(r => `<tr><td><b>${r.receipt_no}</b></td><td>${r.time}</td><td>${r.cashier}</td><td>${r.method}</td><td><b>${r.total.toLocaleString()} F</b></td><td><button class="btn btn-secondary btn-sm" onclick="openReceipt(${r.id})">Reçu</button></td></tr>`).join('') || '<tr><td colspan="6" style="text-align:center;">Aucune vente aujourd hui.</td></tr>'}</tbody>
          </table>
        </div>
      `;
    }

    async function loadPOS() {
      try { DRUGS = await api('/drugs'); await PharmaLocalDB.saveDrugs(DRUGS); }
      catch (e) { DRUGS = await PharmaLocalDB.getDrugs(); }
      document.getElementById('main-content').innerHTML = `
        <div class="pos-grid">
          <div class="card">
            <div class="card-title">Catalogue Officinal (FEFO)</div>
            <input type="text" id="pos-q" placeholder="Rechercher nom, DCI, code-barres..." oninput="renderPOSList()" style="margin-bottom:1rem;">
            <table><thead><tr><th>Médicament</th><th>Prix</th><th>Stock</th><th>Lot FEFO</th><th>Action</th></tr></thead><tbody id="pos-list"></tbody></table>
          </div>
          <div class="card">
            <div class="card-title">Panier & Encaissement</div>
            <div id="pos-cart" style="min-height:150px; margin-bottom:1rem;"></div>
            <div style="font-size:1.25rem; font-weight:800; margin-bottom:0.75rem;">Total : <span id="pos-tot">0 F</span></div>
            <select id="pos-method" style="margin-bottom:0.75rem;">
              <option value="cash">Espèces (Offline OK)</option>
              <option value="om">Orange Money / MTN MoMo</option>
              <option value="card">Carte Bancaire</option>
            </select>
            <input type="number" id="pos-paid" placeholder="Montant reçu" style="margin-bottom:0.75rem;">
            <button class="btn btn-primary" style="width:100%;" onclick="checkout()">Valider l'encaissement</button>
          </div>
        </div>
      `;
      renderPOSList();
      renderCart();
    }

    function renderPOSList() {
      const q = (document.getElementById('pos-q')?.value || '').toLowerCase();
      const tb = document.getElementById('pos-list');
      if (!tb) return;
      tb.innerHTML = DRUGS.filter(d => d.name.toLowerCase().includes(q) || (d.barcode||'').includes(q)).map(d => `
        <tr>
          <td><b>${d.name}</b><br><small>${d.pack}</small></td>
          <td>${d.price.toLocaleString()} F</td>
          <td><span class="badge ${d.sellable>0?'badge-success':'badge-danger'}">${d.sellable}</span></td>
          <td>${d.next_lot_no || '-'} (${d.next_expiry || '-'})</td>
          <td><button class="btn btn-primary btn-sm" onclick="addCart(${d.id})" ${d.sellable<=0?'disabled':''}>+</button></td>
        </tr>
      `).join('');
    }

    function addCart(id) {
      const d = DRUGS.find(x => x.id === id);
      if (!d) return;
      const ex = CART.find(x => x.drug_id === id);
      if (ex) ex.qty += 1; else CART.push({ drug_id: id, name: d.name, price: d.price, qty: 1 });
      renderCart();
    }

    function renderCart() {
      const c = document.getElementById('pos-cart');
      if (!c) return;
      let tot = 0;
      c.innerHTML = CART.map((it, i) => { tot += it.price * it.qty; return `<div style="display:flex; justify-content:space-between; margin-bottom:0.4rem;"><span>${it.qty}x ${it.name}</span><b>${(it.price*it.qty).toLocaleString()} F</b></div>`; }).join('') || 'Panier vide';
      document.getElementById('pos-tot').innerText = tot.toLocaleString() + ' F';
    }

    async function checkout() {
      if (!CART.length) return alert('Panier vide');
      const tot = CART.reduce((a, b) => a + b.price * b.qty, 0);
      const paid = parseInt(document.getElementById('pos-paid').value || tot);
      const method = document.getElementById('pos-method').value;
      const items = CART.map(i => [i.drug_id, i.qty]);
      const idem = 'IDEM-' + Date.now();
      try {
        const res = await api('/sale', 'POST', { idem, items, method, paid });
        CART = [];
        renderCart();
        openReceipt(res.sale_id);
        loadPOS();
      } catch (e) {
        await PharmaLocalDB.queueOutbox({ event_id: 'EVT-' + Date.now(), event_type: 'sale', payload: { idem, items, method, paid } });
        CART = []; renderCart();
        alert('Mode Hors-Ligne : Vente sauvegardée dans l Outbox locale.');
      }
    }

    async function openReceipt(id) {
      const r = await api('/receipt/' + id);
      document.getElementById('receipt-box').className = 'receipt-paper' + (r.pharmacy.format === '58mm' ? ' format-58mm' : '');
      document.getElementById('receipt-body').innerHTML = `
        <div style="text-align:center; border-bottom:1px dashed #333; padding-bottom:0.5rem; margin-bottom:0.5rem;">
          <b>${r.pharmacy.name}</b><br>${r.pharmacy.address}<br>NIF: ${r.pharmacy.tax_id}
        </div>
        <div>Ticket: <b>${r.receipt_no}</b><br>${r.full_timestamp}<br>Caissier: ${r.cashier}</div>
        <div style="border-top:1px dashed #333; border-bottom:1px dashed #333; margin:0.5rem 0; padding:0.5rem 0;">
          ${r.lines.map(l => `<div style="display:flex; justify-content:space-between;"><span>${l.qty}x ${l.label}</span><b>${(l.price*l.qty).toLocaleString()}</b></div>`).join('')}
        </div>
        <div style="font-weight:800; font-size:1.1rem;">TOTAL: ${r.total.toLocaleString()} ${r.pharmacy.currency}</div>
        <div>Payé: ${r.paid.toLocaleString()} | Rendu: ${r.change.toLocaleString()}</div>
      `;
      document.getElementById('receipt-modal').style.display = 'flex';
    }

    async function loadSalesView() {
      const rows = await api('/sales');
      document.getElementById('main-content').innerHTML = `<div class="card"><div class="card-title">Journal des Ventes</div><table><thead><tr><th>Ticket</th><th>Date</th><th>Caissier</th><th>Total</th><th>Action</th></tr></thead><tbody>${rows.map(r=>`<tr><td><b>${r.receipt_no}</b></td><td>${r.full_ts}</td><td>${r.cashier_name}</td><td>${r.total.toLocaleString()} F</td><td><button class="btn btn-secondary btn-sm" onclick="openReceipt(${r.id})">Ticket</button></td></tr>`).join('')}</tbody></table></div>`;
    }

    async function loadInventoryView() {
      const drugs = await api('/drugs');
      document.getElementById('main-content').innerHTML = `<div class="card"><div class="card-title">Stocks & Péremptions FEFO</div><table><thead><tr><th>Réf</th><th>Médicament</th><th>Prix</th><th>Physique</th><th>Vendable</th><th>Lot FEFO</th></tr></thead><tbody>${drugs.map(d=>`<tr><td><code>${d.ref}</code></td><td><b>${d.name}</b></td><td>${d.price.toLocaleString()} F</td><td>${d.physical}</td><td>${d.sellable}</td><td>${d.next_lot_no||'-'} (${d.next_expiry||'-'})</td></tr>`).join('')}</tbody></table></div>`;
    }

    async function loadReceiveView() {
      const drugs = await api('/drugs');
      document.getElementById('main-content').innerHTML = `<div class="card" style="max-width:600px;"><div class="card-title">Réception Fournisseur</div><form onsubmit="submitReceive(event)"><select id="r-drug" style="margin-bottom:0.75rem;">${drugs.map(d=>`<option value="${d.id}">${d.name}</option>`).join('')}</select><input id="r-lot" placeholder="N° Lot" required style="margin-bottom:0.75rem;"><input id="r-exp" placeholder="Péremption (2027-12)" required style="margin-bottom:0.75rem;"><input type="number" id="r-qty" placeholder="Quantité" required style="margin-bottom:0.75rem;"><input type="number" id="r-cost" placeholder="Coût d'achat unitaire (FCFA)" required style="margin-bottom:1rem;"><button type="submit" class="btn btn-primary">Valider Réception</button></form></div>`;
    }
    async function submitReceive(e) {
      e.preventDefault();
      await api('/receive', 'POST', { drug_id: parseInt(document.getElementById('r-drug').value), lot_no: document.getElementById('r-lot').value, expiry: document.getElementById('r-exp').value, qty: parseInt(document.getElementById('r-qty').value), purchase_cost: parseInt(document.getElementById('r-cost').value) });
      alert('Lot ajouté au stock.'); loadInventoryView();
    }

    async function loadPatientsView() {
      const prescs = await api('/prescriptions');
      document.getElementById('main-content').innerHTML = `<div class="card"><div class="card-title">Patients & Ordonnances (Accès restreint & audité)</div><table><thead><tr><th>Patient</th><th>Médecin</th><th>Médicament</th><th>Posologie</th><th>Renouvellements</th></tr></thead><tbody>${prescs.map(p=>`<tr><td><b>${p.customer_name}</b></td><td>${p.doctor}</td><td>${p.drug_name}</td><td>${p.posology}</td><td>${p.refills_left}</td></tr>`).join('')}</tbody></table></div>`;
    }

    async function loadFinanceView() {
      const f = await api('/api/finance/pnl');
      document.getElementById('main-content').innerHTML = `<div class="card"><div class="card-title">Finances & Compte de Résultat (P&L)</div><div class="kpi-grid"><div class="kpi-card"><div class="kpi-label">Chiffre d'affaires</div><div class="kpi-val">${f.total_revenue.toLocaleString()} F</div></div><div class="kpi-card sec"><div class="kpi-label">Coût des ventes (COGS)</div><div class="kpi-val">${f.cogs.toLocaleString()} F</div></div><div class="kpi-card"><div class="kpi-label">Bénéfice Brut (${f.gross_margin_pct}%)</div><div class="kpi-val">${f.gross_profit.toLocaleString()} F</div></div><div class="kpi-card dng"><div class="kpi-label">Résultat Net</div><div class="kpi-val">${f.net_profit.toLocaleString()} F</div></div></div></div>`;
    }

    function loadClosingView() {
      document.getElementById('main-content').innerHTML = `<div class="card" style="max-width:500px;"><div class="card-title">Clôture Z de Caisse</div><form onsubmit="submitZ(event)"><input type="number" id="z-init" value="50000" style="margin-bottom:0.75rem;"><input type="number" id="z-cnt" placeholder="Espèces comptées" required style="margin-bottom:1rem;"><button type="submit" class="btn btn-primary">Valider Clôture Z</button></form></div>`;
    }
    async function submitZ(e) {
      e.preventDefault();
      const res = await api('/cash_closing', 'POST', { initial_cash: parseInt(document.getElementById('z-init').value), counted_cash: parseInt(document.getElementById('z-cnt').value) });
      alert(`Clôture validée. Écart: ${res.diff_cash} F (${res.status})`);
    }

    async function loadAuditView() {
      const a = await api('/api/audit');
      document.getElementById('main-content').innerHTML = `<div class="card"><div class="card-title">Audit Antifraude & Anomalies</div>${a.anomalies.map(x=>`<div class="badge badge-danger" style="margin-bottom:0.5rem;">⚠️ ${x.type}: ${x.detail}</div>`).join('<br>')}<table style="margin-top:1rem;"><thead><tr><th>Date</th><th>Utilisateur</th><th>Action</th><th>Détails</th></tr></thead><tbody>${a.logs.map(l=>`<tr><td>${l.ts}</td><td><b>${l.username||'Sys'}</b></td><td>${l.action}</td><td><code>${l.data}</code></td></tr>`).join('')}</tbody></table></div>`;
    }

    async function loadBranchesView() {
      const b = await api('/api/branches');
      document.getElementById('main-content').innerHTML = `<div class="card"><div class="card-title">Succursales de l'Organisation</div><table><thead><tr><th>Nom</th><th>Ville</th><th>Adresse</th><th>Statut</th></tr></thead><tbody>${b.map(x=>`<tr><td><b>${x.name}</b></td><td>${x.city}</td><td>${x.address}</td><td><span class="badge badge-success">Active</span></td></tr>`).join('')}</tbody></table></div>`;
    }

    async function loadUsersView() {
      const u = await api('/users');
      document.getElementById('main-content').innerHTML = `<div class="card"><div class="card-title">Personnel & Rôles</div><table><thead><tr><th>Identifiant</th><th>Nom</th><th>Rôle</th><th>Statut</th></tr></thead><tbody>${u.map(x=>`<tr><td><b>${x.username}</b></td><td>${x.full_name}</td><td><span class="badge badge-info">${x.role}</span></td><td><span class="badge ${x.active?'badge-success':'badge-danger'}">${x.active?'Actif':'Bloqué'}</span></td></tr>`).join('')}</tbody></table></div>`;
    }

    async function loadSettingsView() {
      const s = await api('/api/settings');
      document.getElementById('main-content').innerHTML = `<div class="card" style="max-width:650px;"><div class="card-title">Paramètres de l'Officine</div><form onsubmit="saveSet(event)"><label>Nom Pharmacie</label><input id="s-name" value="${s.name||''}" style="margin-bottom:0.75rem;"><label>Adresse</label><input id="s-addr" value="${s.address||''}" style="margin-bottom:0.75rem;"><label>Format Ticket</label><select id="s-fmt" style="margin-bottom:1rem;"><option value="80mm" ${s.receipt_format==='80mm'?'selected':''}>80 mm</option><option value="58mm" ${s.receipt_format==='58mm'?'selected':''}>58 mm</option></select><button type="submit" class="btn btn-primary">Enregistrer</button></form></div>`;
    }
    async function saveSet(e) {
      e.preventDefault();
      await api('/api/settings', 'POST', { name: document.getElementById('s-name').value, address: document.getElementById('s-addr').value, receipt_format: document.getElementById('s-fmt').value });
      alert('Paramètres enregistrés.'); initSession();
    }

    async function loadSubscriptionView() {
      const s = await api('/api/settings');
      document.getElementById('main-content').innerHTML = `<div class="card" style="max-width:600px;"><div class="card-title">Mon Abonnement SaaS (SasPay)</div><p style="margin-bottom:1rem;">Statut : <b>${s.subscription_status}</b> • Expire le : <b>${s.subscription_expires_at}</b></p><button class="btn btn-primary" onclick="paySasPay(1)">Renouveler 1 Mois (Orange/MTN MoMo)</button></div>`;
    }
    async function paySasPay(m) {
      const res = await api('/api/subscription/pay', 'POST', { months: m, method: 'orange_money', phone: '+237699000000' });
      alert(`Abonnement renouvelé ! Réf SasPay: ${res.payment_ref}`); loadSubscriptionView();
    }

    window.addEventListener('DOMContentLoaded', () => { PharmaLocalDB.init(); initSession(); });
  </script>
</body>
</html>"""

def make_handler(c):
    class H(BaseHTTPRequestHandler):
        def _send(self, code, data, content_type="application/json; charset=utf-8"):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            b = data.encode("utf-8") if isinstance(data, str) else json.dumps(data).encode("utf-8")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def _get_auth_user(self):
            token = (self.headers.get("Authorization") or "").replace("Bearer ", "").strip()
            if not token and "?" in self.path:
                qs = parse_qs(urlparse(self.path).query)
                token = qs.get("token", [""])[0]
            return security.auth(c, token)

        def _run(self, method):
            parsed = urlparse(self.path)
            path = parsed.path
            qs = parse_qs(parsed.query)
            p = path.split("/")

            if method == "GET" and path in ("/", "/index.html", "/workspace", "/platform-admin"):
                return self._send(200, HTML_PAGE, "text/html; charset=utf-8")
            if method == "GET" and path in ("/manifest.webmanifest", "/manifest.json"):
                return self._send(200, PWA_MANIFEST, "application/manifest+json; charset=utf-8")
            if method == "GET" and path == "/sw.js":
                return self._send(200, SERVICE_WORKER_JS, "application/javascript; charset=utf-8")
            if method == "GET" and path.startswith("/icons/"):
                return self._send(200, PWA_ICON_SVG, "image/svg+xml; charset=utf-8")
            if method == "GET" and path == "/api/ping":
                return self._send(200, {"status": "ok", "server_time": schema.now()})

            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}") if n > 0 else {}
            ip = self.headers.get("X-Forwarded-For") or self.client_address[0]

            try:
                if method == "POST" and path == "/login":
                    return self._send(200, {"token": security.login(c, body["username"], body["password"], ip)})

                u = self._get_auth_user()

                if method == "GET" and path == "/me":
                    return self._send(200, {
                        "id": u["id"], "username": u["username"], "role": u["role"],
                        "pharmacy_id": u["pharmacy_id"], "branch_id": u.get("branch_id")
                    })

                # --- ROUTES ADMINISTRATION PLATEFORME (/api/platform/*) ---
                if method == "GET" and path == "/api/platform/dashboard":
                    return self._send(200, platform_saas.get_platform_dashboard(c, u))
                if method == "GET" and path == "/api/platform/plans":
                    return self._send(200, platform_saas.list_plans(c))
                if method == "POST" and path == "/api/platform/onboard":
                    return self._send(200, platform_saas.onboard_new_pharmacy(c, u, body))
                if method == "POST" and path == "/api/platform/extend":
                    return self._send(200, platform_saas.extend_pharmacy_subscription(c, u, int(body["pharmacy_id"]), int(body["days"])))
                if method == "GET" and path == "/api/platform/crm":
                    return self._send(200, platform_saas.list_crm_prospects(c, u))
                if method == "GET" and path == "/api/platform/support":
                    return self._send(200, platform_saas.list_support_tickets(c, u))

                # --- ROUTES OPÉRATIONS OFFICINES ISOLÉES ---
                if method == "GET" and path == "/owner/stats":
                    return self._send(200, pharmacy_ops.owner_dashboard_stats(c, u))
                if method == "GET" and path == "/api/finance/pnl":
                    return self._send(200, pharmacy_ops.get_finance_pnl(c, u))
                if method == "GET" and path == "/api/audit":
                    return self._send(200, pharmacy_ops.get_audit_logs_and_anomalies(c, u))
                if method == "GET" and path == "/api/branches":
                    return self._send(200, pharmacy_ops.list_branches(c, u))
                if method == "GET" and path == "/users":
                    return self._send(200, pharmacy_ops.list_users(c, u))
                if method == "GET" and path == "/drugs":
                    return self._send(200, pharmacy_ops.list_drugs_with_stock(c, u))
                if method == "GET" and len(p) >= 3 and p[1] == "stock":
                    return self._send(200, pharmacy_ops.stock(c, u, int(p[2])))
                if method == "POST" and path == "/receive":
                    return self._send(200, {"lot_id": pharmacy_ops.receive(c, u, int(body["drug_id"]), body["lot_no"], body["expiry"], int(body["qty"]), int(body.get("purchase_cost", 0)))})
                if method == "POST" and path == "/sale":
                    return self._send(200, {"sale_id": pharmacy_ops.sell(c, u, body["idem"], body["items"], body["method"], body.get("paid"))})
                if method == "GET" and len(p) >= 3 and p[1] == "receipt":
                    return self._send(200, pharmacy_ops.receipt(c, u, int(p[2]), reprint=True))
                if method == "GET" and path == "/sales":
                    return self._send(200, pharmacy_ops.sales_list(c, u))
                if method == "GET" and path == "/prescriptions":
                    return self._send(200, pharmacy_ops.list_prescriptions(c, u))
                if method == "POST" and path == "/cash_closing":
                    return self._send(200, pharmacy_ops.perform_cash_closing(c, u, int(body.get("initial_cash", 0)), int(body["counted_cash"])))
                if method == "GET" and path == "/api/settings":
                    return self._send(200, pharmacy_ops.get_pharmacy_settings(c, u))
                if method == "POST" and path == "/api/settings":
                    return self._send(200, pharmacy_ops.update_pharmacy_settings(c, u, body))
                if method == "POST" and path == "/api/subscription/pay":
                    return self._send(200, pharmacy_ops.pay_subscription_saspay(c, u, int(body.get("months", 1)), body.get("method", "orange_money"), body.get("phone", "")))
                if method == "POST" and path == "/api/sync/push":
                    return self._send(200, pharmacy_ops.sync_push_events(c, u, body.get("device_uuid", ""), body.get("events", [])))
                if method == "GET" and path == "/api/sync/pull":
                    return self._send(200, pharmacy_ops.sync_pull_delta(c, u, qs.get("since", [None])[0], qs.get("device_uuid", [""])[0]))
                if method == "GET" and path == "/export":
                    return self._send(200, pharmacy_ops.export_sales_csv(c, u), "text/csv; charset=utf-8")

                return self._send(404, {"error": "Endpoint inconnu"})
            except security.Denied as e:
                self._send(403, {"error": str(e)})
            except security.Conflict as e:
                self._send(409, {"error": str(e)})
            except Exception as e:
                self._send(500, {"error": f"Erreur serveur: {str(e)}"})

        def do_GET(self): self._run("GET")
        def do_POST(self): self._run("POST")

    return H

if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    db_file = os.environ.get("DB", "pharmaclair.db")
    conn = schema.connect(db_file)
    seed_enterprise.seed_enterprise_data(conn)

    primary_port = int(os.environ.get("PORT", 8000))
    handler = make_handler(conn)

    ports_to_try = [primary_port]
    for p in (8000, 8080):
        if p not in ports_to_try:
            ports_to_try.append(p)

    active_servers = []
    for p in ports_to_try:
        try:
            srv = ThreadingHTTPServer(("0.0.0.0", p), handler)
            print(f"🚀 PharmaClair Enterprise SaaS à l'écoute sur http://0.0.0.0:{p}", flush=True)
            active_servers.append(srv)
        except Exception as e:
            print(f"Port {p} non disponible: {e}", flush=True)

    if not active_servers:
        sys.exit(1)

    for srv in active_servers[1:]:
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    try:
        active_servers[0].serve_forever()
    except KeyboardInterrupt:
        pass
