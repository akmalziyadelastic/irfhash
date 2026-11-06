#!/usr/bin/env python3
"""
irfHASH Local Control Center & Security Dashboard
Isolated Runtime Fortress: Hardened Agentic Secret Hub

Features:
- Default Crisp White Light Mode + 1-Click Dark Mode Toggle
- 1-Click Toggleable "How to Train Your Dragon" (Toothless, Light Fury, Stormfly, Hookfang, Berk) Theme
- 1-Click AI Chat Secret Sanitizer & Redactor (replaces secrets in chat logs with AI-readable irfHASH pointers)
- Configurable Custom Local Domain / Bookmarkable URL (e.g. irfhash.localhost, irfhash.vault, or any xyz domain)
- 22 Built-in App Presets (Slack, Jira, Stripe, Supabase, Vercel, Discord, Cloudflare, GitHub, Notion, etc.)
- Strict 127.0.0.1 localhost binding
"""

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from vault_manager import IrfHashVault

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" data-theme="light" data-dragons="on">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>irfHASH | Isolated Runtime Fortress: Hardened Agentic Secret Hub</title>
<style>
  /* ================= LIGHT MODE (DEFAULT WHITE) ================= */
  :root, html[data-theme="light"] {
    --bg: #f8fafc;
    --bg-gradient: linear-gradient(180deg, #ffffff 0%, #f1f5f9 100%);
    --header-bg: rgba(255, 255, 255, 0.94);
    --panel: #ffffff;
    --panel-alt: #f1f5f9;
    --panel-hover: #f8fafc;
    --border: #e2e8f0;
    --border-strong: #cbd5e1;
    --text: #0f172a;
    --text-soft: #334155;
    --muted: #64748b;
    --accent: #0284c7;
    --accent-hover: #0369a1;
    --accent-soft: rgba(2, 132, 199, 0.1);
    --green: #059669;
    --green-bg: #ecfdf5;
    --green-border: #a7f3d0;
    --red: #e11d48;
    --red-bg: #fff1f2;
    --red-border: #fecdd3;
    --amber: #d97706;
    --amber-bg: #fffbeb;
    --amber-border: #fde68a;
    --purple: #7c3aed;
    --purple-bg: #f5f3ff;
    --purple-border: #ddd6fe;
    --shadow: 0 4px 20px -2px rgba(15, 23, 42, 0.06), 0 2px 6px -1px rgba(15, 23, 42, 0.04);
    --url-color: #0369a1;
    --mono-color: #334155;
    --dragon-banner-bg: linear-gradient(135deg, #f0f9ff 0%, #e0f2fe 45%, #ede9fe 100%);
    --dragon-banner-border: #bae6fd;
  }

  /* ================= DARK MODE ================= */
  html[data-theme="dark"] {
    --bg: #0b0f17;
    --bg-gradient: linear-gradient(180deg, #0b0f17 0%, #111827 100%);
    --header-bg: rgba(15, 23, 42, 0.94);
    --panel: #131b2e;
    --panel-alt: #19233c;
    --panel-hover: #1e293b;
    --border: #263457;
    --border-strong: #334155;
    --text: #f1f5f9;
    --text-soft: #cbd5e1;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --accent-hover: #0ea5e9;
    --accent-soft: rgba(56, 189, 248, 0.14);
    --green: #10b981;
    --green-bg: rgba(16, 185, 129, 0.14);
    --green-border: rgba(16, 185, 129, 0.35);
    --red: #f43f5e;
    --red-bg: rgba(244, 63, 94, 0.15);
    --red-border: rgba(244, 63, 94, 0.35);
    --amber: #f59e0b;
    --amber-bg: rgba(245, 158, 11, 0.15);
    --amber-border: rgba(245, 158, 11, 0.35);
    --purple: #a855f7;
    --purple-bg: rgba(168, 85, 247, 0.15);
    --purple-border: rgba(168, 85, 247, 0.35);
    --shadow: 0 10px 30px -5px rgba(0, 0, 0, 0.45);
    --url-color: #7dd3fc;
    --mono-color: #cbd5e1;
    --dragon-banner-bg: linear-gradient(135deg, #0f172a 0%, #172554 50%, #1e1b4b 100%);
    --dragon-banner-border: #1e3a8a;
  }

  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Inter, sans-serif;
    background: var(--bg);
    background-image: var(--bg-gradient);
    color: var(--text);
    line-height: 1.45;
    min-height: 100vh;
    transition: background 0.25s ease, color 0.2s ease;
  }

  header {
    background: var(--header-bg);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    padding: 15px 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 14px;
    position: sticky;
    top: 0;
    z-index: 50;
    box-shadow: var(--shadow);
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .brand-badge {
    width: 44px;
    height: 44px;
    border-radius: 12px;
    background: linear-gradient(135deg, #0284c7, #4f46e5);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 800;
    font-size: 18px;
    letter-spacing: -0.5px;
    color: #fff;
    box-shadow: 0 4px 14px rgba(2, 132, 199, 0.3);
  }

  .brand h1 {
    margin: 0;
    font-size: 20px;
    font-weight: 800;
    letter-spacing: -0.3px;
  }

  .brand p {
    margin: 2px 0 0 0;
    font-size: 12px;
    color: var(--muted);
  }

  .header-actions {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }

  .pill {
    padding: 6px 11px;
    border-radius: 999px;
    font-size: 11.5px;
    font-weight: 600;
    display: inline-flex;
    align-items: center;
    gap: 5px;
    border: 1px solid var(--border);
    background: var(--panel);
  }
  .pill.secure { color: var(--green); border-color: var(--green-border); background: var(--green-bg); }
  .pill.domain-pill {
    color: var(--accent);
    border-color: var(--border-strong);
    background: var(--panel-alt);
    cursor: pointer;
    text-decoration: none;
  }
  .pill.domain-pill:hover { border-color: var(--accent); }

  button {
    cursor: pointer;
    border: 1px solid var(--border-strong);
    background: var(--panel);
    color: var(--text);
    padding: 8px 13px;
    border-radius: 9px;
    font-size: 12.5px;
    font-weight: 600;
    transition: all 0.15s ease;
    display: inline-flex;
    align-items: center;
    gap: 6px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.03);
  }
  button:hover {
    border-color: var(--accent);
    background: var(--panel-hover);
    transform: translateY(-1px);
  }
  button.primary {
    background: var(--accent);
    color: #ffffff;
    border-color: var(--accent);
  }
  button.primary:hover { background: var(--accent-hover); }
  button.purple-btn {
    background: var(--purple-bg);
    color: var(--purple);
    border-color: var(--purple-border);
  }
  button.purple-btn:hover {
    background: var(--purple);
    color: #ffffff;
  }
  button.danger {
    background: var(--red-bg);
    color: var(--red);
    border-color: var(--red-border);
  }
  button.danger:hover { background: var(--red); color: #fff; }
  button.dragon-toggle-on {
    background: linear-gradient(135deg, #10b981 0%, #0284c7 100%);
    color: #ffffff;
    border-color: #059669;
  }
  button.sm { padding: 5px 10px; font-size: 11.5px; border-radius: 7px; }

  main {
    max-width: 1540px;
    margin: 0 auto;
    padding: 24px 32px 80px;
  }

  /* ================= HOW TO TRAIN YOUR DRAGON THEME ELEMENTS ================= */
  html[data-dragons="off"] .dragon-only {
    display: none !important;
  }

  .dragon-hero {
    background: var(--dragon-banner-bg);
    border: 1px solid var(--dragon-banner-border);
    border-radius: 16px;
    padding: 18px 26px;
    margin-bottom: 22px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 20px;
    position: relative;
    overflow: hidden;
    box-shadow: var(--shadow);
  }

  .dragon-hero-left {
    z-index: 2;
    max-width: 680px;
  }

  .dragon-tag {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    background: rgba(16, 185, 129, 0.16);
    color: var(--green);
    border: 1px solid var(--green-border);
    margin-bottom: 6px;
  }

  .dragon-hero h2 {
    margin: 0 0 4px 0;
    font-size: 18px;
    font-weight: 800;
  }

  .dragon-hero p {
    margin: 0;
    font-size: 13px;
    color: var(--text-soft);
  }

  .dragon-roster {
    display: flex;
    gap: 10px;
    margin-top: 10px;
    flex-wrap: wrap;
  }

  .dragon-chip {
    font-size: 11.5px;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 8px;
    background: var(--panel);
    border: 1px solid var(--border);
    display: inline-flex;
    align-items: center;
    gap: 6px;
    box-shadow: 0 1px 2px rgba(0,0,0,0.03);
  }

  .dragon-art-stage {
    display: flex;
    align-items: center;
    gap: 18px;
    z-index: 2;
  }

  @keyframes floatSlow {
    0%, 100% { transform: translateY(0px); }
    50% { transform: translateY(-6px); }
  }
  @keyframes blinkEyes {
    0%, 92%, 100% { transform: scaleY(1); }
    96% { transform: scaleY(0.08); }
  }
  @keyframes plasmaPulse {
    0%, 100% { opacity: 0.35; transform: scale(0.95); }
    50% { opacity: 0.85; transform: scale(1.08); }
  }
  @keyframes soarAcross {
    0% { transform: translateX(-80px) translateY(10px) scale(0.75); opacity: 0; }
    15% { opacity: 0.22; }
    85% { opacity: 0.22; }
    100% { transform: translateX(900px) translateY(-25px) scale(0.75); opacity: 0; }
  }

  .toothless-svg {
    animation: floatSlow 4.2s ease-in-out infinite;
    filter: drop-shadow(0 8px 16px rgba(15, 23, 42, 0.18));
    cursor: pointer;
  }
  .lightfury-svg {
    animation: floatSlow 4.8s ease-in-out infinite 0.7s;
    filter: drop-shadow(0 8px 16px rgba(2, 132, 199, 0.18));
    cursor: pointer;
  }
  .toothless-eyes {
    transform-origin: center;
    animation: blinkEyes 5.5s infinite;
  }
  .plasma-aura {
    transform-origin: center;
    animation: plasmaPulse 3s ease-in-out infinite;
  }
  .soaring-silhouette {
    position: absolute;
    top: 14px;
    left: 20%;
    pointer-events: none;
    animation: soarAcross 18s linear infinite;
    z-index: 1;
  }

  /* ================= STATS GRID ================= */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
    gap: 14px;
    margin-bottom: 22px;
  }
  .stat-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 16px 18px;
    box-shadow: var(--shadow);
  }
  .stat-card-top {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .stat-card .label {
    font-size: 11.5px;
    font-weight: 700;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .stat-card .val {
    font-size: 28px;
    font-weight: 800;
    margin-top: 6px;
    letter-spacing: -0.5px;
  }
  .stat-card .sub {
    font-size: 12px;
    color: var(--muted);
    margin-top: 3px;
  }
  .stat-dragon-badge {
    font-size: 11px;
    font-weight: 700;
    padding: 3px 8px;
    border-radius: 999px;
    background: var(--panel-alt);
    color: var(--text-soft);
    border: 1px solid var(--border);
  }

  /* ================= TOOLBAR & TABS ================= */
  .toolbar {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 14px 18px;
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
    margin-bottom: 18px;
    box-shadow: var(--shadow);
  }
  .toolbar input, .toolbar select {
    background: var(--panel-alt);
    border: 1px solid var(--border-strong);
    color: var(--text);
    padding: 9px 13px;
    border-radius: 9px;
    font-size: 13px;
    font-weight: 500;
  }
  .toolbar input:focus, .toolbar select:focus {
    outline: none;
    border-color: var(--accent);
    background: var(--panel);
  }
  .toolbar input { flex: 1; min-width: 260px; }

  .tabs {
    display: flex;
    gap: 10px;
    margin-bottom: 16px;
  }
  .tab-btn {
    padding: 9px 18px;
    border-radius: 10px;
    font-size: 13.5px;
    font-weight: 700;
  }
  .tab-btn.active {
    background: var(--accent);
    color: #ffffff;
    border-color: var(--accent);
  }

  /* ================= TABLE ================= */
  .table-wrap {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow-x: auto;
    box-shadow: var(--shadow);
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th, td {
    padding: 12px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }
  th {
    background: var(--panel-alt);
    color: var(--muted);
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  tr:hover td { background: var(--panel-hover); }

  .badge {
    display: inline-block;
    padding: 3px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.3px;
  }
  .badge.ACTIVE { background: var(--green-bg); color: var(--green); border: 1px solid var(--green-border); }
  .badge.EXPIRED { background: var(--red-bg); color: var(--red); border: 1px solid var(--red-border); }
  .badge.CONFIGURED, .badge.UNVERIFIED { background: var(--amber-bg); color: var(--amber); border: 1px solid var(--amber-border); }

  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
    color: var(--mono-color);
  }
  .editable-input {
    background: transparent;
    border: 1px solid transparent;
    color: var(--text);
    padding: 5px 7px;
    border-radius: 7px;
    width: 100%;
    font-size: 13px;
    font-weight: 600;
    transition: all 0.15s ease;
  }
  .editable-input:hover, .editable-input:focus {
    border-color: var(--accent);
    background: var(--panel-alt);
    outline: none;
  }
  .editable-url {
    font-weight: 500;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 12px;
    color: var(--url-color);
  }

  /* ================= MODAL & TOAST ================= */
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: rgba(15, 23, 42, 0.55);
    backdrop-filter: blur(4px);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 100;
  }
  .modal {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 16px;
    width: 100%;
    max-width: 600px;
    padding: 26px;
    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
    max-height: 92vh;
    overflow-y: auto;
  }
  .modal h3 { margin: 0 0 14px 0; font-size: 18px; font-weight: 800; }
  .form-group { margin-bottom: 13px; }
  .form-group label { display: block; font-size: 12px; color: var(--muted); margin-bottom: 5px; font-weight: 600; }
  .form-group input, .form-group select {
    width: 100%;
    background: var(--panel-alt);
    border: 1px solid var(--border-strong);
    color: var(--text);
    padding: 9px 12px;
    border-radius: 8px;
    font-size: 13px;
  }
  .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 20px; }

  .code-box {
    background: var(--panel-alt);
    border: 1px solid var(--border-strong);
    border-radius: 10px;
    padding: 12px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11.5px;
    color: var(--text-soft);
    word-break: break-all;
    margin: 10px 0;
  }

  .toast {
    position: fixed;
    bottom: 24px;
    right: 24px;
    background: var(--panel);
    border: 2px solid var(--accent);
    color: var(--text);
    padding: 12px 18px;
    border-radius: 12px;
    font-size: 13px;
    font-weight: 700;
    display: none;
    z-index: 200;
    box-shadow: var(--shadow);
  }

  .corner-dragon {
    position: fixed;
    bottom: 16px;
    left: 20px;
    z-index: 90;
    background: var(--panel);
    border: 1px solid var(--border-strong);
    border-radius: 999px;
    padding: 6px 14px 6px 8px;
    display: flex;
    align-items: center;
    gap: 8px;
    box-shadow: var(--shadow);
    font-size: 12px;
    font-weight: 700;
    cursor: pointer;
    transition: transform 0.2s ease;
  }
  .corner-dragon:hover {
    transform: scale(1.05);
    border-color: var(--green);
  }
</style>
</head>
<body>
<header>
  <div class="brand">
    <div class="brand-badge">irf</div>
    <div>
      <h1>irfHASH Security Control Center</h1>
      <p>Isolated Runtime Fortress: Hardened Agentic Secret Hub (Claude, Codex &amp; Local AI Ready)</p>
    </div>
  </div>
  <div class="header-actions">
    <a id="bookmarkUrlPill" href="http://irfhash.localhost:8765" class="pill domain-pill" title="Your custom local bookmarkable URL (click Custom URL to change)">⭐ http://irfhash.localhost:8765</a>
    <button onclick="openDomainModal()" title="Set a custom domain name (e.g. irfhash.vault or xyz) to bookmark easily">🌐 Custom URL</button>
    <button class="purple-btn" onclick="openSanitizeModal()" title="Delete raw secrets from AI chat transcripts and replace with AI-readable irfHASH pointers">🛡️ Sanitize Chats</button>
    <button id="themeToggleBtn" onclick="toggleTheme()" title="Switch between White Light Mode and Dark Mode">🌙 Dark Mode</button>
    <button id="dragonToggleBtn" class="dragon-toggle-on" onclick="toggleDragons()" title="Enable or disable the How to Train Your Dragon theme with one click">🐉 Dragons: ON</button>
    <button id="lockdownBtn" onclick="toggleLockdown()">Kill Switch: OFF</button>
    <button onclick="verifyAllConnections()" id="verifyAllBtn">Verify All</button>
    <button class="primary" onclick="openAddModal()">+ Add Connection</button>
  </div>
</header>

<main>
  <!-- HOW TO TRAIN YOUR DRAGON GUARDIAN BANNER -->
  <section class="dragon-hero dragon-only">
    <svg class="soaring-silhouette" width="90" height="44" viewBox="0 0 120 60" fill="none">
      <path d="M60 28 C42 8, 15 4, 2 18 C20 20, 38 26, 54 34 L48 52 L60 40 L72 52 L66 34 C82 26, 100 20, 118 18 C105 4, 78 8, 60 28 Z" fill="currentColor" opacity="0.35"/>
    </svg>

    <div class="dragon-hero-left">
      <div class="dragon-tag">⚡ Isle of Berk Strike Class Security Protocol</div>
      <h2>Toothless &amp; The Dragon Riders Guard Your Local Vault</h2>
      <p>Just like Hiccup's Book of Dragons on Berk, every credential here is locked under Night Fury plasma encryption. Claude Desktop, Codex Desktop, and Antigravity can use your connections without ever seeing a raw secret.</p>
      <div class="dragon-roster">
        <span class="dragon-chip">🖤 <strong>Toothless</strong> (Night Fury: AES-256-GCM Master Key)</span>
        <span class="dragon-chip">🤍 <strong>Light Fury</strong> (Cloaked Chat Redactor)</span>
        <span class="dragon-chip">💙 <strong>Stormfly</strong> (Tracker Class: Health Verifier)</span>
        <span class="dragon-chip">🔥 <strong>Hookfang</strong> (Stoker Class: PROD Write Firewall)</span>
      </div>
    </div>

    <div class="dragon-art-stage">
      <!-- Toothless (Night Fury) Custom SVG -->
      <svg class="toothless-svg" onclick="dragonRoar('Toothless')" width="135" height="108" viewBox="0 0 200 160" title="Click Toothless! (Night Fury)">
        <circle class="plasma-aura" cx="100" cy="82" r="64" fill="url(#plasmaGrad)" />
        <defs>
          <radialGradient id="plasmaGrad" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#38bdf8" stop-opacity="0.45"/>
            <stop offset="100%" stop-color="#10b981" stop-opacity="0"/>
          </radialGradient>
        </defs>
        <path d="M58 82 C25 42, 8 52, 6 88 C22 80, 38 88, 52 98 Z" fill="#1e293b" stroke="#0f172a" stroke-width="2.5"/>
        <path d="M142 82 C175 42, 192 52, 194 88 C178 80, 162 88, 148 98 Z" fill="#1e293b" stroke="#0f172a" stroke-width="2.5"/>
        <path d="M130 125 Q168 135 182 112" stroke="#0f172a" stroke-width="8" stroke-linecap="round" fill="none"/>
        <path d="M180 112 L195 98 L190 116 Z" fill="#e11d48" stroke="#9f1239" stroke-width="1.5"/>
        <path d="M180 112 L172 96 L185 105 Z" fill="#0f172a"/>
        <ellipse cx="100" cy="108" rx="36" ry="30" fill="#0f172a" stroke="#334155" stroke-width="2"/>
        <path d="M72 48 C54 20, 44 26, 62 56 Z" fill="#0f172a" stroke="#334155" stroke-width="2"/>
        <path d="M128 48 C146 20, 156 26, 138 56 Z" fill="#0f172a" stroke="#334155" stroke-width="2"/>
        <path d="M64 62 C44 48, 42 58, 60 70 Z" fill="#1e293b"/>
        <path d="M136 62 C156 48, 158 58, 140 70 Z" fill="#1e293b"/>
        <ellipse cx="100" cy="68" rx="38" ry="28" fill="#0f172a" stroke="#334155" stroke-width="2"/>
        <g class="toothless-eyes">
          <path d="M74 64 Q84 54 93 66 Q84 74 74 64 Z" fill="#10b981"/>
          <ellipse cx="84" cy="64" rx="3.2" ry="6.5" fill="#052e16"/>
          <circle cx="82" cy="61" r="1.6" fill="#ffffff"/>
          <path d="M107 66 Q116 54 126 64 Q116 74 107 66 Z" fill="#10b981"/>
          <ellipse cx="116" cy="64" rx="3.2" ry="6.5" fill="#052e16"/>
          <circle cx="114" cy="61" r="1.6" fill="#ffffff"/>
        </g>
        <circle cx="95" cy="76" r="1.5" fill="#475569"/>
        <circle cx="105" cy="76" r="1.5" fill="#475569"/>
        <path d="M84 83 Q100 90 116 83" stroke="#38bdf8" stroke-width="2" fill="none" stroke-linecap="round"/>
      </svg>

      <!-- Light Fury Custom SVG -->
      <svg class="lightfury-svg" onclick="dragonRoar('Light Fury')" width="120" height="100" viewBox="0 0 200 160" title="Click Light Fury!">
        <path d="M58 84 C26 48, 10 56, 10 88 C26 80, 40 88, 54 96 Z" fill="#f8fafc" stroke="#93c5fd" stroke-width="2.5"/>
        <path d="M142 84 C174 48, 190 56, 190 88 C174 80, 160 88, 146 96 Z" fill="#f8fafc" stroke="#93c5fd" stroke-width="2.5"/>
        <path d="M126 122 Q162 132 178 108" stroke="#e2e8f0" stroke-width="7" stroke-linecap="round" fill="none"/>
        <path d="M178 108 L192 96 L186 114 L172 98 Z" fill="#e0f2fe" stroke="#38bdf8" stroke-width="1.5"/>
        <ellipse cx="100" cy="108" rx="32" ry="27" fill="#ffffff" stroke="#bae6fd" stroke-width="2.5"/>
        <path d="M75 50 C60 24, 50 30, 66 58 Z" fill="#ffffff" stroke="#93c5fd" stroke-width="2"/>
        <path d="M125 50 C140 24, 150 30, 134 58 Z" fill="#ffffff" stroke="#93c5fd" stroke-width="2"/>
        <ellipse cx="100" cy="68" rx="34" ry="25" fill="#ffffff" stroke="#bae6fd" stroke-width="2.5"/>
        <g class="toothless-eyes">
          <path d="M76 64 Q85 55 93 66 Q85 73 76 64 Z" fill="#38bdf8"/>
          <ellipse cx="85" cy="64" rx="2.8" ry="5.8" fill="#0c4a6e"/>
          <circle cx="83" cy="61" r="1.5" fill="#ffffff"/>
          <path d="M107 66 Q115 55 124 64 Q115 73 107 66 Z" fill="#38bdf8"/>
          <ellipse cx="115" cy="64" rx="2.8" ry="5.8" fill="#0c4a6e"/>
          <circle cx="113" cy="61" r="1.5" fill="#ffffff"/>
        </g>
        <path d="M88 81 Q100 86 112 81" stroke="#93c5fd" stroke-width="2" fill="none" stroke-linecap="round"/>
      </svg>
    </div>
  </section>

  <!-- STATS CARDS -->
  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-card-top">
        <div class="label">Total Connections</div>
        <span class="stat-dragon-badge dragon-only">📖 Book of Dragons</span>
      </div>
      <div class="val" id="statTotal">0</div>
      <div class="sub">Encrypted in local vault</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-top">
        <div class="label">Active &amp; Verified</div>
        <span class="stat-dragon-badge dragon-only">🖤 Toothless Strike</span>
      </div>
      <div class="val" id="statActive" style="color: var(--green);">0</div>
      <div class="sub">Ready for zero-leak agent calls</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-top">
        <div class="label">Expired / Rotate</div>
        <span class="stat-dragon-badge dragon-only">🔥 Hookfang Alert</span>
      </div>
      <div class="val" id="statExpired" style="color: var(--red);">0</div>
      <div class="sub">Kept for reference or key replacement</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-top">
        <div class="label">PROD Write-Locked</div>
        <span class="stat-dragon-badge dragon-only">💙 Stormfly Shield</span>
      </div>
      <div class="val" id="statProd" style="color: var(--amber);">0</div>
      <div class="sub">Hard-blocked from any mutation</div>
    </div>
    <div class="stat-card">
      <div class="stat-card-top">
        <div class="label">Audit Events Logged</div>
        <span class="stat-dragon-badge dragon-only">🪨 Meatlug Ledger</span>
      </div>
      <div class="val" id="statAudit" style="color: var(--accent);">0</div>
      <div class="sub">SHA-256 hash-chained log</div>
    </div>
  </div>

  <div class="tabs">
    <button class="tab-btn active" id="tabConnBtn" onclick="switchTab('connections')">Connections &amp; Credentials</button>
    <button class="tab-btn" id="tabAuditBtn" onclick="switchTab('audit')">Immutable Audit Log (InfoSec View)</button>
  </div>

  <div id="connectionsSection">
    <div class="toolbar">
      <input type="text" id="searchInput" placeholder="Search by editable name, ID, URL, system, or masked key..." oninput="renderConnections()">
      <select id="filterSystem" onchange="renderConnections()">
        <option value="ALL">All Systems</option>
      </select>
      <select id="filterStatus" onchange="renderConnections()">
        <option value="ALL">All Statuses</option>
        <option value="ACTIVE">ACTIVE</option>
        <option value="EXPIRED">EXPIRED</option>
        <option value="CONFIGURED">CONFIGURED</option>
        <option value="UNVERIFIED">UNVERIFIED</option>
      </select>
      <select id="filterEnv" onchange="renderConnections()">
        <option value="ALL">All Environments</option>
        <option value="TEST">TEST</option>
        <option value="UAT">UAT</option>
        <option value="DEV">DEV</option>
        <option value="PROD">PROD (Write-Locked)</option>
        <option value="PERSONAL">PERSONAL</option>
      </select>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th style="width: 230px;">Editable Name &amp; ID</th>
            <th style="width: 115px;">System &amp; Env</th>
            <th style="width: 300px;">Editable URL / Endpoint</th>
            <th style="width: 155px;">Masked Secret</th>
            <th style="width: 170px;">Status</th>
            <th style="width: 185px;">Agent Permission Policy</th>
            <th style="width: 180px;">Editable Notes</th>
            <th style="width: 175px;">Actions</th>
          </tr>
        </thead>
        <tbody id="connTableBody"></tbody>
      </table>
    </div>
  </div>

  <div id="auditSection" style="display: none;">
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Connection ID</th>
            <th>Method &amp; Target</th>
            <th>Decision</th>
            <th>Detail</th>
            <th>SHA-256 Chain Hash</th>
          </tr>
        </thead>
        <tbody id="auditTableBody"></tbody>
      </table>
    </div>
  </div>
</main>

<!-- Corner Toothless Companion -->
<div class="corner-dragon dragon-only" onclick="dragonRoar('Toothless')" title="Click Toothless for a Night Fury status check!">
  <span style="font-size: 18px;">🐉</span>
  <span id="cornerDragonText">Toothless is guarding your keys</span>
</div>

<!-- Add / Replace Connection Modal (Expanded with 22 App Presets) -->
<div class="modal-backdrop" id="connModal">
  <div class="modal">
    <h3 id="modalTitle">Add or Replace Connection</h3>
    <div class="form-group" id="presetGroup">
      <label>Quick Application Preset (Auto-fills Auth &amp; URL settings)</label>
      <select id="mPreset" onchange="applyAppPreset(this.value)">
        <option value="">Select an application preset (or configure custom below)...</option>
        <option value="slack">💬 Slack (Bot / User OAuth Token xoxb / xoxp)</option>
        <option value="jira">📋 Jira Cloud (Atlassian API Token)</option>
        <option value="search-cluster">📊 Analytics Dashboard (Search / Analytics Dashboard API Key)</option>
        <option value="search-engine">🔍 Search Engine (Cluster API Key)</option>
        <option value="hr-platform">🏢 HR Platform (REST / A2A OAuth2 Client)</option>
        <option value="itsm-platform">🛠️ ITSM Platform (REST / MCP OAuth2 / Bearer)</option>
        <option value="diagram-api">📐 Diagram API (REST API v1 Bearer Key)</option>
        <option value="github">🐙 GitHub (Personal Access Token / Fine-Grained PAT)</option>
        <option value="gitlab">🦊 GitLab (Personal / Project Access Token)</option>
        <option value="google">☁️ Google Workspace / Google Cloud API</option>
        <option value="confluence">📘 Confluence Cloud (Atlassian API Token)</option>
        <option value="notion">📝 Notion (Internal Integration Bearer Token)</option>
        <option value="linear">⚡ Linear (GraphQL API Key)</option>
        <option value="okta">🔐 Okta (SSWS Admin / API Token)</option>
        <option value="datadog">🐶 Datadog (DD-API-KEY)</option>
        <option value="pagerduty">📟 PagerDuty (REST API Token)</option>
        <option value="openai">🤖 OpenAI (API Key sk-...)</option>
        <option value="anthropic">🧠 Anthropic Claude (x-api-key)</option>
        <option value="azure-openai">🔷 Azure OpenAI (api-key)</option>
        <option value="langsmith">🦜 LangSmith (Tracing x-api-key)</option>
        <option value="jina">🔎 Jina AI (Reader &amp; Embeddings Bearer Key)</option>
        <option value="custom">⚙️ Custom REST / GraphQL / MCP Endpoint</option>
      </select>
    </div>
    <div class="form-group">
      <label>Connection ID (unique slug used by AI agents)</label>
      <input type="text" id="mConnId" placeholder="e.g. slack-workspace-bot or jira-main">
    </div>
    <div class="form-group">
      <label>Friendly Display Name (Editable anytime)</label>
      <input type="text" id="mName" placeholder="e.g. Slack Workspace Bot Token">
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px;">
      <div class="form-group">
        <label>System Category</label>
        <input type="text" id="mSystem" placeholder="slack, jira, github, notion, stripe, openai...">
      </div>
      <div class="form-group">
        <label>Environment</label>
        <select id="mEnv">
          <option value="TEST">TEST</option>
          <option value="UAT">UAT</option>
          <option value="DEV">DEV</option>
          <option value="PROD">PROD (Auto Write-Lock)</option>
          <option value="PERSONAL">PERSONAL</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <label>Base URL / Endpoint</label>
      <input type="text" id="mUrl" placeholder="https://...">
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px;">
      <div class="form-group">
        <label>Auth Type</label>
        <select id="mAuthType">
          <option value="ApiKey">ApiKey</option>
          <option value="Bearer">Bearer</option>
          <option value="Basic">Basic (User:Token)</option>
          <option value="CustomHeader">CustomHeader</option>
          <option value="OAuth2Client">OAuth2Client</option>
        </select>
      </div>
      <div class="form-group">
        <label>Header Name</label>
        <input type="text" id="mHeaderName" value="Authorization">
      </div>
      <div class="form-group">
        <label>Header Prefix</label>
        <input type="text" id="mHeaderPrefix" value="ApiKey ">
      </div>
    </div>
    <div class="form-group">
      <label>Secret / API Key / Token (Encrypted immediately into macOS Keychain + AES-256-GCM)</label>
      <input type="password" id="mSecret" placeholder="Paste new API key or token here (leave blank to keep existing)">
    </div>
    <div class="form-group">
      <label>Notes (For your reference)</label>
      <input type="text" id="mNotes" placeholder="Optional reference note">
    </div>
    <div class="modal-actions">
      <button onclick="closeModal('connModal')">Cancel</button>
      <button class="primary" onclick="saveModalConnection()">Encrypt &amp; Save</button>
    </div>
  </div>
</div>

<!-- Sanitize & Redact Chats Modal -->
<div class="modal-backdrop" id="sanitizeModal">
  <div class="modal">
    <h3>🛡️ Sanitize &amp; Redact AI Chat Logs</h3>
    <p style="font-size: 13px; color: var(--text-soft); margin-top: 0;">
      This tool scans your local AI chat histories (Claude Desktop, Codex Desktop, Antigravity) for any raw API keys or tokens stored in your <strong>irfHASH</strong> vault. It deletes the sensitive plaintext from the chat files and replaces it with an AI-readable pointer:
    </p>
    <div class="code-box">
      [REDACTED_BY_IRFHASH:id=&lt;conn_id&gt;|system=&lt;sys&gt;|env=&lt;env&gt;|note=Secret secured in local irfHASH vault. AI agents: run 'irfhash request &lt;conn_id&gt; &lt;METHOD&gt; &lt;path&gt;' to use without exposing credentials]
    </div>
    <div id="sanitizeStatusBox" style="background: var(--panel-alt); border: 1px solid var(--border); border-radius: 10px; padding: 14px; font-size: 13px; margin-top: 12px;">
      Scanning chat files for raw secrets...
    </div>
    <div class="modal-actions">
      <button onclick="closeModal('sanitizeModal')">Close</button>
      <button class="purple-btn" onclick="runSanitize(true)">Re-Scan (Dry Run)</button>
      <button class="primary" id="execSanitizeBtn" onclick="runSanitize(false)">🛡️ Redact All Secrets in Chats Now</button>
    </div>
  </div>
</div>

<!-- Custom Local Domain / Bookmarkable URL Modal -->
<div class="modal-backdrop" id="domainModal">
  <div class="modal">
    <h3>🌐 Custom Local Domain &amp; Bookmark URL</h3>
    <p style="font-size: 13px; color: var(--text-soft); margin-top: 0;">
      Instead of typing <code>127.0.0.1</code>, assign any memorable domain name to your local <strong>irfHASH</strong> dashboard so you can bookmark or star it in your browser.
    </p>
    <div class="form-group">
      <label>Choose or Type Any Custom Domain Name (e.g. irfhash.localhost, irfhash.vault, berk.local, mykeys.box)</label>
      <input type="text" id="mCustomDomain" placeholder="irfhash.localhost">
    </div>
    <div style="font-size: 12px; color: var(--muted); margin-bottom: 12px;">
      💡 <strong>Tip:</strong> Any name ending in <code>.localhost</code> (such as <code>irfhash.localhost</code> or <code>berk.localhost</code>) works immediately in all browsers without even touching <code>/etc/hosts</code>! For custom top-level names like <code>irfhash.vault</code> or <code>xyz.local</code>, check the box below to map it in <code>/etc/hosts</code>.
    </div>
    <div class="form-group" style="display:flex; align-items:center; gap:8px;">
      <input type="checkbox" id="mMapHosts" style="width:auto;">
      <label for="mMapHosts" style="margin:0; cursor:pointer;">Also add <code>127.0.0.1 &lt;domain&gt;</code> to <code>/etc/hosts</code> (macOS Admin Prompt)</label>
    </div>
    <div id="domainResultBox" class="code-box" style="display:none;"></div>
    <div class="modal-actions">
      <button onclick="closeModal('domainModal')">Close</button>
      <button class="primary" onclick="saveCustomDomain()">Save &amp; Activate URL</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
let state = { connections: {}, settings: {}, audit: [] };

const APP_PRESETS = {
  "slack": { system: "slack", url: "https://slack.com/api", auth_type: "Bearer", header_name: "Authorization", header_prefix: "Bearer ", name: "Slack Workspace Bot / User Token" },
  "jira": { system: "jira", url: "https://your-domain.atlassian.net", auth_type: "Basic", header_name: "Authorization", header_prefix: "Basic ", name: "Jira Cloud API Token" },
  "search-cluster": { system: "search-cluster", url: "https://search-cluster.example.com", auth_type: "ApiKey", header_name: "Authorization", header_prefix: "ApiKey ", name: "Analytics Dashboard Cluster API Key" },
  "search-engine": { system: "search-engine", url: "https://search.example.com:443", auth_type: "ApiKey", header_name: "Authorization", header_prefix: "ApiKey ", name: "Search Engine Cluster API Key" },
  "hr-platform": { system: "hr-platform", url: "https://hr-api.example.com", auth_type: "OAuth2Client", header_name: "Authorization", header_prefix: "Bearer ", name: "HR Platform OAuth2 / A2A Gateway" },
  "itsm-platform": { system: "itsm-platform", url: "https://your-instance.service-now.com", auth_type: "Bearer", header_name: "Authorization", header_prefix: "Bearer ", name: "ITSM Platform REST / MCP Endpoint" },
  "diagram-api": { system: "diagram-api", url: "https://api.stripe.com/v1", auth_type: "Bearer", header_name: "Authorization", header_prefix: "Bearer ", name: "Diagram API REST API v1 Key" },
  "github": { system: "github", url: "https://api.github.com", auth_type: "Bearer", header_name: "Authorization", header_prefix: "Bearer ", name: "GitHub Personal Access Token" },
  "gitlab": { system: "gitlab", url: "https://gitlab.com/api/v4", auth_type: "CustomHeader", header_name: "PRIVATE-TOKEN", header_prefix: "", name: "GitLab Personal Access Token" },
  "google": { system: "google-api", url: "https://www.googleapis.com", auth_type: "CustomHeader", header_name: "X-Goog-Api-Key", header_prefix: "", name: "Google Cloud / Workspace API Key" },
  "confluence": { system: "confluence", url: "https://your-domain.atlassian.net/wiki", auth_type: "Basic", header_name: "Authorization", header_prefix: "Basic ", name: "Confluence Cloud API Token" },
  "notion": { system: "notion", url: "https://api.notion.com/v1", auth_type: "Bearer", header_name: "Authorization", header_prefix: "Bearer ", name: "Notion Integration Token" },
  "linear": { system: "linear", url: "https://api.linear.app/graphql", auth_type: "Bearer", header_name: "Authorization", header_prefix: "", name: "Linear GraphQL API Key" },
  "okta": { system: "okta", url: "https://your-org.okta.com", auth_type: "CustomHeader", header_name: "Authorization", header_prefix: "SSWS ", name: "Okta SSWS API Token" },
  "datadog": { system: "datadog", url: "https://api.datadoghq.com", auth_type: "CustomHeader", header_name: "DD-API-KEY", header_prefix: "", name: "Datadog API Key" },
  "pagerduty": { system: "pagerduty", url: "https://api.pagerduty.com", auth_type: "CustomHeader", header_name: "Authorization", header_prefix: "Token token=", name: "PagerDuty REST API Key" },
  "openai": { system: "openai", url: "https://api.openai.com/v1", auth_type: "Bearer", header_name: "Authorization", header_prefix: "Bearer ", name: "OpenAI API Key" },
  "anthropic": { system: "anthropic", url: "https://api.anthropic.com/v1", auth_type: "CustomHeader", header_name: "x-api-key", header_prefix: "", name: "Anthropic Claude API Key" },
  "azure-openai": { system: "azure-openai", url: "https://your-resource.openai.azure.com", auth_type: "CustomHeader", header_name: "api-key", header_prefix: "", name: "Azure OpenAI API Key" },
  "langsmith": { system: "langsmith", url: "https://api.smith.langchain.com", auth_type: "CustomHeader", header_name: "x-api-key", header_prefix: "", name: "LangSmith Tracing API Key" },
  "jina": { system: "jina", url: "https://r.jina.ai", auth_type: "Bearer", header_name: "Authorization", header_prefix: "Bearer ", name: "Jina Reader & Embeddings Key" },
  "custom": { system: "custom", url: "https://api.example.com", auth_type: "Bearer", header_name: "Authorization", header_prefix: "Bearer ", name: "Custom API Connection" }
};

(function initPreferences() {
  const savedTheme = localStorage.getItem('irfhash_theme') || 'light';
  const savedDragons = localStorage.getItem('irfhash_dragons') || 'on';
  applyTheme(savedTheme);
  applyDragons(savedDragons);
})();

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('irfhash_theme', theme);
  const btn = document.getElementById('themeToggleBtn');
  if (btn) {
    btn.textContent = theme === 'light' ? '🌙 Dark Mode' : '☀️ Light Mode';
  }
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const next = current === 'light' ? 'dark' : 'light';
  applyTheme(next);
  showToast(next === 'light' ? 'Switched to White Light Mode' : 'Switched to Dark Mode');
}

function applyDragons(mode) {
  document.documentElement.setAttribute('data-dragons', mode);
  localStorage.setItem('irfhash_dragons', mode);
  const btn = document.getElementById('dragonToggleBtn');
  if (btn) {
    if (mode === 'on') {
      btn.textContent = '🐉 Dragons: ON';
      btn.className = 'dragon-toggle-on';
    } else {
      btn.textContent = '🐉 Dragons: OFF';
      btn.className = '';
    }
  }
}

function toggleDragons() {
  const current = document.documentElement.getAttribute('data-dragons') || 'on';
  const next = current === 'on' ? 'off' : 'on';
  applyDragons(next);
  showToast(next === 'on' ? '🐉 Isle of Berk Dragons Theme Enabled!' : 'Dragons Theme Disabled (Clean Mode)');
}

function applyAppPreset(presetKey) {
  const p = APP_PRESETS[presetKey];
  if (!p) return;
  document.getElementById('mSystem').value = p.system;
  document.getElementById('mUrl').value = p.url;
  document.getElementById('mAuthType').value = p.auth_type;
  document.getElementById('mHeaderName').value = p.header_name;
  document.getElementById('mHeaderPrefix').value = p.header_prefix;
  if (!document.getElementById('mName').value) {
    document.getElementById('mName').value = p.name;
  }
  if (!document.getElementById('mConnId').value && !document.getElementById('mConnId').disabled) {
    document.getElementById('mConnId').value = p.system + '-primary';
  }
}

function dragonRoar(name) {
  const activeCnt = Object.values(state.connections || {}).filter(c => c.status === 'ACTIVE').length;
  if (name === 'Toothless') {
    showToast(`🖤 Toothless fires a plasma salute! ${activeCnt} active connections verified and guarded.`);
  } else {
    showToast(`🤍 Light Fury cloaks your vault: zero secrets ever exposed in chat.`);
  }
}

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.style.display = 'block';
  clearTimeout(window._toastTimer);
  window._toastTimer = setTimeout(() => { t.style.display = 'none'; }, 3400);
}

async function fetchState() {
  const res = await fetch('/api/state');
  state = await res.json();
  updateStatsAndFilters();
  renderConnections();
  renderAudit();
}

function updateStatsAndFilters() {
  const list = Object.values(state.connections || {});
  const activeCount = list.filter(c => c.status === 'ACTIVE').length;
  document.getElementById('statTotal').textContent = list.length;
  document.getElementById('statActive').textContent = activeCount;
  document.getElementById('statExpired').textContent = list.filter(c => c.status === 'EXPIRED').length;
  document.getElementById('statProd').textContent = list.filter(c => c.environment === 'PROD' || c.prod_write_lock).length;
  document.getElementById('statAudit').textContent = (state.audit || []).length;

  const cd = document.getElementById('cornerDragonText');
  if (cd) {
    cd.textContent = `Toothless is guarding ${list.length} keys (${activeCount} active)`;
  }

  const dom = (state.settings && state.settings.custom_domain) ? state.settings.custom_domain : 'irfhash.localhost';
  const port = (state.settings && state.settings.dashboard_port) ? state.settings.dashboard_port : 8765;
  const pill = document.getElementById('bookmarkUrlPill');
  if (pill) {
    pill.textContent = `⭐ http://${dom}:${port}`;
    pill.href = `http://${dom}:${port}`;
  }

  const lb = document.getElementById('lockdownBtn');
  if (state.settings && state.settings.global_lockdown) {
    lb.textContent = 'GLOBAL LOCKDOWN: ON';
    lb.className = 'danger';
  } else {
    lb.textContent = 'Kill Switch: OFF';
    lb.className = '';
  }

  const sysSel = document.getElementById('filterSystem');
  const currentVal = sysSel.value;
  const systems = Array.from(new Set(list.map(c => c.system))).sort();
  sysSel.innerHTML = '<option value="ALL">All Systems</option>' +
    systems.map(s => `<option value="${s}">${s.toUpperCase()}</option>`).join('');
  if (systems.includes(currentVal)) sysSel.value = currentVal;
}

function renderConnections() {
  const q = document.getElementById('searchInput').value.toLowerCase();
  const sysF = document.getElementById('filterSystem').value;
  const stF = document.getElementById('filterStatus').value;
  const envF = document.getElementById('filterEnv').value;

  const list = Object.values(state.connections || {}).sort((a, b) => {
    const order = { ACTIVE: 1, CONFIGURED: 2, UNVERIFIED: 3, EXPIRED: 4 };
    const oa = order[a.status] || 5;
    const ob = order[b.status] || 5;
    if (oa !== ob) return oa - ob;
    return a.name.localeCompare(b.name);
  });

  const filtered = list.filter(c => {
    if (sysF !== 'ALL' && c.system !== sysF) return false;
    if (stF !== 'ALL' && c.status !== stF) return false;
    if (envF !== 'ALL' && c.environment !== envF) return false;
    if (q) {
      const hay = `${c.id} ${c.name} ${c.system} ${c.url} ${c.masked_preview} ${c.notes || ''} ${c.status_detail || ''}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });

  const tbody = document.getElementById('connTableBody');
  tbody.innerHTML = filtered.map(c => `
    <tr>
      <td>
        <input class="editable-input" value="${esc(c.name)}" title="Click to edit friendly name"
          onchange="inlineUpdate('${esc(c.id)}', {name: this.value})">
        <div class="mono" style="padding-left:7px; font-size:11px; color:var(--muted);">${esc(c.id)}</div>
      </td>
      <td>
        <div style="font-weight:700; text-transform:uppercase; font-size:11.5px; margin-bottom:4px;">${esc(c.system)}</div>
        <select style="background:var(--panel-alt); color:var(--text); border:1px solid var(--border-strong); border-radius:6px; font-size:11px; padding:3px 6px; font-weight:600;"
          onchange="inlineUpdate('${esc(c.id)}', {environment: this.value})">
          ${['TEST','UAT','DEV','PROD','PERSONAL'].map(e => `<option value="${e}" ${c.environment===e?'selected':''}>${e}</option>`).join('')}
        </select>
        ${(c.environment === 'PROD' || c.prod_write_lock) ? '<div style="font-size:10.5px; font-weight:700; color:var(--amber); margin-top:3px;">🔒 Write-Locked</div>' : ''}
      </td>
      <td>
        <input class="editable-input editable-url" value="${esc(c.url)}" title="Click to edit URL"
          onchange="inlineUpdate('${esc(c.id)}', {url: this.value})">
      </td>
      <td>
        <span class="mono">${esc(c.masked_preview)}</span>
        <div style="font-size:10.5px; color:var(--muted); margin-top:2px;">${esc(c.auth_type)}</div>
      </td>
      <td>
        <span class="badge ${esc(c.status)}">${esc(c.status)}</span>
        <div style="font-size:11px; color:var(--muted); margin-top:4px; max-width:165px; word-break:break-word;">${esc(c.status_detail || '')}</div>
      </td>
      <td>
        <select style="background:var(--panel-alt); color:var(--text); border:1px solid var(--border-strong); border-radius:7px; font-size:11.5px; padding:5px 8px; width:100%; font-weight:500;"
          onchange="inlineUpdate('${esc(c.id)}', {permission_mode: this.value})">
          <option value="ALLOW_READ_ASK_WRITE" ${c.permission_mode==='ALLOW_READ_ASK_WRITE'?'selected':''}>Allow Read / Prompt Write</option>
          <option value="ASK_EVERY_TIME" ${c.permission_mode==='ASK_EVERY_TIME'?'selected':''}>Prompt Every Time (macOS)</option>
          <option value="SESSION_15M" ${c.permission_mode==='SESSION_15M'?'selected':''}>15m Session Lease</option>
          <option value="LOCKED" ${c.permission_mode==='LOCKED'?'selected':''}>LOCKED (Block All Agents)</option>
        </select>
      </td>
      <td>
        <input class="editable-input" style="font-weight:400; font-size:12px;" value="${esc(c.notes || '')}" placeholder="Add note..."
          onchange="inlineUpdate('${esc(c.id)}', {notes: this.value})">
      </td>
      <td>
        <div style="display:flex; gap:6px; flex-wrap:wrap;">
          <button class="sm" onclick="verifyOne('${esc(c.id)}')">Verify</button>
          <button class="sm" onclick="openReplaceModal('${esc(c.id)}')">Replace Key</button>
          <button class="sm danger" onclick="deleteConn('${esc(c.id)}')">Remove</button>
        </div>
      </td>
    </tr>
  `).join('');
}

function renderAudit() {
  const tbody = document.getElementById('auditTableBody');
  tbody.innerHTML = (state.audit || []).map(a => `
    <tr>
      <td class="mono">${esc(a.timestamp)}</td>
      <td>${esc(a.actor)}</td>
      <td class="mono">${esc(a.action)}</td>
      <td class="mono">${esc(a.connection_id)}</td>
      <td class="mono" style="max-width:280px; overflow:hidden; text-overflow:ellipsis;">${esc(a.method || '')} ${esc(a.target || '')}</td>
      <td><span class="badge ${a.decision.includes('DENIED') || a.decision==='EXPIRED' ? 'EXPIRED' : 'ACTIVE'}">${esc(a.decision)}</span></td>
      <td style="font-size:12px; color:var(--muted);">${esc(a.detail || '')}</td>
      <td class="mono" style="font-size:11px; color:var(--muted);">${esc((a.hash || '').slice(0, 16))}...</td>
    </tr>
  `).join('');
}

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function switchTab(tab) {
  document.getElementById('connectionsSection').style.display = tab === 'connections' ? 'block' : 'none';
  document.getElementById('auditSection').style.display = tab === 'audit' ? 'block' : 'none';
  document.getElementById('tabConnBtn').className = 'tab-btn' + (tab === 'connections' ? ' active' : '');
  document.getElementById('tabAuditBtn').className = 'tab-btn' + (tab === 'audit' ? ' active' : '');
}

async function inlineUpdate(id, updates) {
  const res = await fetch('/api/update', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ id, updates })
  });
  if (res.ok) {
    showToast(`Saved changes for ${id}`);
    await fetchState();
  }
}

async function verifyOne(id) {
  showToast(`Verifying ${id}...`);
  const res = await fetch('/api/verify', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ id })
  });
  const data = await res.json();
  showToast(`${id}: ${data.status} (${data.status_detail})`);
  await fetchState();
}

async function verifyAllConnections() {
  const btn = document.getElementById('verifyAllBtn');
  btn.textContent = 'Verifying...';
  btn.disabled = true;
  showToast('Running safe read-only verification across all connections...');
  await fetch('/api/verify_all', { method: 'POST' });
  btn.textContent = 'Verify All';
  btn.disabled = false;
  showToast('All connections verified!');
  await fetchState();
}

async function deleteConn(id) {
  if (!confirm(`Remove connection '${id}' and wipe its encrypted secret from vault and macOS Keychain?`)) return;
  await fetch('/api/delete', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ id })
  });
  showToast(`Removed ${id}`);
  await fetchState();
}

async function toggleLockdown() {
  const next = !(state.settings && state.settings.global_lockdown);
  await fetch('/api/lockdown', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ global_lockdown: next })
  });
  showToast(next ? 'GLOBAL LOCKDOWN ENABLED: All agent calls blocked' : 'Global Lockdown disabled');
  await fetchState();
}

function openAddModal() {
  document.getElementById('modalTitle').textContent = 'Add New Encrypted Connection';
  document.getElementById('presetGroup').style.display = 'block';
  document.getElementById('mPreset').value = '';
  document.getElementById('mConnId').value = '';
  document.getElementById('mConnId').disabled = false;
  document.getElementById('mName').value = '';
  document.getElementById('mSystem').value = 'search-cluster';
  document.getElementById('mEnv').value = 'TEST';
  document.getElementById('mUrl').value = '';
  document.getElementById('mAuthType').value = 'ApiKey';
  document.getElementById('mHeaderName').value = 'Authorization';
  document.getElementById('mHeaderPrefix').value = 'ApiKey ';
  document.getElementById('mSecret').value = '';
  document.getElementById('mNotes').value = '';
  document.getElementById('connModal').style.display = 'flex';
}

function openReplaceModal(id) {
  const c = state.connections[id];
  if (!c) return;
  document.getElementById('modalTitle').textContent = `Replace Key / Edit: ${c.name}`;
  document.getElementById('presetGroup').style.display = 'none';
  document.getElementById('mConnId').value = c.id;
  document.getElementById('mConnId').disabled = true;
  document.getElementById('mName').value = c.name;
  document.getElementById('mSystem').value = c.system;
  document.getElementById('mEnv').value = c.environment;
  document.getElementById('mUrl').value = c.url;
  document.getElementById('mAuthType').value = c.auth_type;
  document.getElementById('mHeaderName').value = c.header_name || 'Authorization';
  document.getElementById('mHeaderPrefix').value = c.header_prefix !== undefined ? c.header_prefix : 'ApiKey ';
  document.getElementById('mSecret').value = '';
  document.getElementById('mNotes').value = c.notes || '';
  document.getElementById('connModal').style.display = 'flex';
}

function closeModal(modalId) {
  document.getElementById(modalId || 'connModal').style.display = 'none';
}

async function saveModalConnection() {
  const payload = {
    id: document.getElementById('mConnId').value.trim(),
    name: document.getElementById('mName').value.trim(),
    system: document.getElementById('mSystem').value.trim() || 'other',
    environment: document.getElementById('mEnv').value,
    url: document.getElementById('mUrl').value.trim(),
    auth_type: document.getElementById('mAuthType').value,
    header_name: document.getElementById('mHeaderName').value.trim(),
    header_prefix: document.getElementById('mHeaderPrefix').value,
    secret_value: document.getElementById('mSecret').value.trim() || null,
    notes: document.getElementById('mNotes').value.trim(),
  };
  if (!payload.id || !payload.name) {
    alert('Connection ID and Friendly Name are required.');
    return;
  }
  await fetch('/api/upsert', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });
  closeModal('connModal');
  showToast(`Saved ${payload.name} to encrypted vault`);
  await fetchState();
}

async function openSanitizeModal() {
  document.getElementById('sanitizeModal').style.display = 'flex';
  await runSanitize(true);
}

async function runSanitize(dryRun) {
  const box = document.getElementById('sanitizeStatusBox');
  box.innerHTML = dryRun
    ? '🔍 Running dry-run scan across Claude, Codex, and Antigravity chat files...'
    : '🛡️ Redacting all raw secrets from chat transcripts and replacing with AI-readable irfHASH pointers...';
  const res = await fetch('/api/sanitize', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ dry_run: dryRun })
  });
  const data = await res.json();
  const affectedKeys = Object.entries(data.affected_connections || {});
  const breakdown = affectedKeys.length
    ? '<ul style="margin:8px 0 0 18px; padding:0;">' + affectedKeys.map(([k, v]) => `<li><code>${esc(k)}</code>: ${v} occurrences</li>`).join('') + '</ul>'
    : '<div style="margin-top:6px; color:var(--green); font-weight:700;">✅ Zero raw vault secrets exposed in chat files!</div>';

  box.innerHTML = `
    <div><strong>Mode:</strong> ${dryRun ? 'Preview (Dry Run)' : '✅ Sanitized & Redacted'}</div>
    <div><strong>Chat / Session Files Scanned:</strong> ${data.files_scanned}</div>
    <div><strong>Files Containing Raw Vault Secrets:</strong> ${data.files_with_secrets}</div>
    <div><strong>Total Secret Occurrences ${dryRun ? 'Found' : 'Replaced with AI Pointers'}:</strong> ${data.total_redactions}</div>
    ${breakdown}
  `;
  if (!dryRun) {
    showToast(`Redacted ${data.total_redactions} secrets across ${data.files_with_secrets} chat files!`);
    await fetchState();
  }
}

function openDomainModal() {
  const dom = (state.settings && state.settings.custom_domain) ? state.settings.custom_domain : 'irfhash.localhost';
  document.getElementById('mCustomDomain').value = dom;
  document.getElementById('domainResultBox').style.display = 'none';
  document.getElementById('domainModal').style.display = 'flex';
}

async function saveCustomDomain() {
  const domain = document.getElementById('mCustomDomain').value.trim() || 'irfhash.localhost';
  const mapHosts = document.getElementById('mMapHosts').checked;
  const res = await fetch('/api/domain', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({ domain, map_etc_hosts: mapHosts })
  });
  const data = await res.json();
  const rbox = document.getElementById('domainResultBox');
  rbox.style.display = 'block';
  rbox.innerHTML = `
    <div><strong>Bookmark URL:</strong> <a href="${esc(data.url)}" target="_blank" style="color:var(--accent);">${esc(data.url)}</a></div>
    <div><strong>Instant .localhost Alias:</strong> <a href="${esc(data.fallback_localhost_url)}" target="_blank" style="color:var(--accent);">${esc(data.fallback_localhost_url)}</a></div>
    <div style="margin-top:4px;">${esc(data.message)}</div>
  `;
  showToast(`Custom URL set to ${data.url}`);
  await fetchState();
}

fetchState();
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    vault = IrfHashVault()

    def log_message(self, format, *args):
        pass

    def _send_json(self, data, status=200):
        raw = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/?"):
            raw = DASHBOARD_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
            return

        if self.path == "/api/state":
            cat = self.vault.load_catalog()
            settings = self.vault.load_settings()
            audit = self.vault.get_audit_logs(200)
            self._send_json(
                {
                    "connections": cat.get("connections", {}),
                    "settings": settings,
                    "audit": audit,
                }
            )
            return

        self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        payload = json.loads(body) if body else {}

        if self.path == "/api/update":
            cid = payload["id"]
            updates = payload.get("updates", {})
            entry = self.vault.update_metadata(cid, updates, actor="dashboard-user")
            self._send_json(entry)
            return

        if self.path == "/api/upsert":
            entry = self.vault.upsert_connection(
                conn_id=payload["id"],
                name=payload["name"],
                system=payload.get("system", "other"),
                url=payload.get("url", ""),
                environment=payload.get("environment", "TEST"),
                auth_type=payload.get("auth_type", "ApiKey"),
                secret_value=payload.get("secret_value"),
                header_name=payload.get("header_name", "Authorization"),
                header_prefix=payload.get("header_prefix", "ApiKey "),
                notes=payload.get("notes", ""),
                actor="dashboard-user",
            )
            if payload.get("secret_value"):
                entry = self.vault.verify_connection(payload["id"], actor="dashboard-user")
            self._send_json(entry)
            return

        if self.path == "/api/verify":
            cid = payload["id"]
            entry = self.vault.verify_connection(cid, actor="dashboard-user")
            self._send_json(entry)
            return

        if self.path == "/api/verify_all":
            cat = self.vault.load_catalog()
            for cid in list(cat.get("connections", {}).keys()):
                try:
                    self.vault.verify_connection(cid, timeout=6, actor="dashboard-user")
                except Exception:
                    pass
            self._send_json({"ok": True})
            return

        if self.path == "/api/delete":
            cid = payload["id"]
            ok = self.vault.delete_connection(cid, actor="dashboard-user")
            self._send_json({"ok": ok})
            return

        if self.path == "/api/lockdown":
            settings = self.vault.load_settings()
            settings["global_lockdown"] = bool(payload.get("global_lockdown", False))
            self.vault.save_settings(settings)
            self.vault.log_audit(
                "TOGGLE_LOCKDOWN",
                "GLOBAL",
                "LOCKDOWN_ON" if settings["global_lockdown"] else "LOCKDOWN_OFF",
                actor="dashboard-user",
            )
            self._send_json(settings)
            return

        if self.path == "/api/sanitize":
            dry = bool(payload.get("dry_run", True))
            res = self.vault.sanitize_chats(dry_run=dry, actor="dashboard-user")
            self._send_json(res)
            return

        if self.path == "/api/domain":
            dom = payload.get("domain", "irfhash.localhost")
            map_hosts = bool(payload.get("map_etc_hosts", False))
            res = self.vault.configure_custom_domain(dom, map_etc_hosts=map_hosts)
            self._send_json(res)
            return

        self._send_json({"error": "Unknown endpoint"}, 404)


def run_server(port: int = 8765):
    server = ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"irfHASH Security Control Center running on http://irfhash.localhost:{port} (127.0.0.1:{port})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    p = int(sys.argv[1]) if len(sys.argv) > 1 else 8765
    run_server(p)
