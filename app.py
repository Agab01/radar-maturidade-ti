from __future__ import annotations

import os
from datetime import datetime
from functools import wraps
from typing import Dict, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import (
    Flask,
    flash,
    g,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "fallback-inseguro-apenas-para-dev")

app.config["SESSION_COOKIE_SECURE"] = True     # Só envia o cookie via HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True   # Impede que scripts maliciosos (XSS) leiam o cookie
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Protege contra ataques CSRF leves

DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("ERRO CRÍTICO: A variável DATABASE_URL não foi encontrada. Verifique seu arquivo .env!")

SCORING = {
    0: "Não se aplica",
    1: "Inexistente",
    2: "Inicial",
    3: "Parcial",
    4: "Consistente",
    5: "Totalmente implementado",
}

CATEGORIES = [
    "Processos de TI",
    "Ferramentas de TI",
    "Nível de Serviço",
    "Alinhamento Estratégico",
    "Governança de TI",
    "Gestão de Riscos",
    "Cultura de TI",
]

ROLE_PERMISSIONS = {
    "admin": {"manage_users", "manage_companies", "manage_questions", "respond", "view_reports"},
    "analista": {"manage_companies", "manage_questions", "respond", "view_reports"},
    "avaliador": {"respond", "view_reports"},
    "leitor": {"view_reports"},
}

BASE_HTML = """
<!doctype html>
<html lang="pt-br">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title or 'RADAR.TI' }}</title>
  <link href="https://fonts.googleapis.com/css2?family=Archivo+Black&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #fdfdfc; 
      --fg: #1a1a1a; 
      --surface: #ffffff;
      
      --p-primary: #9d4edd; 
      --p-primary-dk: #7b2cbf;
      --p-accent: #ccff00; 
      --p-warn: #ffca3a; 
      --p-danger: #ff595e; 
      --p-success: #8ac926; 

      --border-thick: 3px solid var(--fg);
      --border-thin: 1px solid var(--fg);
      --shadow-raw: 5px 5px 0px var(--fg);
      --shadow-raw-sm: 3px 3px 0px var(--fg);
    }
    
    * { box-sizing: border-box; }
    
    body {
      margin: 0;
      font-family: 'Space Mono', monospace;
      color: var(--fg);
      background-color: var(--bg);
      background-image: 
        linear-gradient(#e5e5e5 1px, transparent 1px),
        linear-gradient(90deg, #e5e5e5 1px, transparent 1px);
      background-size: 30px 30px;
      padding: 20px;
    }

    h1, h2, h3, h4 {
      font-family: 'Archivo Black', sans-serif;
      text-transform: uppercase;
      margin: 0 0 15px 0;
      letter-spacing: -1px;
    }
    
    h1 { font-size: 42px; line-height: 0.9; }
    h2 { font-size: 28px; background: var(--fg); color: white; display: inline-block; padding: 5px 10px; }
    h3 { font-size: 20px; text-decoration: underline; }
    
    p { margin: 0 0 15px 0; font-size: 15px; }
    .muted { opacity: 0.7; }

    .app-wrap {
      max-width: 1000px;
      margin: 0 auto;
    }

    .main-header {
      border: var(--border-thick);
      background: var(--surface);
      padding: 20px;
      box-shadow: var(--shadow-raw);
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 30px;
    }
    .brand { display: flex; align-items: center; gap: 15px; }
    .brand-logo {
      width: 50px; height: 50px;
      background: var(--fg); color: var(--p-accent);
      display: grid; place-items: center;
      font-family: 'Archivo Black', sans-serif; font-size: 28px;
    }
    .user-info { text-align: right; }

    .main-nav {
      background: var(--surface);
      border: var(--border-thick);
      margin-bottom: 30px;
      padding: 5px;
      box-shadow: var(--shadow-raw);
      display: flex;
      justify-content: center;
      flex-wrap: wrap;
      gap: 5px;
    }
    .main-nav a {
      color: var(--fg);
      text-decoration: none;
      font-weight: 700;
      font-size: 14px;
      padding: 10px 15px;
      border: var(--border-thin);
      transition: all 0.15s;
    }
    .main-nav a:hover {
      background: var(--p-primary);
      color: white;
      transform: translate(-2px, -2px);
      box-shadow: var(--shadow-raw-sm);
    }
    .main-nav a.active {
      background: var(--fg);
      color: var(--p-accent);
    }

    .content {
      display: flex;
      flex-direction: column;
      gap: 30px;
    }

    .card {
      background: var(--surface);
      border: var(--border-thick);
      padding: 25px;
      box-shadow: var(--shadow-raw);
    }

    .table-wrap { overflow-x: auto; }
    table {
      width: 100%;
      border-collapse: collapse;
      border: var(--border-thick);
      margin-bottom: 15px;
    }
    th {
      background: var(--fg); color: white;
      text-transform: uppercase; font-size: 13px; font-weight: 700;
      padding: 12px; text-align: left;
    }
    td {
      padding: 12px;
      border-bottom: var(--border-thin);
      font-size: 14px;
      background: var(--surface);
      vertical-align: middle;
    }
    tr:last-child td { border-bottom: none; }
    tr:hover td { background: #f0f0f0; }

    .btn, button {
      font-family: 'Space Mono', monospace;
      text-transform: uppercase; font-weight: 700; font-size: 14px;
      padding: 12px 20px;
      background: var(--fg);
      color: white;
      border: var(--border-thin);
      cursor: pointer;
      display: inline-flex; align-items: center; gap: 8px;
      transition: all 0.1s;
      text-decoration: none;
    }
    .btn:hover, button:hover {
      transform: translate(-3px, -3px);
      box-shadow: var(--shadow-raw-sm);
      background: var(--p-primary);
    }
    .btn.accent { background: var(--p-accent); color: var(--fg); }
    .btn.accent:hover { background: #cfff33; }
    .btn.secondary { background: var(--bg); color: var(--fg); border: var(--border-thin); }
    .btn.secondary:hover { background: #e0e0e0; }

    .grid-form {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 15px;
    }
    .form-group { margin-bottom: 15px; }
    label {
      display: block; font-weight: 700; font-size: 14px;
      margin-bottom: 6px; text-transform: uppercase;
    }
    input, select, textarea {
      width: 100%;
      padding: 12px;
      border: var(--border-thick);
      background: var(--surface);
      font-family: inherit; font-size: 14px;
      color: var(--fg);
      outline: none;
    }
    input:focus, select:focus, textarea:focus {
      background: #f8f8f8;
      border-color: var(--p-primary);
    }
    textarea { min-height: 120px; resize: vertical; }

    .flash {
      border: var(--border-thick);
      padding: 15px;
      font-weight: 700;
      background: var(--p-accent); color: var(--fg);
      box-shadow: var(--shadow-raw);
      margin-bottom: 25px;
    }

    .pill {
      display: inline-block;
      padding: 4px 8px;
      font-weight: 700;
      font-size: 12px;
      text-transform: uppercase;
      border: var(--border-thin);
    }
    .p-artesanal { background: #ffcccc; color: #990000; }
    .p-eficiente { background: #ffeb99; color: #997300; }
    .p-eficaz { background: #cce0ff; color: #004099; }
    .p-estrategico { background: #ccffeb; color: #009966; }

    .stat-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 15px;
      margin-bottom: 30px;
    }
    .stat-card {
      border: var(--border-thick);
      background: var(--surface);
      padding: 20px;
      text-align: center;
      display: flex; flex-direction: column; justify-content: space-between;
    }
    .stat-card strong { text-transform: uppercase; font-size: 12px; color: var(--text-muted); }
    .score { font-family: 'Archivo Black', sans-serif; font-size: 48px; color: var(--fg); margin-top: 10px; }

    .bar {
      height: 20px;
      border: var(--border-thin);
      background: var(--bg);
      margin-top: 15px;
      position: relative;
    }
    .bar > span {
      display: block; height: 100%; background: var(--fg);
    }

    .actions-flex {
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }

    @media (max-width: 600px) {
      .main-header { flex-direction: column; text-align: center; gap: 10px; }
      .user-info { text-align: center; }
      h1 { font-size: 32px; }
      .grid-form { grid-template-columns: 1fr; }
    }
  </style>
  <script>
    window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
  </script>
  <script defer src="/_vercel/insights/script.js"></script>
</head>
<body>
<div class="app-wrap">
  {% if session.get('user_id') %}
  <header class="main-header">
    <div class="brand">
      <div class="brand-logo">R</div>
      <div>
        <div style="font-size:11px; text-transform:uppercase; color:var(--text-muted);">Radar_Governança</div>
        <h1 style="font-size:24px; margin:0;">Maturidade.TI</h1>
      </div>
    </div>
    <div class="user-info">
      <strong>{{ session.get('user_name') }}</strong><br>
      <span class="muted" style="font-size:12px;">Perfil: {{ session.get('role')|upper }}</span>
    </div>
  </header>

  <nav class="main-nav">
    <a href="{{ url_for('dashboard') }}" class="{% if request.endpoint == 'dashboard' %}active{% endif %}">DASHBOARD</a>
    <a href="{{ url_for('companies') }}" class="{% if request.endpoint in ['companies', 'edit_company'] %}active{% endif %}">EMPRESAS</a>
    <a href="{{ url_for('questions') }}" class="{% if request.endpoint in ['questions', 'edit_question'] %}active{% endif %}">QUESTÕES</a>
    <a href="{{ url_for('assessments') }}" class="{% if request.endpoint in ['assessments','new_assessment','view_assessment', 'answer_assessment'] %}active{% endif %}">AVALIAÇÕES</a>
    {% if has_perm('manage_users') %}
    <a href="{{ url_for('users') }}" class="{% if request.endpoint in ['users', 'edit_user'] %}active{% endif %}">ACESSOS</a>
    {% endif %}
    <a href="{{ url_for('logout') }}" style="background:var(--p-danger); color:white; border-color:var(--fg);">SAIR</a>
  </nav>
  {% endif %}

  <main class="content">
    {% with messages = get_flashed_messages() %}
      {% if messages %}
        {% for message in messages %}
          <div class="flash">{{ message }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    
    {{ content|safe }}
  </main>
</div>
</body>
</html>
"""

def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def query_db(query: str, args: Tuple = (), one: bool = False):
    with get_db().cursor() as cur:
        cur.execute(query, args)
        rows = cur.fetchall()
        return (rows[0] if rows else None) if one else rows

def execute_db(query: str, args: Tuple = ()):
    with get_db().cursor() as cur:
        cur.execute(query, args)
        if "RETURNING" in query.upper():
            return cur.fetchone()['id']
        return cur.rowcount

def init_db() -> None:
    db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    db.autocommit = True
    with db.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS companies (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                sector TEXT,
                size TEXT,
                contact_name TEXT,
                contact_email TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS questions (
                id SERIAL PRIMARY KEY,
                category TEXT NOT NULL,
                text TEXT NOT NULL,
                weight REAL NOT NULL DEFAULT 1,
                guidance TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS assessments (
                id SERIAL PRIMARY KEY,
                company_id INTEGER NOT NULL REFERENCES companies(id),
                title TEXT NOT NULL,
                evaluator_id INTEGER NOT NULL REFERENCES users(id),
                started_at TEXT NOT NULL,
                completed_at TEXT,
                overall_score REAL,
                maturity_level TEXT
            );
            CREATE TABLE IF NOT EXISTS responses (
                id SERIAL PRIMARY KEY,
                assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
                question_id INTEGER NOT NULL REFERENCES questions(id),
                score INTEGER NOT NULL,
                evidence TEXT,
                action_plan TEXT,
                note TEXT,
                created_at TEXT NOT NULL,
                UNIQUE(assessment_id, question_id)
            );
        """)

        cur.execute("SELECT id FROM users LIMIT 1")
        if not cur.fetchone():
            admin_email = os.environ.get("ADMIN_EMAIL")
            admin_pass = os.environ.get("ADMIN_PASSWORD")
            
            if admin_email and admin_pass:
                now = datetime.now().isoformat(timespec="seconds")
                cur.execute(
                    "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                    ("Administrador", admin_email, generate_password_hash(admin_pass), "admin", now),
                )
            
    db.close()

def require_login(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper

def has_perm(perm: str) -> bool:
    role = session.get("role")
    return perm in ROLE_PERMISSIONS.get(role, set())

@app.context_processor
def inject_helpers():
    return {"has_perm": has_perm, "scoring": SCORING}

def require_perm(perm: str):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not has_perm(perm):
                flash("Você não tem permissão para acessar esta área.")
                return redirect(url_for("dashboard"))
            return view(*args, **kwargs)
        return wrapper
    return decorator

def layout(content: str, **context):
    return render_template_string(BASE_HTML, content=content, **context)

def maturity_from_score(score: float) -> Tuple[str, str, str]:
    if score < 60:
        return ("Artesanal / Reativo", "p-artesanal", "Predomínio de ações reativas, pouca padronização, processos manuais e dependência de pessoas-chave.")
    if score < 80:
        return ("Eficiente / Proativo", "p-eficiente", "Processos básicos existem, há prevenção de problemas, padronização inicial e maior consciência operacional.")
    if score < 90:
        return ("Eficaz / Otimizado", "p-eficaz", "Processos otimizados, alinhamento com objetivos do negócio, monitoramento contínuo e governança consistente.")
    return ("Estratégico", "p-estrategico", "A TI atua como parceira estratégica, com alta automação, integração, resiliência e geração de valor para o negócio.")

def compute_assessment(assessment_id: int) -> Dict:
    rows = query_db(
        """
        SELECT q.category, q.weight, r.score, r.evidence, r.action_plan, q.text
        FROM responses r
        JOIN questions q ON q.id = r.question_id
        WHERE r.assessment_id = %s
        ORDER BY q.category, q.id
        """,
        (assessment_id,),
    )
    if not rows:
        return {"overall": 0.0, "level": maturity_from_score(0), "segments": {}, "rows": []}

    segments: Dict[str, Dict[str, float | int]] = {}
    total_weighted = 0.0
    max_weighted = 0.0
    for r in rows:
        cat = r["category"]
        segments.setdefault(cat, {"sum": 0.0, "max": 0.0, "count": 0})
        segments[cat]["sum"] += r["score"] * r["weight"]
        segments[cat]["max"] += 5 * r["weight"]
        segments[cat]["count"] += 1
        total_weighted += r["score"] * r["weight"]
        max_weighted += 5 * r["weight"]

    segment_scores = {}
    for cat, data in segments.items():
        pct = round((data["sum"] / data["max"]) * 100, 2) if data["max"] else 0.0
        segment_scores[cat] = {**data, "score": pct, "level": maturity_from_score(pct)}

    overall = round((total_weighted / max_weighted) * 100, 2) if max_weighted else 0.0
    return {
        "overall": overall,
        "level": maturity_from_score(overall),
        "segments": segment_scores,
        "rows": rows,
    }

# =========================================================
# ROTAS PRINCIPAIS
# =========================================================
@app.route("/")
def home():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        password = request.form["password"]
        user = query_db("SELECT * FROM users WHERE lower(email) = %s", (email,), one=True)

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))

        flash("Acesso Negado. Credenciais Incorretas.")

    return render_template_string(
        """
        <!doctype html>
        <html lang="pt-br">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>{{ title }}</title>
          <link href="https://fonts.googleapis.com/css2?family=Archivo+Black&family=Space+Mono:wght@400;700&display=swap" rel="stylesheet">
          <style>
            :root {
              --bg: #fdfdfc; --fg: #1a1a1a; --surface: #ffffff;
              --p-primary: #9d4edd; --p-accent: #ccff00;
              --border-thick: 3px solid var(--fg);
              --shadow-raw: 5px 5px 0px var(--fg);
              --shadow-raw-sm: 3px 3px 0px var(--fg);
            }
            * { box-sizing:border-box; }
            body {
              margin:0; font-family: 'Space Mono', monospace; color: var(--fg);
              background-color: var(--bg); display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px;
              background-image: linear-gradient(#e5e5e5 1px, transparent 1px), linear-gradient(90deg, #e5e5e5 1px, transparent 1px);
              background-size: 20px 20px;
            }
            .login-card {
              background: var(--surface); border: var(--border-thick); padding: 40px; box-shadow: var(--shadow-raw);
              width: 100%; max-width: 460px;
            }
            .login-header { text-align: center; margin-bottom: 30px; border-bottom: var(--border-thick); padding-bottom: 20px; }
            .logo-wrap { display: inline-flex; align-items: center; gap: 10px; margin-bottom: 10px; }
            .logo-icon {
              width: 50px; height: 50px; background: var(--fg); color: var(--p-accent);
              display: grid; place-items: center; font-family: 'Archivo Black', sans-serif; font-size: 28px;
            }
            h1 { font-family: 'Archivo Black', sans-serif; font-size: 26px; text-transform: uppercase; margin: 0; letter-spacing: -1px; line-height: 1; }
            
            .alert { background: #ff595e; color: white; padding: 10px; border: 1px solid var(--fg); font-weight: 700; font-size: 13px; margin-bottom: 20px; text-align: center; }

            .form-group { margin-bottom: 20px; }
            label { display: block; font-size: 14px; font-weight: 700; margin-bottom: 6px; text-transform: uppercase; }
            input {
              width: 100%; padding: 12px; border: var(--border-thick); background: var(--surface);
              font-family: inherit; font-size: 14px; color: var(--fg); outline: none;
            }
            input:focus { border-color: var(--p-primary); background: #f8f8f8; }
            
            button {
              width: 100%; padding: 12px; background: var(--p-primary); color: white; border: var(--border-thick);
              font-family: 'Space Mono', monospace; text-transform: uppercase; font-weight: 700; font-size: 15px; cursor: pointer;
              transition: all 0.1s; margin-top: 10px;
            }
            button:hover { transform: translate(-3px, -3px); box-shadow: var(--shadow-raw-sm); }
            
            .hint { text-align: center; margin-top: 25px; font-size: 12px; border-top: 1px solid #ccc; padding-top: 15px; color: #555;}
            .hint strong { color: var(--fg); }
          </style>
          <script>
            window.va = window.va || function () { (window.vaq = window.vaq || []).push(arguments); };
          </script>
          <script defer src="/_vercel/insights/script.js"></script>
        </head>
        <body>
          <div class="login-card">
            <div class="login-header">
              <div class="logo-wrap">
                <div class="logo-icon">R</div>
                <h1>RADAR.MATURIDADE_TI</h1>
              </div>
              <p class="muted">Acesso restrito. Identifique-se.</p>
            </div>

            {% with messages = get_flashed_messages() %}
              {% if messages %}
                {% for message in messages %}
                  <div class="alert">{{ message }}</div>
                {% endfor %}
              {% endif %}
            {% endwith %}

            <form method="post">
              <div class="form-group">
                <label>_ID_LOGIN (E-MAIL)</label>
                <input name="email" type="email" placeholder="..." required>
              </div>
              <div class="form-group">
                <label>_CHAVE_ACESSO (SENHA)</label>
                <input name="password" type="password" placeholder="••••••••" required>
              </div>
              <button type="submit">_AUTENTICAR</button>
            </form>
            
          </div>
        </body>
        </html>
        """,
        title="LOGIN / RADAR.TI",
    )

@app.route("/logout")
@require_login
def logout():
    session.clear()
    flash("Sessão finalizada com segurança.")
    return redirect(url_for("login"))

@app.route("/dashboard")
@require_login
def dashboard():
    totals = {
        "users": query_db("SELECT COUNT(*) c FROM users", one=True)["c"],
        "companies": query_db("SELECT COUNT(*) c FROM companies", one=True)["c"],
        "questions": query_db("SELECT COUNT(*) c FROM questions", one=True)["c"],
        "assessments": query_db("SELECT COUNT(*) c FROM assessments", one=True)["c"],
    }
    recent = query_db(
        """
        SELECT a.id, a.title, c.name company_name, a.overall_score, a.maturity_level, a.completed_at
        FROM assessments a JOIN companies c ON c.id = a.company_id
        ORDER BY a.id DESC LIMIT 5
        """
    )
    content = render_template_string(
        """
        <div class="stat-grid">
          <div class="stat-card"><strong>[ USUÁRIOS ]</strong><div class="score">{{ totals.users }}</div></div>
          <div class="stat-card"><strong>[ EMPRESAS ]</strong><div class="score">{{ totals.companies }}</div></div>
          <div class="stat-card"><strong>[ QUESTÕES ]</strong><div class="score">{{ totals.questions }}</div></div>
          <div class="stat-card"><strong>[ AVALIAÇÕES ]</strong><div class="score">{{ totals.assessments }}</div></div>
        </div>
        
        <div class="card">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
            <h2>Avaliações_Recentes</h2>
            <a class="btn accent" href="{{ url_for('new_assessment') }}">++ Nova</a>
          </div>
          <div class="table-wrap">
            <table>
              <tr><th>ID</th><th>Título_Diagnóstico</th><th>Empresa_Cliente</th><th>Score</th><th>Nível_Maturidade</th><th>Ações</th></tr>
              {% for r in recent %}
                <tr>
                  <td>#{{ r.id }}</td>
                  <td style="font-weight: 700;">{{ r.title }}</td>
                  <td>{{ r.company_name }}</td>
                  <td style="font-weight: 700;">{{ '%.1f'|format(r.overall_score or 0) }}%</td>
                  <td><span class="pill p-{{ (r.maturity_level|lower).split()[0] if r.maturity_level else 'default' }}">{{ r.maturity_level or 'PENDENTE' }}</span></td>
                  <td>
                    <div class="actions-flex">
                      <a class="btn secondary" href="{{ url_for('view_assessment', assessment_id=r.id) }}" style="padding: 6px 10px; font-size: 12px;">Relatório</a>
                      {% if has_perm('respond') %}
                      <form action="{{ url_for('delete_assessment', assessment_id=r.id) }}" method="POST" style="margin:0;" onsubmit="return confirm('ATENÇÃO! Deletar esta avaliação e TODAS as suas respostas de forma irreversível?');">
                        <button type="submit" class="btn" style="padding: 6px 10px; font-size:12px; background:var(--p-danger); color:white;">[X]</button>
                      </form>
                      {% endif %}
                    </div>
                  </td>
                </tr>
              {% else %}
                <tr><td colspan="6" style="text-align:center; padding: 30px;">[ Base de avaliações vazia ]</td></tr>
              {% endfor %}
            </table>
          </div>
        </div>
        """,
        totals=totals,
        recent=recent,
    )
    return layout(content, title="Dashboard_Principal")

# =========================================================
# ROTAS CRUD: USUÁRIOS
# =========================================================
@app.route("/users", methods=["GET", "POST"])
@require_login
@require_perm("manage_users")
def users():
    if request.method == "POST":
        execute_db(
            "INSERT INTO users (name, email, password_hash, role, created_at) VALUES (%s, %s, %s, %s, %s)",
            (
                request.form["name"],
                request.form["email"].strip().lower(),
                generate_password_hash(request.form["password"]),
                request.form["role"],
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        flash("Usuário Adicionado ao Banco.")
        return redirect(url_for("users"))
    rows = query_db("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC")
    content = render_template_string(
        """
        <div class="card">
          <h2>++ Novo_Acesso</h2>
          <form method="post" class="grid-form" style="margin-top:20px;">
            <div class="form-group"><label>Nome_Completo</label><input name="name" required></div>
            <div class="form-group"><label>E-mail_Login</label><input name="email" type="email" required></div>
            <div class="form-group"><label>Senha_Inicial</label><input name="password" type="password" required></div>
            <div class="form-group">
              <label>Perfil_Acesso</label>
              <select name="role">{% for role in roles %}<option value="{{ role }}">{{ role|upper }}</option>{% endfor %}</select>
            </div>
            <div style="grid-column: 1 / -1; text-align: right;">
              <button class="btn accent" type="submit">Salvar_Registro</button>
            </div>
          </form>
        </div>
        
        <div class="card">
          <h2>Acessos_Cadastrados</h2>
          <div class="table-wrap" style="margin-top:20px;">
            <table>
              <tr><th>Nome</th><th>E-mail</th><th>Perfil</th><th>Criado_Em</th><th>Ações</th></tr>
              {% for u in rows %}
                <tr>
                  <td style="font-weight: 700;">{{ u.name }}</td>
                  <td>{{ u.email }}</td>
                  <td><span class="pill" style="background:#333; color:white; border:none;">{{ u.role|upper }}</span></td>
                  <td style="font-size: 12px;">{{ u.created_at[:10] }}</td>
                  <td>
                    <div class="actions-flex">
                      <a href="{{ url_for('edit_user', user_id=u.id) }}" class="btn secondary" style="padding: 4px 8px; font-size:11px;">Editar</a>
                      <form action="{{ url_for('delete_user', user_id=u.id) }}" method="POST" style="margin:0;" onsubmit="return confirm('ATENÇÃO! Tem certeza que deseja DELETAR este usuário permanentemente?');">
                        <button type="submit" class="btn" style="padding: 4px 8px; font-size:11px; background:var(--p-danger); color:white;">[X]</button>
                      </form>
                    </div>
                  </td>
                </tr>
              {% endfor %}
            </table>
          </div>
        </div>
        """,
        rows=rows,
        roles=list(ROLE_PERMISSIONS.keys()),
    )
    return layout(content, title="Gestão_Usuários")

@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@require_login
@require_perm("manage_users")
def edit_user(user_id):
    user = query_db("SELECT * FROM users WHERE id = %s", (user_id,), one=True)
    if not user:
        flash("Usuário não encontrado.")
        return redirect(url_for("users"))
        
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"].strip().lower()
        role = request.form["role"]
        password = request.form["password"]

        if password:
            execute_db(
                "UPDATE users SET name=%s, email=%s, role=%s, password_hash=%s WHERE id=%s",
                (name, email, role, generate_password_hash(password), user_id)
            )
        else:
            execute_db(
                "UPDATE users SET name=%s, email=%s, role=%s WHERE id=%s",
                (name, email, role, user_id)
            )
        flash("Dados do usuário atualizados.")
        return redirect(url_for("users"))
        
    content = render_template_string(
        """
        <div class="card" style="max-width: 600px; margin: 0 auto;">
          <h2>:: Editar_Acesso</h2>
          <form method="post" class="grid-form" style="margin-top:20px;">
            <div class="form-group" style="grid-column: 1 / -1;"><label>Nome_Completo</label><input name="name" value="{{ user.name }}" required></div>
            <div class="form-group" style="grid-column: 1 / -1;"><label>E-mail_Login</label><input name="email" type="email" value="{{ user.email }}" required></div>
            <div class="form-group" style="grid-column: 1 / -1;">
              <label>Nova_Senha (deixe em branco para manter a atual)</label>
              <input name="password" type="password" placeholder="••••••••">
            </div>
            <div class="form-group" style="grid-column: 1 / -1;">
              <label>Perfil_Acesso</label>
              <select name="role">
                {% for role in roles %}
                  <option value="{{ role }}" {% if user.role == role %}selected{% endif %}>{{ role|upper }}</option>
                {% endfor %}
              </select>
            </div>
            <div style="grid-column: 1 / -1; display:flex; gap:10px; justify-content: flex-end; margin-top:10px;">
              <a href="{{ url_for('users') }}" class="btn secondary">Cancelar</a>
              <button class="btn accent" type="submit">Salvar_Alterações</button>
            </div>
          </form>
        </div>
        """,
        user=user,
        roles=list(ROLE_PERMISSIONS.keys())
    )
    return layout(content, title="Editar_Usuário")

@app.route("/users/<int:user_id>/delete", methods=["POST"])
@require_login
@require_perm("manage_users")
def delete_user(user_id):
    if user_id == session.get("user_id"):
        flash("ERRO: Operação negada. Você não pode deletar a sua própria conta ativa.")
        return redirect(url_for("users"))
    try:
        execute_db("DELETE FROM users WHERE id = %s", (user_id,))
        flash("Usuário deletado do sistema.")
    except psycopg2.IntegrityError:
        flash("ERRO: Não é possível deletar um usuário que já realizou avaliações. As avaliações dependem deste registro.")
    return redirect(url_for("users"))

# =========================================================
# ROTAS CRUD: EMPRESAS
# =========================================================
@app.route("/companies", methods=["GET", "POST"])
@require_login
def companies():
    if request.method == "POST":
        if not has_perm("manage_companies"):
            flash("Permissão Negada para Cadastro.")
            return redirect(url_for("companies"))
        execute_db(
            "INSERT INTO companies (name, sector, size, contact_name, contact_email, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
            (
                request.form["name"],
                request.form.get("sector"),
                request.form.get("size"),
                request.form.get("contact_name"),
                request.form.get("contact_email"),
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        flash("Empresa Cliente Registrada.")
        return redirect(url_for("companies"))
    rows = query_db("SELECT * FROM companies ORDER BY id DESC")
    content = render_template_string(
        """
        <div class="card">
          <h2>++ Nova_Empresa</h2>
          {% if has_perm('manage_companies') %}
          <form method="post" class="grid-form" style="margin-top:20px;">
            <div class="form-group"><label>Nome / Razão Social</label><input name="name" required></div>
            <div class="form-group"><label>Setor_Atuação</label><input name="sector"></div>
            <div class="form-group"><label>Porte_Empresa</label>
              <select name="size">
                <option value="Pequena">Pequena</option>
                <option value="Média">Média</option>
                <option value="Grande">Grande</option>
                <option value="Enterprise">Enterprise</option>
              </select>
            </div>
            <div class="form-group"><label>Nome_Contato</label><input name="contact_name"></div>
            <div class="form-group"><label>E-mail_Contato</label><input name="contact_email" type="email"></div>
            <div style="grid-column: 1 / -1; text-align: right;">
              <button class="btn accent" type="submit">Registrar</button>
            </div>
          </form>
          {% else %}
          <p class="flash" style="background:var(--p-warn); color:var(--fg);">Seu perfil não tem permissão de escrita.</p>
          {% endif %}
        </div>
        
        <div class="card">
          <h2>Diretório_Empresas</h2>
          <div class="table-wrap" style="margin-top:20px;">
            <table>
              <tr><th>Empresa</th><th>Setor</th><th>Porte</th><th>Contato Principal</th><th>Ações</th></tr>
              {% for c in rows %}
              <tr>
                <td style="font-weight: 700;">{{ c.name }}</td>
                <td>{{ c.sector or '-' }}</td>
                <td style="font-weight: 700;">{{ c.size or '-' }}</td>
                <td>
                  {% if c.contact_name %}
                    {{ c.contact_name }} / <span style="font-size:12px;">{{ c.contact_email }}</span>
                  {% else %}-{% endif %}
                </td>
                <td>
                  <div class="actions-flex">
                    <a class="btn" href="{{ url_for('new_assessment', company_id=c.id) }}" style="padding: 4px 8px; font-size: 11px; background:var(--p-accent); color:var(--fg);">Avaliar</a>
                    {% if has_perm('manage_companies') %}
                      <a href="{{ url_for('edit_company', company_id=c.id) }}" class="btn secondary" style="padding: 4px 8px; font-size:11px;">Editar</a>
                      <form action="{{ url_for('delete_company', company_id=c.id) }}" method="POST" style="margin:0;" onsubmit="return confirm('ATENÇÃO! Deletar esta empresa?');">
                        <button type="submit" class="btn" style="padding: 4px 8px; font-size:11px; background:var(--p-danger); color:white;">[X]</button>
                      </form>
                    {% endif %}
                  </div>
                </td>
              </tr>
              {% endfor %}
            </table>
          </div>
        </div>
        """,
        rows=rows,
    )
    return layout(content, title="Diretório_Empresas")

@app.route("/companies/<int:company_id>/edit", methods=["GET", "POST"])
@require_login
@require_perm("manage_companies")
def edit_company(company_id):
    company = query_db("SELECT * FROM companies WHERE id = %s", (company_id,), one=True)
    if not company:
        flash("Empresa não localizada.")
        return redirect(url_for("companies"))

    if request.method == "POST":
        execute_db(
            "UPDATE companies SET name=%s, sector=%s, size=%s, contact_name=%s, contact_email=%s WHERE id=%s",
            (
                request.form["name"],
                request.form.get("sector"),
                request.form.get("size"),
                request.form.get("contact_name"),
                request.form.get("contact_email"),
                company_id
            )
        )
        flash("Dados da empresa atualizados com sucesso.")
        return redirect(url_for("companies"))

    content = render_template_string(
        """
        <div class="card" style="max-width: 700px; margin: 0 auto;">
          <h2>:: Editar_Empresa</h2>
          <form method="post" class="grid-form" style="margin-top:20px;">
            <div class="form-group" style="grid-column: 1 / -1;"><label>Nome / Razão Social</label><input name="name" value="{{ company.name }}" required></div>
            <div class="form-group"><label>Setor_Atuação</label><input name="sector" value="{{ company.sector or '' }}"></div>
            <div class="form-group"><label>Porte_Empresa</label>
              <select name="size">
                {% for s in ['Pequena', 'Média', 'Grande', 'Enterprise'] %}
                  <option value="{{ s }}" {% if company.size == s %}selected{% endif %}>{{ s }}</option>
                {% endfor %}
              </select>
            </div>
            <div class="form-group"><label>Nome_Contato</label><input name="contact_name" value="{{ company.contact_name or '' }}"></div>
            <div class="form-group"><label>E-mail_Contato</label><input name="contact_email" type="email" value="{{ company.contact_email or '' }}"></div>
            <div style="grid-column: 1 / -1; display:flex; gap:10px; justify-content: flex-end; margin-top:10px;">
              <a href="{{ url_for('companies') }}" class="btn secondary">Cancelar</a>
              <button class="btn accent" type="submit">Salvar_Alterações</button>
            </div>
          </form>
        </div>
        """,
        company=company
    )
    return layout(content, title="Editar_Empresa")

@app.route("/companies/<int:company_id>/delete", methods=["POST"])
@require_login
@require_perm("manage_companies")
def delete_company(company_id):
    try:
        execute_db("DELETE FROM companies WHERE id = %s", (company_id,))
        flash("Empresa excluída do sistema.")
    except psycopg2.IntegrityError:
        flash("ERRO: Não é possível deletar esta empresa, pois existem relatórios de avaliação vinculados a ela.")
    return redirect(url_for("companies"))

# =========================================================
# ROTAS CRUD: QUESTÕES
# =========================================================
@app.route("/questions", methods=["GET", "POST"])
@require_login
def questions():
    if request.method == "POST":
        if not has_perm("manage_questions"):
            flash("Permissão Negada para FRAMEWORK.")
            return redirect(url_for("questions"))
        execute_db(
            "INSERT INTO questions (category, text, weight, guidance, created_at) VALUES (%s, %s, %s, %s, %s)",
            (
                request.form["category"],
                request.form["text"],
                float(request.form.get("weight", 1) or 1),
                request.form.get("guidance"),
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        flash("Quesito Adicionado ao Framework.")
        return redirect(url_for("questions"))
    rows = query_db("SELECT * FROM questions ORDER BY category, id")
    content = render_template_string(
        """
        <div class="card">
          <h2>++ Novo_Quesito_Framework</h2>
          {% if has_perm('manage_questions') %}
          <form method="post" class="grid-form" style="margin-top:20px;">
            <div class="form-group">
              <label>Domínio / Categoria</label>
              <select name="category">{% for c in categories %}<option value="{{ c }}">{{ c }}</option>{% endfor %}</select>
            </div>
            <div class="form-group">
              <label>Peso_Relevância (0.1 - 5.0)</label>
              <input name="weight" type="number" step="0.1" value="1.0">
            </div>
            <div class="form-group" style="grid-column: 1 / -1;">
              <label>Enunciado da Questão / Quesito</label>
              <textarea name="text" style="min-height: 70px;" required></textarea>
            </div>
            <div class="form-group" style="grid-column: 1 / -1;">
              <label>Guia de Avaliação (Instruções)</label>
              <textarea name="guidance" style="min-height: 50px;"></textarea>
            </div>
            <div style="grid-column: 1 / -1; text-align: right;">
              <button class="btn accent" type="submit">Gravar no Framework</button>
            </div>
          </form>
          {% else %}
          <p class="flash" style="background:var(--p-warn); color:var(--fg);">Acesso apenas para leitura.</p>
          {% endif %}
        </div>
        
        <div class="card">
          <h2>Framework_TI Atual</h2>
          <div class="table-wrap" style="margin-top:20px;">
            <table>
              <tr><th>Categoria</th><th>Peso</th><th>Quesito / Guia</th><th>Ações</th></tr>
              {% for q in rows %}
                <tr>
                  <td style="font-weight: 700; background:#f0f0f0; white-space:nowrap;">{{ q.category }}</td>
                  <td style="text-align:center; font-weight:700; font-size:16px;">{{ q.weight }}</td>
                  <td>
                    <div style="font-weight:700;">{{ q.text }}</div>
                    {% if q.guidance %}
                      <div style="font-size: 12px; border:var(--border-thin); background:var(--bg); padding: 5px; margin-top:5px;">INFO: {{ q.guidance }}</div>
                    {% endif %}
                  </td>
                  <td>
                    {% if has_perm('manage_questions') %}
                    <div class="actions-flex">
                      <a href="{{ url_for('edit_question', question_id=q.id) }}" class="btn secondary" style="padding: 4px 8px; font-size:11px;">Editar</a>
                      <form action="{{ url_for('delete_question', question_id=q.id) }}" method="POST" style="margin:0;" onsubmit="return confirm('ATENÇÃO! Deletar este quesito afetará cálculos futuros. Continuar?');">
                        <button type="submit" class="btn" style="padding: 4px 8px; font-size:11px; background:var(--p-danger); color:white;">[X]</button>
                      </form>
                    </div>
                    {% endif %}
                  </td>
                </tr>
              {% endfor %}
            </table>
          </div>
        </div>
        """,
        rows=rows,
        categories=CATEGORIES,
    )
    return layout(content, title="Base_Questões_Framework")

@app.route("/questions/<int:question_id>/edit", methods=["GET", "POST"])
@require_login
@require_perm("manage_questions")
def edit_question(question_id):
    question = query_db("SELECT * FROM questions WHERE id = %s", (question_id,), one=True)
    if not question:
        flash("Questão não encontrada.")
        return redirect(url_for("questions"))

    if request.method == "POST":
        execute_db(
            "UPDATE questions SET category=%s, text=%s, weight=%s, guidance=%s WHERE id=%s",
            (
                request.form["category"],
                request.form["text"],
                float(request.form.get("weight", 1) or 1),
                request.form.get("guidance"),
                question_id
            )
        )
        flash("Quesito atualizado no framework.")
        return redirect(url_for("questions"))

    content = render_template_string(
        """
        <div class="card" style="max-width: 800px; margin: 0 auto;">
          <h2>:: Editar_Quesito_Framework</h2>
          <form method="post" class="grid-form" style="margin-top:20px;">
            <div class="form-group">
              <label>Domínio / Categoria</label>
              <select name="category">
                {% for c in categories %}
                  <option value="{{ c }}" {% if question.category == c %}selected{% endif %}>{{ c }}</option>
                {% endfor %}
              </select>
            </div>
            <div class="form-group">
              <label>Peso_Relevância (0.1 - 5.0)</label>
              <input name="weight" type="number" step="0.1" value="{{ question.weight }}">
            </div>
            <div class="form-group" style="grid-column: 1 / -1;">
              <label>Enunciado da Questão / Quesito</label>
              <textarea name="text" style="min-height: 70px;" required>{{ question.text }}</textarea>
            </div>
            <div class="form-group" style="grid-column: 1 / -1;">
              <label>Guia de Avaliação (Instruções)</label>
              <textarea name="guidance" style="min-height: 50px;">{{ question.guidance or '' }}</textarea>
            </div>
            <div style="grid-column: 1 / -1; display:flex; gap:10px; justify-content: flex-end; margin-top:10px;">
              <a href="{{ url_for('questions') }}" class="btn secondary">Cancelar</a>
              <button class="btn accent" type="submit">Salvar_Quesito</button>
            </div>
          </form>
        </div>
        """,
        question=question,
        categories=CATEGORIES
    )
    return layout(content, title="Editar_Quesito")

@app.route("/questions/<int:question_id>/delete", methods=["POST"])
@require_login
@require_perm("manage_questions")
def delete_question(question_id):
    try:
        execute_db("DELETE FROM questions WHERE id = %s", (question_id,))
        flash("Quesito deletado do framework.")
    except psycopg2.IntegrityError:
        flash("ERRO: Quesito não pode ser deletado pois já foi respondido em avaliações existentes.")
    return redirect(url_for("questions"))

# =========================================================
# ROTAS CRUD: AVALIAÇÕES
# =========================================================
@app.route("/assessments")
@require_login
def assessments():
    rows = query_db(
        """
        SELECT a.*, c.name company_name, u.name evaluator_name
        FROM assessments a
        JOIN companies c ON c.id = a.company_id
        JOIN users u ON u.id = a.evaluator_id
        ORDER BY a.id DESC
        """
    )
    content = render_template_string(
        """
        <div class="card">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 20px;">
            <h2>Log_Avaliações</h2>
            {% if has_perm('respond') %}
            <a class="btn accent" href="{{ url_for('new_assessment') }}">++ Iniciar</a>
            {% endif %}
          </div>
          <div class="table-wrap">
            <table>
              <tr><th>Data_Ini</th><th>Título</th><th>Empresa</th><th>Score</th><th>Maturidade</th><th>Ações</th></tr>
              {% for a in rows %}
                <tr>
                  <td style="font-size: 12px;">{{ a.started_at[:10] }}</td>
                  <td style="font-weight: 700;">{{ a.title }}</td>
                  <td>{{ a.company_name }} <br><span style="font-size:11px; color:var(--text-muted);">Avaliador: {{ a.evaluator_name }}</span></td>
                  <td style="font-weight: 700; font-size:16px;">{{ '%.1f'|format(a.overall_score or 0) }}%</td>
                  <td><span class="pill p-{{ (a.maturity_level|lower).split()[0] if a.maturity_level else 'default' }}">{{ a.maturity_level or 'PENDENTE' }}</span></td>
                  <td>
                    <div class="actions-flex">
                      <a class="btn secondary" href="{{ url_for('view_assessment', assessment_id=a.id) }}" style="padding: 6px 10px; font-size: 12px;">Relatório</a>
                      {% if has_perm('respond') %}
                      <form action="{{ url_for('delete_assessment', assessment_id=a.id) }}" method="POST" style="margin:0;" onsubmit="return confirm('ATENÇÃO! Deletar esta avaliação e TODAS as suas respostas de forma irreversível?');">
                        <button type="submit" class="btn" style="padding: 6px 10px; font-size:12px; background:var(--p-danger); color:white;">[X]</button>
                      </form>
                      {% endif %}
                    </div>
                  </td>
                </tr>
              {% else %}
                <tr><td colspan="6" style="text-align:center; padding:30px;">[ Sem registros ]</td></tr>
              {% endfor %}
            </table>
          </div>
        </div>
        """,
        rows=rows,
    )
    return layout(content, title="Gestão_Avaliações")

@app.route("/assessments/<int:assessment_id>/delete", methods=["POST"])
@require_login
@require_perm("respond")
def delete_assessment(assessment_id):
    execute_db("DELETE FROM responses WHERE assessment_id = %s", (assessment_id,))
    execute_db("DELETE FROM assessments WHERE id = %s", (assessment_id,))
    flash("Avaliação e suas respostas foram excluídas do sistema.")
    return redirect(url_for("assessments"))

@app.route("/assessments/new", methods=["GET", "POST"])
@require_login
@require_perm("respond")
def new_assessment():
    companies = query_db("SELECT id, name FROM companies ORDER BY name")
    if request.method == "POST":
        assessment_id = execute_db(
            "INSERT INTO assessments (company_id, title, evaluator_id, started_at) VALUES (%s, %s, %s, %s) RETURNING id",
            (
                request.form["company_id"],
                request.form["title"],
                session["user_id"],
                datetime.now().isoformat(timespec="seconds"),
            )
        )
        return redirect(url_for("answer_assessment", assessment_id=assessment_id))
    pre_company = request.args.get("company_id", "")
    content = render_template_string(
        """
        <div class="card" style="max-width: 600px; margin: 0 auto;">
          <h2>:: Setup_Nova_Avaliação</h2>
          <form method="post" style="margin-top:20px;">
            <div class="form-group">
              <label>Selecione_Empresa</label>
              <select name="company_id" required>
                <option value="">...</option>
                {% for c in companies %}
                  <option value="{{ c.id }}" {% if pre_company|int == c.id %}selected{% endif %}>{{ c.name }}</option>
                {% endfor %}
              </select>
            </div>
            <div class="form-group">
              <label>Título_Diagnóstico</label>
              <input name="title" value="Diagnóstico de Maturidade de TI" required>
            </div>
            <div style="text-align: right; margin-top:20px;">
              <button class="btn accent" type="submit" style="width: 100%;">Abrir Questionário =></button>
            </div>
          </form>
        </div>
        """,
        companies=companies,
        pre_company=pre_company,
    )
    return layout(content, title="Nova_Avaliação")

@app.route("/assessments/<int:assessment_id>/answer", methods=["GET", "POST"])
@require_login
@require_perm("respond")
def answer_assessment(assessment_id: int):
    assessment = query_db("SELECT * FROM assessments WHERE id = %s", (assessment_id,), one=True)
    if not assessment:
        flash("Avaliação não localizada.")
        return redirect(url_for("assessments"))
    questions_rows = query_db("SELECT * FROM questions ORDER BY category, id")
    if request.method == "POST":
        for q in questions_rows:
            score = int(request.form.get(f"score_{q['id']}", 0))
            evidence = request.form.get(f"evidence_{q['id']}", "").strip()
            action_plan = request.form.get(f"action_{q['id']}", "").strip()
            note = request.form.get(f"note_{q['id']}", "").strip()
            execute_db(
                """
                INSERT INTO responses (assessment_id, question_id, score, evidence, action_plan, note, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT(assessment_id, question_id)
                DO UPDATE SET score=EXCLUDED.score, evidence=EXCLUDED.evidence, action_plan=EXCLUDED.action_plan, note=EXCLUDED.note
                """,
                (assessment_id, q["id"], score, evidence, action_plan, note, datetime.now().isoformat(timespec="seconds")),
            )
        result = compute_assessment(assessment_id)
        level_name, _, _ = result["level"]
        execute_db(
            "UPDATE assessments SET completed_at = %s, overall_score = %s, maturity_level = %s WHERE id = %s",
            (datetime.now().isoformat(timespec="seconds"), result["overall"], level_name, assessment_id),
        )
        flash("Respostas Gravadas. Relatório Consolidado.")
        return redirect(url_for("view_assessment", assessment_id=assessment_id))

    existing = {
        r["question_id"]: r
        for r in query_db("SELECT * FROM responses WHERE assessment_id = %s", (assessment_id,))
    }
    content = render_template_string(
        """
        <div class="card" style="margin-bottom: 20px; background:var(--fg); color:var(--p-accent);">
          <h1>#Questionário_Avaliação</h1>
          <p style="margin:0;">[ ID_AVALIAÇÃO: {{ assessment.id }} ] | Responda todos os quesitos abaixo.</p>
        </div>
        
        <form method="post">
          {% for q in questions %}
            <div class="card" style="margin-bottom:20px; border-color:var(--p-primary);">
              <div style="display:flex; justify-content:space-between; margin-bottom: 10px; border-bottom:var(--border-thin); padding-bottom:5px;">
                <span class="pill" style="background:var(--fg); color:white; border:none;">{{ q.category }}</span>
                <strong class="muted">QUESITO {{ loop.index }}</strong>
              </div>
              
              <h2 style="font-family:'Space Mono'; text-transform:none; background:none; color:var(--fg); padding:0; margin-bottom:10px;">{{ q.text }}</h2>
              {% if q.guidance %}
                <p style="font-size: 13px; background: var(--bg); padding: 10px; border: var(--border-thin);">ℹ️ <strong>GUIA:</strong> {{ q.guidance }}</p>
              {% endif %}
              
              <div class="grid-form" style="margin-top: 20px;">
                <div class="form-group">
                  <label>_NOTA (0 a 5)</label>
                  <select name="score_{{ q.id }}" style="background: white; border-width: 2px;">
                    {% for v, label in scoring.items() %}
                      <option value="{{ v }}" {% if existing.get(q.id) and existing[q.id]['score'] == v %}selected{% endif %}>{{ v }} - {{ label }}</option>
                    {% endfor %}
                  </select>
                </div>
                <div class="form-group">
                  <label>_EVIDÊNCIAS_ENCONTRADAS</label>
                  <textarea name="evidence_{{ q.id }}" placeholder="...">{{ existing.get(q.id)['evidence'] if existing.get(q.id) else '' }}</textarea>
                </div>
                <div class="form-group">
                  <label>_PLANO_DE_AÇÃO_RECOMENDADO</label>
                  <textarea name="action_{{ q.id }}" placeholder="...">{{ existing.get(q.id)['action_plan'] if existing.get(q.id) else '' }}</textarea>
                </div>
                <div class="form-group">
                  <label>_NOTAS_INTERNAS (OPCIONAL)</label>
                  <textarea name="note_{{ q.id }}" placeholder="...">{{ existing.get(q.id)['note'] if existing.get(q.id) else '' }}</textarea>
                </div>
              </div>
            </div>
          {% endfor %}
          
          <div style="position: sticky; bottom: 10px; z-index: 10; padding: 15px; background: var(--surface); border: var(--border-thick); box-shadow: var(--shadow-raw); text-align: right;">
            <button class="btn accent" type="submit" style="font-size: 16px; padding: 15px 30px;">[ FINALIZAR_E_GERAR_RELATÓRIO ]</button>
          </div>
        </form>
        """,
        assessment=assessment,
        questions=questions_rows,
        existing=existing,
    )
    return layout(content, title=f"Questionário: {assessment['title']}")

@app.route("/assessments/<int:assessment_id>")
@require_login
@require_perm("view_reports")
def view_assessment(assessment_id: int):
    assessment = query_db(
        """
        SELECT a.*, c.name company_name, c.sector, c.size, u.name evaluator_name
        FROM assessments a
        JOIN companies c ON c.id = a.company_id
        JOIN users u ON u.id = a.evaluator_id
        WHERE a.id = %s
        """,
        (assessment_id,),
        one=True,
    )
    if not assessment:
        flash("Relatório não localizado.")
        return redirect(url_for("assessments"))
    result = compute_assessment(assessment_id)
    level_name, level_class, explanation = result["level"]

    gaps = query_db(
        """
        SELECT q.category, q.text, r.score, r.action_plan, r.evidence
        FROM responses r JOIN questions q ON q.id = r.question_id
        WHERE r.assessment_id = %s AND r.score <= 2
        ORDER BY q.category, r.score ASC
        """,
        (assessment_id,),
    )
    strengths = query_db(
        """
        SELECT q.category, q.text, r.score, r.evidence
        FROM responses r JOIN questions q ON q.id = r.question_id
        WHERE r.assessment_id = %s AND r.score >= 4
        ORDER BY q.category, r.score DESC
        """,
        (assessment_id,),
    )

    content = render_template_string(
        """
        <div class="card" style="background:var(--fg); color:white;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start; flex-wrap:wrap; gap: 15px;">
            <div>
              <span class="pill" style="background:white; color:var(--fg); border:none; margin-bottom:10px;">RELATÓRIO_FINAL</span>
              <h1 style="color:var(--p-accent); font-size:38px;">{{ assessment.company_name }}</h1>
              <p style="margin: 5px 0 0 0; font-weight:700;">Setor: {{ assessment.sector or '?' }} | Porte: {{ assessment.size or '?' }}</p>
              <p class="muted" style="margin-top:5px; font-size:13px;">Avaliador: {{ assessment.evaluator_name }} | Encerrado: {{ assessment.completed_at[:10] if assessment.completed_at else 'PENDENTE' }}</p>
            </div>
            
            <div style="text-align: right; background:white; color:var(--fg); border:var(--border-thick); padding: 15px; box-shadow: 5px 5px 0 var(--p-accent);">
              <div style="font-size: 11px; text-transform: uppercase; font-weight: 700;">Score_Geral</div>
              <div class="score" style="font-size: 58px; margin: 0; line-height:1;">{{ '%.1f'|format(result.overall) }}<span style="font-size:28px;">%</span></div>
              <span class="pill {{ level_class }}" style="border-width:2px; margin-top:5px;">{{ level_name }}</span>
            </div>
          </div>
          
          <div style="margin-top: 25px; padding-top: 15px; border-top: 1px solid #444;">
            <p style="margin: 0; line-height: 1.6; font-weight:700;">{{ explanation }}</p>
            <div class="bar" style="border-color:#444;"><span style="width:{{ result.overall }}%; background:var(--p-accent);"></span></div>
          </div>
        </div>

        <div class="grid-form" style="align-items: start;">
          <div class="card">
            <h2>Pontuação_Dimensão</h2>
            <div class="table-wrap" style="margin-top:15px;">
              <table>
                <tr><th>Domínio_TI</th><th>Score</th><th>Leitura</th></tr>
                {% for cat, data in result.segments.items() %}
                  <tr>
                    <td style="font-weight: 700;">{{ cat }}</td>
                    <td style="color: var(--p-primary); font-weight: 700; font-size:16px;">{{ '%.1f'|format(data.score) }}%</td>
                    <td style="font-size: 13px;">{{ data.level[2] }}</td>
                  </tr>
                {% endfor %}
              </table>
            </div>
          </div>

          <div class="card">
            <h2>Legenda_Níveis</h2>
            <div style="display:flex; flex-direction:column; gap: 8px; margin-top:15px; font-size:13px;">
              <div style="padding: 8px; background: #ffcccc; border: var(--border-thin); color:#900;"><strong>[0-59%] Rreativo:</strong> Caótico, dependente de heróis.</div>
              <div style="padding: 8px; background: #ffeb99; border: var(--border-thin); color:#960;"><strong>[60-79%] Proativo:</strong> Processos básicos, prevenção.</div>
              <div style="padding: 8px; background: #cce0ff; border: var(--border-thin); color:#049;"><strong>[80-89%] Otimizado:</strong> Medido, alinhado ao negócio.</div>
              <div style="padding: 8px; background: #ccffeb; border: var(--border-thin); color:#064;"><strong>[90-100%] Estratégico:</strong> Inovador, gera valor.</div>
            </div>
          </div>
        </div>

        <div class="card" style="border-color:var(--p-danger);">
          <h2 style="background:var(--p-danger);">Gaps_Críticos / Plano_Ação</h2>
          <p class="muted" style="margin-top:5px;">Notas baixa (0, 1 ou 2) exigem atenção imediata.</p>
          <div class="table-wrap" style="margin-top:15px;">
            <table>
              <tr><th>Domínio</th><th>Quesito</th><th>Nota</th><th>Providência_Recomendada</th></tr>
              {% for g in gaps %}
                <tr>
                  <td style="font-size:12px; font-weight:700; background:#f8f8f8;">{{ g.category }}</td>
                  <td style="font-weight: 700;">{{ g.text }}</td>
                  <td style="color: var(--p-danger); font-weight: 700; font-size:18px; text-align:center;">{{ g.score }}</td>
                  <td>{{ g.action_plan or '[ Sem plano documentado ]' }}</td>
                </tr>
              {% else %}
                <tr><td colspan="4" style="text-align:center; padding: 20px;">[ Sem gaps críticos detectados ]</td></tr>
              {% endfor %}
            </table>
          </div>
        </div>

        <div class="card" style="border-color:var(--p-success);">
          <h2 style="background:var(--p-success);">Pontos_Fortes / Evidências</h2>
          <p class="muted" style="margin-top:5px;">Conformidade alta (nota 4 ou 5).</p>
          <div class="table-wrap" style="margin-top:15px;">
            <table>
              <tr><th>Domínio</th><th>Quesito</th><th>Nota</th><th>Evidência_Registrada</th></tr>
              {% for s in strengths %}
                <tr>
                  <td style="font-size:12px; font-weight:700; background:#f8f8f8;">{{ s.category }}</td>
                  <td style="font-weight: 700;">{{ s.text }}</td>
                  <td style="color: var(--p-success); font-weight: 700; font-size:18px; text-align:center;">{{ s.score }}</td>
                  <td>{{ s.evidence or '-' }}</td>
                </tr>
              {% else %}
                <tr><td colspan="4" style="text-align:center; padding: 20px;">[ Sem destaques positivos ]</td></tr>
              {% endfor %}
            </table>
          </div>
        </div>

        <div style="display: flex; gap: 15px; justify-content: flex-end; margin-bottom: 30px; border-top:var(--border-thick); padding-top:20px;">
          <a class="btn secondary" href="{{ url_for('answer_assessment', assessment_id=assessment.id) }}">revisar_respostas</a>
          <button class="btn" onclick="window.print()">[ imprimir_PDF ]</button>
        </div>
        """,
        assessment=assessment,
        result=result,
        level_name=level_name,
        level_class=level_class,
        explanation=explanation,
        strengths=strengths,
        gaps=gaps,
    )
    return layout(content, title=f"RELATÓRIO: {assessment['company_name']}")


if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", False), host="0.0.0.0", port=5000)