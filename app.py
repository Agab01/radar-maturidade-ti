from __future__ import annotations

import os
import secrets
import hashlib
import smtplib
import ssl
import io
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Tuple
from google import genai
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, flash, g, redirect, render_template, request, session, url_for, jsonify, send_file
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "fallback-inseguro-apenas-para-dev")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=1440)
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("ERRO CRÍTICO: DATABASE_URL não encontrada. Verifique seu arquivo .env!")

SCORING = {0: "Não se aplica", 1: "Inexistente", 2: "Inicial", 3: "Parcial", 4: "Consistente", 5: "Totalmente implementado"}
CATEGORIES = [
    "Governança Estratégica de TI", 
    "Gestão de Processos e Operações", 
    "Gestão de Projetos e Mudanças", 
    "Gestão de Serviços e Nível de Serviço", 
    "Segurança da Informação e Conformidade", 
    "Gestão de Riscos", 
    "Alinhamento Estratégico e Valor de TI", 
    "Cultura, Pessoas e Competências", 
    "Infraestrutura, Ferramentas e Automação"
]

CID_PILLARS = ["N/A", "Confidencialidade", "Integridade", "Disponibilidade"]
GOV_MGT_TYPES = ["Gestão (Execução/Operação)", "Governança (Avaliar/Direcionar/Monitorar)"]
FRAMEWORKS = ["N/A", "COBIT 5", "ITIL 4", "ISO/IEC 27000", "Múltiplos"]

ROLE_PERMISSIONS = {
    "admin": {"manage_users", "manage_companies", "manage_questions", "respond", "view_reports"},
    "analista": {"manage_companies", "manage_questions", "view_reports"},
    "avaliador": {"respond", "view_reports"},
    "leitor": {"manage_companies", "view_reports"},
}

# =========================================================
# BANCO DE DADOS
# =========================================================
def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None: db.close()

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
            CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS companies (id SERIAL PRIMARY KEY, name TEXT NOT NULL, sector TEXT, size TEXT, contact_name TEXT, contact_email TEXT, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS questions (id SERIAL PRIMARY KEY, category TEXT NOT NULL, text TEXT NOT NULL, weight REAL NOT NULL DEFAULT 1, guidance TEXT, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS assessments (id SERIAL PRIMARY KEY, company_id INTEGER NOT NULL REFERENCES companies(id), title TEXT NOT NULL, evaluator_id INTEGER NOT NULL REFERENCES users(id), started_at TEXT NOT NULL, completed_at TEXT, overall_score REAL, maturity_level TEXT);
            CREATE TABLE IF NOT EXISTS responses (id SERIAL PRIMARY KEY, assessment_id INTEGER NOT NULL REFERENCES assessments(id) ON DELETE CASCADE, question_id INTEGER NOT NULL REFERENCES questions(id), score INTEGER NOT NULL, evidence TEXT, action_plan TEXT, note TEXT, created_at TEXT NOT NULL, UNIQUE(assessment_id, question_id));
        """)
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT;")
        cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_expires_at TEXT;")
        cur.execute("ALTER TABLE questions ADD COLUMN IF NOT EXISTS cid_pillar TEXT DEFAULT 'N/A';")
        cur.execute("ALTER TABLE questions ADD COLUMN IF NOT EXISTS gov_or_mgt TEXT DEFAULT 'Gestão (Execução/Operação)';")
        cur.execute("ALTER TABLE questions ADD COLUMN IF NOT EXISTS framework_ref TEXT DEFAULT 'N/A';")
        cur.execute("ALTER TABLE responses ADD COLUMN IF NOT EXISTS risk_probability INTEGER DEFAULT 0;")
        cur.execute("ALTER TABLE responses ADD COLUMN IF NOT EXISTS risk_impact INTEGER DEFAULT 0;")
        cur.execute("ALTER TABLE responses ADD COLUMN IF NOT EXISTS action_responsible TEXT;")
        cur.execute("ALTER TABLE responses ADD COLUMN IF NOT EXISTS action_deadline TEXT;")
        cur.execute("ALTER TABLE responses ADD COLUMN IF NOT EXISTS action_priority TEXT;")
        cur.execute("ALTER TABLE responses ADD COLUMN IF NOT EXISTS action_status TEXT DEFAULT 'A Fazer';")
        cur.execute("SELECT id FROM users LIMIT 1")

        if not cur.fetchone():
            admin_email, admin_pass = os.environ.get("ADMIN_EMAIL"), os.environ.get("ADMIN_PASSWORD")
            if admin_email and admin_pass:
                now = datetime.now().isoformat(timespec="seconds")
                cur.execute("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                            ("Administrador", admin_email, generate_password_hash(admin_pass), "admin", now))
    db.close()

# =========================================================
# AUTENTICAÇÃO E LÓGICA CORE
# =========================================================
def require_login(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"): return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper

def has_perm(perm: str) -> bool:
    return perm in ROLE_PERMISSIONS.get(session.get("role"), set())

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

def enviar_link_recuperacao(destinatario: str, link_reset: str) -> bool:
    remetente = os.environ.get("SMTP_EMAIL")
    senha_smtp = os.environ.get("SMTP_PASSWORD")
    smtp_server = os.environ.get("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.environ.get("SMTP_PORT", 465))
    
    if not remetente or not senha_smtp:
        print("Aviso: Credenciais SMTP não configuradas.")
        return False

    msg = EmailMessage()
    msg['Subject'] = 'RADAR.TI - Redefinição de Senha'
    msg['From'] = f"RADAR.TI <{remetente}>"
    msg['To'] = destinatario
    
    conteudo_html = f"""
    <html>
    <body style="font-family: monospace; background-color: #fdfdfc; color: #1a1a1a; padding: 20px;">
        <div style="border: 3px solid #1a1a1a; padding: 30px; max-width: 500px; margin: 0 auto; box-shadow: 5px 5px 0px #1a1a1a;">
            <h2 style="background-color: #1a1a1a; color: #ccff00; display: inline-block; padding: 5px 10px;">RESET DE CHAVE</h2>
            <p>Uma solicitação de redefinição de senha foi feita para sua conta no RADAR.TI.</p>
            <p>Clique no botão abaixo para criar uma nova chave. Este link expirará em <strong>30 minutos</strong>.</p>
            <br>
            <a href="{link_reset}" style="display: inline-block; background: #9d4edd; color: white; padding: 15px 20px; text-decoration: none; font-weight: bold; border: 2px solid #1a1a1a; text-transform: uppercase;">REDEFINIR MINHA CHAVE</a>
            <br><br>
            <hr style="border: 1px solid #1a1a1a; margin: 20px 0;">
            <p style="font-size: 11px; color: #666;">Se você não solicitou isso, ignore este e-mail.</p>
        </div>
    </body>
    </html>
    """
    msg.set_content(f"Acesse o link para redefinir sua senha: {link_reset}")
    msg.add_alternative(conteudo_html, subtype='html')

    try:
        contexto = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_server, smtp_port, context=contexto) as server:
            server.login(remetente, senha_smtp)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Erro ao enviar e-mail (SMTP): {e}")
        return False

def maturity_from_score(score: float) -> Tuple[str, str, str]:
    if score < 60: return ("Artesanal / Reativo", "p-artesanal", "Predomínio de ações reativas, pouca padronização e processos manuais.")
    if score < 80: return ("Eficiente / Proativo", "p-eficiente", "Processos básicos existem, há prevenção de problemas e padronização inicial.")
    if score < 90: return ("Eficaz / Otimizado", "p-eficaz", "Processos otimizados, alinhamento com o negócio e governança consistente.")
    return ("Estratégico", "p-estrategico", "TI atua como parceira estratégica, com alta automação e geração de valor.")

def compute_assessment(assessment_id: int) -> Dict:
    rows = query_db("SELECT q.category, q.weight, r.score, r.evidence, r.action_plan, q.text FROM responses r JOIN questions q ON q.id = r.question_id WHERE r.assessment_id = %s ORDER BY q.category, q.id", (assessment_id,))
    if not rows: return {"overall": 0.0, "level": maturity_from_score(0), "segments": {}, "rows": []}
    segments: Dict[str, Dict[str, float | int]] = {}
    total_weighted, max_weighted = 0.0, 0.0
    for r in rows:
        cat = r["category"]
        segments.setdefault(cat, {"sum": 0.0, "max": 0.0, "count": 0})
        segments[cat]["sum"] += r["score"] * r["weight"]
        segments[cat]["max"] += 5 * r["weight"]
        segments[cat]["count"] += 1
        total_weighted += r["score"] * r["weight"]
        max_weighted += 5 * r["weight"]
    segment_scores = {cat: {**data, "score": round((data["sum"] / data["max"]) * 100, 2) if data["max"] else 0.0, "level": maturity_from_score(round((data["sum"] / data["max"]) * 100, 2) if data["max"] else 0.0)} for cat, data in segments.items()}
    overall = round((total_weighted / max_weighted) * 100, 2) if max_weighted else 0.0
    return {"overall": overall, "level": maturity_from_score(overall), "segments": segment_scores, "rows": rows}

# =========================================================
# ROTAS PÚBLICAS (LOGIN E RECUPERAÇÃO SEGURA)
# =========================================================
@app.route("/")
def home():
    if session.get("user_id"): return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, password = request.form["email"].strip().lower(), request.form["password"]
        user = query_db("SELECT * FROM users WHERE lower(email) = %s", (email,), one=True)
        if user and check_password_hash(user["password_hash"], password):
            session.permanent = True
            session["user_id"], session["user_name"], session["role"] = user["id"], user["name"], user["role"]
            return redirect(url_for("dashboard"))
    return render_template("login.html", is_login=True, title="LOGIN / RADAR.TI")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"].strip()
        email = request.form["email"].strip().lower()
        password = request.form["password"]

        if len(password) < 6 or len(password) > 30:
            flash("ERRO: A senha deve conter entre 6 e 30 caracteres.")
            return redirect(url_for("register"))
        
        if query_db("SELECT id FROM users WHERE email = %s", (email,), one=True):
            flash("ERRO: Este e-mail já possui um acesso cadastrado.")
            return redirect(url_for("register"))

        execute_db("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                   (name, email, generate_password_hash(password), "leitor", datetime.now().isoformat(timespec="seconds")))
        flash("ACESSO CRIADO! Autentique-se para continuar.")
        return redirect(url_for("login"))
    
    return render_template("register.html", is_login=True, title="CADASTRAR / RADAR.TI")

@app.route("/recover", methods=["GET", "POST"])
def recover():
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = query_db("SELECT * FROM users WHERE email = %s", (email,), one=True)

        if user:
            raw_token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            expires_at = (datetime.now() + timedelta(minutes=30)).isoformat(timespec="seconds")
            
            execute_db("UPDATE users SET reset_token_hash = %s, reset_token_expires_at = %s WHERE id = %s",
                       (token_hash, expires_at, user["id"]))
            
            link_reset = url_for("reset", _external=True, email=email, token=raw_token)
            if not enviar_link_recuperacao(email, link_reset):
                flash("ERRO: Falha na comunicação com o servidor de e-mail.")
                return redirect(url_for("recover"))

        flash("Se o e-mail constar em nossa base, um link de redefinição seguro foi enviado.")
        return redirect(url_for("login"))

    return render_template("recover.html", is_login=True, title="RECUPERAR / RADAR.TI")

@app.route("/reset", methods=["GET", "POST"])
def reset():
    email = request.args.get("email", "").strip().lower()
    token = request.args.get("token", "")

    if not email or not token:
        flash("Link de redefinição inválido ou incompleto.")
        return redirect(url_for("login"))

    if request.method == "POST":
        new_password = request.form.get("password")
        
        if len(new_password) < 6 or len(new_password) > 30:
            flash("ERRO: A nova senha deve conter entre 6 e 30 caracteres.")
            return redirect(url_for("reset", email=email, token=token))

        user = query_db("SELECT * FROM users WHERE email = %s", (email,), one=True)

        if user and user.get("reset_token_hash") and user.get("reset_token_expires_at"):
            if datetime.now().isoformat() > user["reset_token_expires_at"]:
                flash("Este link de redefinição já expirou. Solicite um novo.")
                return redirect(url_for("recover"))

            token_hash = hashlib.sha256(token.encode()).hexdigest()
            if secrets.compare_digest(token_hash, user["reset_token_hash"]):

                execute_db(
                    "UPDATE users SET password_hash = %s, reset_token_hash = NULL, reset_token_expires_at = NULL WHERE id = %s",
                    (generate_password_hash(new_password), user["id"])
                )
                flash("Sua chave de acesso foi redefinida com sucesso! Faça o login.")
                return redirect(url_for("login"))

        flash("Link de redefinição inválido ou já utilizado.")
        return redirect(url_for("recover"))

    return render_template("reset.html", email=email, token=token, is_login=True, title="NOVA SENHA / RADAR.TI")

@app.route("/logout")
@require_login
def logout():
    session.clear()
    flash("Sessão finalizada com segurança.")
    return redirect(url_for("login"))

# =========================================================
# ROTAS PRIVADAS (SISTEMA)
# =========================================================
@app.route("/change-password", methods=["GET", "POST"])
@require_login
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        if len(new_password) < 6 or len(new_password) > 30:
            flash("ERRO: A nova senha deve conter entre 6 e 30 caracteres.")
            return redirect(url_for("change_password"))

        if new_password == current_password:
            flash("ERRO: A nova senha deve ser diferente da atual.")
            return redirect(url_for("change_password"))

        if new_password != confirm_password:
            flash("ERRO: As novas senhas não coincidem.")
            return redirect(url_for("change_password"))

        user_id = session.get("user_id")
        user = query_db("SELECT password_hash FROM users WHERE id = %s", (user_id,), one=True)

        if not check_password_hash(user["password_hash"], current_password):
            flash("ERRO: A chave atual informada está incorreta.")
            return redirect(url_for("change_password"))

        execute_db(
            "UPDATE users SET password_hash = %s WHERE id = %s",
            (generate_password_hash(new_password), user_id)
        )
        
        flash("CHAVE ATUALIZADA COM SUCESSO! Sua nova senha já está ativa.")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html", title="Alterar Senha / RADAR.TI")

@app.route("/dashboard")
@require_login
def dashboard():
    u_id = session.get("user_id")
    role = session.get("role")

    if role in ["admin", "analista"]:
        totals = {
            "users": query_db("SELECT COUNT(*) c FROM users", one=True)["c"],
            "companies": query_db("SELECT COUNT(*) c FROM companies", one=True)["c"],
            "questions": query_db("SELECT COUNT(*) c FROM questions", one=True)["c"],
            "assessments": query_db("SELECT COUNT(*) c FROM assessments", one=True)["c"],
        }
        recent = query_db("SELECT a.id, a.title, c.name company_name, a.overall_score, a.maturity_level, a.completed_at FROM assessments a JOIN companies c ON c.id = a.company_id ORDER BY a.id DESC LIMIT 5")
        
    elif role == "avaliador":
        totals = {
            "users": 1, 
            "companies": query_db("SELECT COUNT(*) c FROM companies", one=True)["c"],
            "questions": query_db("SELECT COUNT(*) c FROM questions", one=True)["c"],
            "assessments": query_db("SELECT COUNT(*) c FROM assessments WHERE evaluator_id = %s", (u_id,), one=True)["c"],
        }
        recent = query_db("""
            SELECT a.id, a.title, c.name company_name, a.overall_score, a.maturity_level, a.completed_at 
            FROM assessments a JOIN companies c ON c.id = a.company_id 
            WHERE a.evaluator_id = %s ORDER BY a.id DESC LIMIT 5
        """, (u_id,))
        
    else: 
        totals = {
            "users": 1,
            "companies": query_db("SELECT COUNT(*) c FROM companies WHERE client_id = %s", (u_id,), one=True)["c"],
            "questions": 0,
            "assessments": query_db("SELECT COUNT(a.*) c FROM assessments a JOIN companies c ON c.id = a.company_id WHERE c.client_id = %s", (u_id,), one=True)["c"],
        }
        recent = query_db("""
            SELECT a.id, a.title, c.name company_name, a.overall_score, a.maturity_level, a.completed_at 
            FROM assessments a JOIN companies c ON c.id = a.company_id 
            WHERE c.client_id = %s ORDER BY a.id DESC LIMIT 5
        """, (u_id,))

    return render_template("dashboard.html", totals=totals, recent=recent, title="Dashboard_Principal")

@app.route("/users", methods=["GET", "POST"])
@require_login
@require_perm("manage_users")
def users():
    if request.method == "POST":
        execute_db("INSERT INTO users (name, email, password_hash, role, created_at) VALUES (%s, %s, %s, %s, %s)",
                   (request.form["name"], request.form["email"].strip().lower(), generate_password_hash(request.form["password"]), request.form["role"], datetime.now().isoformat(timespec="seconds")))
        flash("Usuário Adicionado ao Banco.")
        return redirect(url_for("users"))
    rows = query_db("SELECT id, name, email, role, created_at FROM users ORDER BY id DESC")
    return render_template("users.html", rows=rows, roles=list(ROLE_PERMISSIONS.keys()), title="Gestão_Usuários")

@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@require_login
@require_perm("manage_users")
def edit_user(user_id):
    user = query_db("SELECT * FROM users WHERE id = %s", (user_id,), one=True)
    if not user:
        flash("Usuário não encontrado.")
        return redirect(url_for("users"))
    if request.method == "POST":
        name, email, role, password = request.form["name"], request.form["email"].strip().lower(), request.form["role"], request.form["password"]
        if password: execute_db("UPDATE users SET name=%s, email=%s, role=%s, password_hash=%s WHERE id=%s", (name, email, role, generate_password_hash(password), user_id))
        else: execute_db("UPDATE users SET name=%s, email=%s, role=%s WHERE id=%s", (name, email, role, user_id))
        flash("Dados do usuário atualizados.")
        return redirect(url_for("users"))
    return render_template("edit_user.html", user=user, roles=list(ROLE_PERMISSIONS.keys()), title="Editar_Usuário")

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
        flash("ERRO: Não é possível deletar um usuário que já realizou avaliações.")
    return redirect(url_for("users"))

@app.route("/companies", methods=["GET", "POST"])
@require_login
def companies():
    u_id = session.get("user_id")
    role = session.get("role")

    if request.method == "POST":
        if not has_perm("manage_companies"):
            flash("Permissão Negada.")
            return redirect(url_for("companies")) 
        name = request.form["name"].strip()
        existing = query_db("SELECT id FROM companies WHERE lower(name) = %s AND client_id = %s", (name.lower(), u_id), one=True)
        if existing:
            flash(f"A empresa '{name}' já está na sua conta.")
            return redirect(url_for("companies"))
        execute_db("""
            INSERT INTO companies (name, sector, size, contact_name, contact_email, created_at, client_id, avaliador_id) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, NULL)
        """, (name, request.form.get("sector"), request.form.get("size"), 
              request.form.get("contact_name"), request.form.get("contact_email"), 
              datetime.now().isoformat(timespec="seconds"), u_id))
        flash("Empresa cadastrada. Aguarde a designação de um avaliador.")
        return redirect(url_for("companies"))

    if role in ["admin", "analista", "avaliador"]:
        rows = query_db("SELECT * FROM companies ORDER BY id DESC")
    else:
        rows = query_db("SELECT * FROM companies WHERE client_id = %s ORDER BY id DESC", (u_id,))
    
    return render_template("companies.html", rows=rows, title="Minhas_Empresas")

@app.route("/companies/<int:company_id>/edit", methods=["GET", "POST"])
@require_login
@require_perm("manage_companies")
def edit_company(company_id):
    company = query_db("SELECT * FROM companies WHERE id = %s", (company_id,), one=True)
    if not company:
        flash("Empresa não localizada.")
        return redirect(url_for("companies"))
    
    if session.get("role") != "admin" and company.get("avaliador_id") != session.get("user_id"):
        flash("ACESSO NEGADO: Esta empresa pertence à carteira de outro avaliador.")
        return redirect(url_for("companies"))

    if request.method == "POST":
        execute_db("UPDATE companies SET name=%s, sector=%s, size=%s, contact_name=%s, contact_email=%s WHERE id=%s",
                   (request.form["name"], request.form.get("sector"), request.form.get("size"), request.form.get("contact_name"), request.form.get("contact_email"), company_id))
        flash("Dados da empresa atualizados.")
        return redirect(url_for("companies"))
    return render_template("edit_company.html", company=company, title="Editar_Empresa")

@app.route("/companies/<int:company_id>/delete", methods=["POST"])
@require_login
@require_perm("manage_companies")
def delete_company(company_id):
    try:
        execute_db("DELETE FROM companies WHERE id = %s", (company_id,))
        flash("Empresa excluída do sistema.")
    except psycopg2.IntegrityError:
        flash("ERRO: Não é possível deletar empresa com relatórios vinculados.")
    return redirect(url_for("companies"))

@app.route("/questions", methods=["GET", "POST"])
@require_login
def questions():
    if request.method == "POST":
        if not has_perm("manage_questions"):
            flash("Permissão Negada.")
            return redirect(url_for("questions"))
        
        execute_db("""
            INSERT INTO questions (module, category, text, weight, guidance, created_at, cid_pillar, gov_or_mgt, framework_ref) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            request.form.get("module", "Maturidade"),
            request.form["category"], 
            request.form["text"], 
            float(request.form.get("weight", 1) or 1), 
            request.form.get("guidance"), 
            datetime.now().isoformat(timespec="seconds"),
            request.form.get("cid_pillar", "N/A"),
            request.form.get("gov_or_mgt", "Gestão (Execução/Operação)"),
            request.form.get("framework_ref", "N/A")
        ))
        
        flash("Quesito Adicionado com as Novas Dimensões.")
        return redirect(url_for("questions"))
      
    rows = query_db("SELECT * FROM questions ORDER BY module DESC, category, id")
    
    return render_template(
        "questions.html", 
        rows=rows, 
        categories=CATEGORIES, 
        cid_pillars=CID_PILLARS, 
        gov_mgt_types=GOV_MGT_TYPES, 
        frameworks=FRAMEWORKS, 
        title="Base_Questões"
    )

@app.route("/questions/<int:question_id>/edit", methods=["GET", "POST"])
@require_login
@require_perm("manage_questions")
def edit_question(question_id):
    question = query_db("SELECT * FROM questions WHERE id = %s", (question_id,), one=True)
    if not question:
        flash("Questão não encontrada.")
        return redirect(url_for("questions"))
        
    if request.method == "POST":
        execute_db("""
            UPDATE questions 
            SET module=%s, category=%s, text=%s, weight=%s, guidance=%s, 
                cid_pillar=%s, gov_or_mgt=%s, framework_ref=%s 
            WHERE id=%s
        """, (
            request.form.get("module", "Maturidade"),
            request.form["category"], 
            request.form["text"], 
            float(request.form.get("weight", 1) or 1), 
            request.form.get("guidance"),
            request.form.get("cid_pillar", "N/A"),
            request.form.get("gov_or_mgt", "Gestão (Execução/Operação)"),
            request.form.get("framework_ref", "N/A"),
            question_id
        ))
        flash("Quesito atualizado com as novas dimensões.")
        return redirect(url_for("questions"))
        
    return render_template(
        "edit_question.html", 
        question=question, 
        categories=CATEGORIES,
        cid_pillars=CID_PILLARS, 
        gov_mgt_types=GOV_MGT_TYPES, 
        frameworks=FRAMEWORKS,
        title="Editar_Quesito"
    )

@app.route("/questions/<int:question_id>/delete", methods=["POST"])
@require_login
@require_perm("manage_questions")
def delete_question(question_id):
    try:
        execute_db("DELETE FROM questions WHERE id = %s", (question_id,))
        flash("Quesito deletado.")
    except psycopg2.IntegrityError:
        flash("ERRO: Quesito não pode ser deletado pois já foi respondido.")
    return redirect(url_for("questions"))

@app.route("/assessments")
@require_login
def assessments():
    u_id = session.get("user_id")
    role = session.get("role")
    
    if role in ["admin", "analista"]:
        rows = query_db("""SELECT a.*, c.name company_name, u.name evaluator_name FROM assessments a JOIN companies c ON c.id = a.company_id JOIN users u ON u.id = a.evaluator_id ORDER BY a.id DESC""")
    elif role == "avaliador":
        rows = query_db("""SELECT a.*, c.name company_name, u.name evaluator_name FROM assessments a JOIN companies c ON c.id = a.company_id JOIN users u ON u.id = a.evaluator_id WHERE a.evaluator_id = %s ORDER BY a.id DESC""", (u_id,))
    else: 
        rows = query_db("""SELECT a.*, c.name company_name, u.name evaluator_name FROM assessments a JOIN companies c ON c.id = a.company_id JOIN users u ON u.id = a.evaluator_id WHERE c.client_id = %s ORDER BY a.id DESC""", (u_id,))
        
    return render_template("assessments.html", rows=rows, title="Relatórios")

@app.route("/assessments/<int:assessment_id>/delete", methods=["POST"])
@require_login
@require_perm("respond")
def delete_assessment(assessment_id):
    execute_db("DELETE FROM responses WHERE assessment_id = %s", (assessment_id,))
    execute_db("DELETE FROM assessments WHERE id = %s", (assessment_id,))
    flash("Avaliação excluída.")
    return redirect(url_for("assessments"))

@app.route("/assessments/new", methods=["GET", "POST"])
@require_login
@require_perm("respond")
def new_assessment():
    companies_list = query_db("SELECT id, name FROM companies ORDER BY name")
    
    if request.method == "POST":
        company_id = request.form.get("company_id")
        title = request.form.get("title")
        module_type = request.form.get("module", "Maturidade") 
        
        if not company_id:
            flash("Selecione uma empresa válida.")
            return redirect(url_for("new_assessment"))
            
        assessment_id = execute_db("""
            INSERT INTO assessments (company_id, title, evaluator_id, started_at, module) 
            VALUES (%s, %s, %s, %s, %s) RETURNING id
        """, (company_id, title, session["user_id"], datetime.now().isoformat(timespec="seconds"), module_type))
        
        return redirect(url_for("answer_assessment", assessment_id=assessment_id))
        
    pre_company = request.args.get("company_id", 0) 
    return render_template("new_assessment.html", companies=companies_list, title="Iniciar_Avaliação", pre_company=pre_company)

@app.route("/assessments/<int:assessment_id>/answer", methods=["GET", "POST"])
@require_login
@require_perm("respond")
def answer_assessment(assessment_id: int):
    assessment = query_db("SELECT * FROM assessments WHERE id = %s", (assessment_id,), one=True)
    if not assessment:
        flash("Avaliação não localizada.")
        return redirect(url_for("assessments"))
        
    questions_rows = query_db(
        "SELECT * FROM questions WHERE module = %s ORDER BY category, id", 
        (assessment.get('module', 'Maturidade'),)
    )
    
    if request.method == "POST":
        for q in questions_rows:
            qid = q['id']
            score = int(request.form.get(f"score_{qid}", 0))
            evidence = request.form.get(f"evidence_{qid}", "").strip()
            note = request.form.get(f"note_{qid}", "").strip()
 
            risk_prob = int(request.form.get(f"risk_prob_{qid}", 0))
            risk_impact = int(request.form.get(f"risk_impact_{qid}", 0))
            
            action_plan = request.form.get(f"action_{qid}", "").strip() # 1. What
            action_why = request.form.get(f"action_why_{qid}", "").strip() # 2. Why
            action_where = request.form.get(f"action_where_{qid}", "").strip() # 3. Where
            action_deadline = request.form.get(f"action_deadline_{qid}", "").strip() # 4. When
            action_resp = request.form.get(f"action_resp_{qid}", "").strip() # 5. Who
            action_how = request.form.get(f"action_how_{qid}", "").strip() # 6. How
            action_cost = request.form.get(f"action_cost_{qid}", "").strip() # 7. How Much
            
            action_priority = request.form.get(f"action_priority_{qid}", "").strip()
            action_status = request.form.get(f"action_status_{qid}", "A Fazer").strip()

            execute_db("""
                INSERT INTO responses (
                    assessment_id, question_id, score, evidence, action_plan, note, created_at,
                    risk_probability, risk_impact, action_responsible, action_deadline, action_priority, action_status,
                    action_why, action_where, action_how, action_cost
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
                ON CONFLICT(assessment_id, question_id) DO UPDATE SET 
                    score=EXCLUDED.score, evidence=EXCLUDED.evidence, action_plan=EXCLUDED.action_plan, note=EXCLUDED.note,
                    risk_probability=EXCLUDED.risk_probability, risk_impact=EXCLUDED.risk_impact, action_responsible=EXCLUDED.action_responsible,
                    action_deadline=EXCLUDED.action_deadline, action_priority=EXCLUDED.action_priority, action_status=EXCLUDED.action_status,
                    action_why=EXCLUDED.action_why, action_where=EXCLUDED.action_where, action_how=EXCLUDED.action_how, action_cost=EXCLUDED.action_cost
                """,
                (assessment_id, qid, score, evidence, action_plan, note, datetime.now().isoformat(timespec="seconds"),
                 risk_prob, risk_impact, action_resp, action_deadline, action_priority, action_status,
                 action_why, action_where, action_how, action_cost)
            )
            
        result = compute_assessment(assessment_id)
        execute_db("""
            UPDATE assessments SET completed_at = %s, overall_score = %s, maturity_level = %s WHERE id = %s
        """, (datetime.now().isoformat(timespec="seconds"), result["overall"], result["level"][0], assessment_id))
        
        flash("Respostas Gravadas. Relatório Consolidado.")
        return redirect(url_for("view_assessment", assessment_id=assessment_id))
        
    existing = {r["question_id"]: r for r in query_db("SELECT * FROM responses WHERE assessment_id = %s", (assessment_id,))}
    return render_template("answer_assessment.html", assessment=assessment, questions=questions_rows, existing=existing, title=f"Questionário: {assessment['title']}")


client = genai.Client()

@app.route("/assessments/<int:assessment_id>/generate-pdti", methods=["POST"])
@require_login
def generate_pdti(assessment_id):
    from google import genai
    client = genai.Client()
    
    # 1. Buscar os dados da avaliação e da empresa
    assessment = query_db("SELECT a.*, c.name as company_name FROM assessments a JOIN companies c ON a.company_id = c.id WHERE a.id = %s", (assessment_id,), one=True)
    
    responses = query_db("""
        SELECT q.text as question, q.category, r.score, r.action_plan, r.action_why, r.action_deadline, r.action_cost, r.action_responsible 
        FROM responses r 
        JOIN questions q ON r.question_id = q.id 
        WHERE r.assessment_id = %s
    """, (assessment_id,))
    
    # 2. Puxa o nome do avaliador (com trava de segurança)
    nome_avaliador = session.get("user_name")
    if not nome_avaliador or nome_avaliador.strip() == "":
        nome_avaliador = "Consultoria Radar.TI" # Nome de fallback caso a sessão falhe
    
    # 3. Montar o Contexto
    contexto_dados = f"Empresa: {assessment['company_name']}\nScore Geral Atual: {assessment.get('overall_score', 0)}%\n\nDETALHES DO DIAGNÓSTICO:\n"
    for r in responses:
        responsavel = r.get('action_responsible') or 'A definir'
        contexto_dados += f"- Domínio: {r['category']} | Quesito: {r['question']}\n"
        contexto_dados += f"  Nota: {r['score']}/5\n"
        if r['action_plan']:
            contexto_dados += f"  Ação Planejada: {r['action_plan']} | Por que: {r['action_why']} | Prazo: {r['action_deadline']} | Custo: {r['action_cost']} | Responsável: {responsavel}\n"
        contexto_dados += "\n"


    periodo_pdti = "2026-2028"

    # 4. O Prompt de Sistema (A estrutura do 1º com o conteúdo do 2º)
    instrucoes = f"""
Você é um Consultor Sênior de Governança de TI, especializado em PDTI, COBIT, ITIL, Segurança da Informação, Gestão de Riscos e Alinhamento Estratégico entre TI e negócio.

Sua tarefa é ler os dados do diagnóstico de TI e o plano de ação fornecido pela aplicação, e redigir um PDTI — Plano Diretor de Tecnologia da Informação — em formato executivo, formal, claro e profissional.

O período oficial deste PDTI é: {periodo_pdti}.
Todas as análises, cronogramas e conclusões devem respeitar esse período.

O PDTI deve parecer um documento final de consultoria, pronto para apresentação à diretoria.

REGRAS GERAIS:
- Formate toda a resposta em Markdown.
- Seja formal, objetivo e direto.
- Não invente dados numéricos que não foram fornecidos.
- Não invente custos, responsáveis, prazos, scores ou percentuais.
- Quando algum dado não estiver disponível, escreva "Não informado".
- Pode organizar, reescrever, resumir e melhorar a apresentação dos dados fornecidos.
- Pode classificar prioridades como Alta, Média ou Baixa com base na criticidade dos riscos e impacto no negócio.
- Não crie ações novas fora do plano de ação fornecido, a menos que sejam recomendações gerais sem custo, prazo ou responsável inventado.
- Corrija inconsistências evidentes de escrita, padronização e organização.
- Caso existam datas muito antigas ou incompatíveis com o período do PDTI, sinalize ou reorganize de forma coerente, sem criar datas aleatórias.
- Use linguagem consultiva, como se o documento fosse entregue para CEO, CFO, Gerente de TI e demais lideranças.

ESTRUTURA OBRIGATÓRIA DO DOCUMENTO:

# Plano Diretor de Tecnologia da Informação — PDTI
Informe:
- Empresa;
- Período do PDTI: {periodo_pdti};
- Score atual de maturidade de TI, se fornecido.

## 1. Resumo Executivo
Explique de forma clara:
- O objetivo do PDTI;
- O cenário atual da TI;
- O score atual, se fornecido;
- O que esse score representa;
- As principais fragilidades identificadas;
- A necessidade de evolução da TI de uma área reativa para uma área estratégica;
- A relação do plano com os objetivos do negócio.

Se houver score de maturidade, explique que ele foi calculado a partir das dimensões avaliadas no diagnóstico, como governança, processos, segurança da informação, riscos, infraestrutura, gestão de serviços, pessoas, automação e alinhamento estratégico, sem inventar fórmula.

## 2. Alinhamento Estratégico, Governança e Metodologia
Divida esta seção em três subtópicos:

### 2.1 Alinhamento Estratégico
Explique como a TI deve se alinhar aos objetivos do negócio, como crescimento, eficiência operacional, redução de riscos, inovação, expansão ou internacionalização, quando essas informações estiverem disponíveis.

### 2.2 Governança de TI
Explique como a governança será aplicada.
Recomende a criação ou fortalecimento de mecanismos como:
- Comitê de Governança de TI;
- Definição de papéis e responsabilidades;
- Rituais de acompanhamento;
- Priorização de projetos por valor de negócio;
- Indicadores de desempenho;
- Reporte executivo.

Quando fizer sentido, cite boas práticas baseadas em COBIT, sem aprofundar tecnicamente demais.

### 2.3 Metodologia de Gestão
Explique a metodologia recomendada para organizar a TI.
Quando fizer sentido, recomende práticas baseadas em ITIL para:
- Gestão de incidentes;
- Requisições;
- Problemas;
- Mudanças;
- Catálogo de serviços;
- SLAs e OLAs;
- Melhoria contínua.

Para projetos, mencione abordagem ágil, híbrida ou tradicional, conforme o contexto informado.

## 3. Principais Gaps e Riscos Identificados
Organize os gaps e riscos por categorias.

Use, sempre que possível, os seguintes grupos:

### 3.1 Gestão de Processos e Operações
Liste gaps e riscos relacionados a processos, incidentes, mudanças, requisições, documentação e dependência de pessoas.

### 3.2 Infraestrutura, Ferramentas e Automação
Liste gaps e riscos relacionados a monitoramento, inventário, ativos, ferramentas, automação e infraestrutura.

### 3.3 Gestão de Serviços e Níveis de Atendimento
Liste gaps e riscos relacionados a SLAs, OLAs, atendimento, previsibilidade, satisfação dos usuários e serviços críticos.

### 3.4 Governança Estratégica e Valor da TI
Liste gaps e riscos relacionados a alinhamento estratégico, ausência de indicadores, falta de priorização, papéis e responsabilidades.

### 3.5 Segurança da Informação, Riscos e Continuidade
Liste gaps e riscos relacionados a acessos, backup, continuidade, recuperação de desastres, LGPD, ransomware, controles e gestão de riscos.

### 3.6 Pessoas, Cultura e Competências
Liste gaps e riscos relacionados a capacitação, dependência de pessoas-chave, compartilhamento de conhecimento, inovação e colaboração.

Em cada categoria, use o formato:

**Gaps identificados:**
- ...

**Riscos associados:**
- ...

## 4. Eixos Estratégicos do PDTI
Crie uma seção explicando que o plano será organizado em eixos estratégicos.

Use os seguintes eixos, se forem compatíveis com os dados:

1. Governança e Alinhamento Estratégico;
2. Gestão de Serviços de TI;
3. Segurança da Informação, Riscos e Continuidade;
4. Infraestrutura, Ferramentas e Automação;
5. Pessoas, Cultura e Melhoria Contínua.

Não invente eixos desnecessários. Caso algum eixo não tenha ações relacionadas, mantenha apenas os eixos aplicáveis.

## 5. Plano de Ação e Cronograma
Crie uma tabela em Markdown com as ações do plano.

A tabela deve ter obrigatoriamente as colunas:

| Eixo | Ação | Justificativa | Prazo | Custo Estimado | Responsável | Prioridade |

Regras para a tabela:
- Use apenas ações fornecidas no plano de ação da aplicação.
- Não invente custo.
- Não invente responsável.
- Não invente prazo.
- Se algum campo não existir, escreva "Não informado".
- A justificativa deve explicar o porquê da ação em linguagem executiva.
- Classifique a prioridade como Alta, Média ou Baixa, considerando impacto, risco e urgência.
- Agrupe corretamente cada ação dentro do eixo estratégico mais adequado.
- Padronize os nomes dos responsáveis e ações, mantendo o sentido original.

## 6. Indicadores de Sucesso — KPIs
Crie uma tabela de KPIs para acompanhar a evolução do PDTI.

A tabela deve ter as colunas:

| Indicador | Meta |

Regras:
- Se metas numéricas forem fornecidas, utilize exatamente os valores fornecidos.
- Se não houver metas numéricas, proponha indicadores qualitativos sem inventar percentuais.
- Os KPIs devem medir evolução em governança, serviços, segurança, riscos, continuidade, disponibilidade, satisfação dos usuários, documentação, automação e entrega de projetos, quando esses temas existirem no diagnóstico.
- Não invente percentuais, valores financeiros ou prazos específicos sem base nos dados.

Exemplos de indicadores que podem ser usados, se fizerem sentido:
- Score Geral de Maturidade de TI;
- Maturidade de Governança de TI;
- Disponibilidade dos Serviços Críticos;
- MTTR — Tempo Médio para Restauração;
- Cumprimento de SLAs;
- Satisfação dos Usuários — CSAT;
- Percentual de Processos Documentados;
- Percentual de Automação de Rotinas;
- Conformidade com Políticas de Segurança;
- Testes de Recuperação de Desastres;
- Projetos Entregues no Prazo e Orçamento;
- Redução da Dependência de Pessoas-Chave.

## 7. Priorização Geral
Crie uma seção separando as ações por prioridade.

Use o formato:

### Alta Prioridade
- ...

### Média Prioridade
- ...

### Baixa Prioridade
- ...

A classificação deve ser coerente com os riscos identificados.
Ações ligadas a segurança, continuidade, governança, processos críticos, gestão de acessos, backup, riscos e serviços essenciais normalmente devem receber prioridade mais alta.

## 8. Conclusão
Finalize com uma conclusão executiva explicando:
- A situação atual da TI;
- A importância da execução do PDTI;
- Os benefícios esperados;
- A necessidade de apoio da alta direção;
- O papel da TI como área estratégica;
- A importância do acompanhamento contínuo por indicadores.

A conclusão deve ser formal, forte e adequada para fechamento de documento institucional.

IMPORTANTE:
O resultado final deve conter apenas o PDTI em Markdown.
Não explique o que você fez.
Não inclua comentários fora do documento.
Não use linguagem informal.
REGRA CRÍTICA DE ASSINATURA: O documento foi elaborado por "{nome_avaliador}". No final da conclusão, você deve assinar EXATAMENTE como: "Consultor: {nome_avaliador}". É terminantemente proibido utilizar colchetes como [Seu Nome] ou [Nome da Empresa].
"""

    try:
        # 5. Chamar a API do Gemini
        prompt_completo = f"{instrucoes}\n\n--- DADOS DA EMPRESA ---\n{contexto_dados}"
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_completo
        )
        
        pdti_text = response.text
        
        query_db(
    """
    UPDATE assessments
    SET pdti_markdown = %s,
        pdti_generated_at = NOW()
    WHERE id = %s
    """,
    (pdti_text, assessment_id)
)
        # 6. Retornar para o frontend
        return jsonify({"status": "success", "pdti": pdti_text})
        
    except Exception as e:
        print(f"Erro na IA: {e}", flush=True)
        return jsonify({"status": "error", "message": str(e)}), 500
    
@app.route("/assessments/<int:assessment_id>/download-pdti", methods=["GET"])
@require_login
def download_pdti_pdf(assessment_id):
    from google import genai
    from flask import render_template, redirect, url_for, flash, session
    
    client = genai.Client()
    assessment = query_db("SELECT a.*, c.name as company_name FROM assessments a JOIN companies c ON a.company_id = c.id WHERE a.id = %s", (assessment_id,), one=True)
    
    responses = query_db("""
        SELECT q.text as question, q.category, r.score, r.action_plan, r.action_why, r.action_deadline, r.action_cost, r.action_responsible 
        FROM responses r 
        JOIN questions q ON r.question_id = q.id 
        WHERE r.assessment_id = %s
    """, (assessment_id,))
    
    nome_avaliador = session.get("user_name")
    if not nome_avaliador or nome_avaliador.strip() == "":
        nome_avaliador = "Consultoria Radar.TI"
    
    contexto_dados = f"Empresa: {assessment['company_name']}\nScore Geral Atual: {assessment.get('overall_score', 0)}%\n\nDETALHES DO DIAGNÓSTICO:\n"
    for r in responses:
        responsavel = r.get('action_responsible') or 'A definir'
        contexto_dados += f"- Domínio: {r['category']} | Quesito: {r['question']}\n  Nota: {r['score']}/5\n"
        if r['action_plan']:
            contexto_dados += f"  Ação: {r['action_plan']} | Por que: {r['action_why']} | Prazo: {r['action_deadline']} | Custo: {r['action_cost']} | Resp: {responsavel}\n"

    # A MÁGICA ESTÁ AQUI: Pedindo HTML direto para a IA
    instrucoes = f"""
    Você é um Consultor Sênior de Governança de TI. Sua tarefa é ler os dados do diagnóstico de TI e redigir um PDTI (Plano Diretor de Tecnologia da Informação) executivo.
    
    REGRAS DE FORMATAÇÃO (CRÍTICO): 
    Formate sua resposta EXCLUSIVAMENTE em tags HTML válidas (use <h2> para títulos, <p> para textos, <ul> e <li> para listas, <strong> para negritos). 
    NÃO use formatação Markdown (como ** ou #). 
    NÃO coloque o texto dentro de blocos de código (como ```html). Retorne apenas o código HTML puro.
    
    Estrutura obrigatória:
    1. Resumo Executivo.
    2. Alinhamento Estratégico, Governança e Metodologia.
    3. Principais Gaps e Riscos Encontrados.
    4. Mapa do Plano de Ação e Cronograma (Apresente em formato de LISTA HTML usando <ul> e <li>, garantindo a exibição de responsáveis, prazos e custos).
    5. Indicadores de Sucesso (KPIs para medir a evolução do plano).
    6. Conclusão.

    O documento foi elaborado por "{nome_avaliador}". No final, assine EXATAMENTE como: "Consultor: {nome_avaliador}".
    """

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=f"{instrucoes}\n\n--- DADOS DA EMPRESA ---\n{contexto_dados}"
        )
        
        # Pega a resposta da IA (que agora já vem em HTML) e joga direto pra tela!
        html_from_ia = response.text.replace('```html', '').replace('```', '')
        
        return render_template("pdti_pdf_template.html", 
                               company_name=assessment['company_name'], 
                               score=assessment.get('overall_score', 0),
                               content=html_from_ia)
        
    except Exception as e:
        flash(f"Erro ao gerar o PDTI: {str(e)}")
        return redirect(url_for('view_assessment', assessment_id=assessment_id))
    
@app.route("/assessments/<int:assessment_id>")
@require_login
@require_perm("view_reports")
def view_assessment(assessment_id: int):
    assessment = query_db("""
        SELECT a.*, c.name as company_name, c.sector, c.size 
        FROM assessments a
        JOIN companies c ON a.company_id = c.id
        WHERE a.id = %s
    """, (assessment_id,), one=True)
    
    if not assessment:
        flash("Avaliação não encontrada.")
        return redirect(url_for("assessments"))
        
    responses = query_db("""
        SELECT r.*, q.category, q.text, q.cid_pillar, q.gov_or_mgt 
        FROM responses r
        JOIN questions q ON r.question_id = q.id
        WHERE r.assessment_id = %s
    """, (assessment_id,))
    
    result = compute_assessment(assessment_id)
    level_tuple = result["level"] if result else ("Indefinido", "", "Sem dados")
    
    gaps = [r for r in responses if r['score'] <= 2]
    strengths = [r for r in responses if r['score'] >= 4]
    
    questions_by_category = {}
    cat_scores = {}
    for r in responses:
        cat = r['category']
        if cat not in questions_by_category:
            questions_by_category[cat] = []
        questions_by_category[cat].append(r)
        
        if cat not in cat_scores:
            cat_scores[cat] = []
        cat_scores[cat].append(r['score'])
        
    radar_labels = list(cat_scores.keys())
    radar_data = [round((sum(v)/len(v)) * 20, 1) if v else 0 for v in cat_scores.values()]
    
    risks = [r for r in responses if r['risk_probability'] and r['risk_impact']]
    for r in risks:
        r['risk_score'] = r['risk_probability'] * r['risk_impact']
    top_risks = sorted(risks, key=lambda x: x['risk_score'], reverse=True)[:3]
    
    actions = [r for r in responses if r['action_plan']]
    action_stats = {
        'total': len(actions),
        'a_fazer': len([a for a in actions if a['action_status'] == 'A Fazer']),
        'andamento': len([a for a in actions if a['action_status'] == 'Em Andamento']),
        'concluido': len([a for a in actions if a['action_status'] == 'Concluído'])
    }

    history_rows = query_db("""
        SELECT title, overall_score, completed_at 
        FROM assessments 
        WHERE company_id = %s AND completed_at IS NOT NULL 
        ORDER BY completed_at ASC
    """, (assessment['company_id'],))
    history_labels = [h['completed_at'][:10] for h in history_rows]
    history_data = [h['overall_score'] for h in history_rows]


    my_sector = assessment['sector']
    my_size = assessment['size']

    all_completed = query_db("""
        SELECT a.overall_score, c.sector, c.size 
        FROM assessments a
        JOIN companies c ON a.company_id = c.id
        WHERE a.completed_at IS NOT NULL AND a.id != %s
    """, (assessment_id,))

    sector_scores = []
    size_scores = []

    for row in all_completed:
        # Se os textos baterem exatamente, entra na média!
        if row['sector'] == my_sector:
            sector_scores.append(row['overall_score'])
        if row['size'] == my_size:
            size_scores.append(row['overall_score'])

    benchmark = {
        'my_macro_sector': my_sector or "Não Informado",
        'avg_sector': round(sum(sector_scores)/len(sector_scores), 1) if sector_scores else None,
        'count_sector': len(sector_scores),
        'avg_size': round(sum(size_scores)/len(size_scores), 1) if size_scores else None,
        'count_size': len(size_scores)
    }

    return render_template(
        "view_assessment.html", 
        assessment=assessment, responses=responses, result=result, 
        level_name=level_tuple[0], level_class=level_tuple[1], explanation=level_tuple[2], 
        gaps=gaps, strengths=strengths, questions_by_category=questions_by_category, 
        radar_labels=radar_labels, radar_data=radar_data, top_risks=top_risks, action_stats=action_stats, 
        history_labels=history_labels, history_data=history_data,
        benchmark=benchmark, 
        title=f"Relatório: {assessment.get('title', 'Avaliação')}"
    )

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", False), host="0.0.0.0", port=5000)