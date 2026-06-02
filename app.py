from __future__ import annotations

from http.client import responses
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

    assessment = query_db(
        """
        SELECT a.*, c.name as company_name
        FROM assessments a
        JOIN companies c ON a.company_id = c.id
        WHERE a.id = %s
        """,
        (assessment_id,),
        one=True
    )

    if not assessment:
        return jsonify({
            "status": "error",
            "message": "Avaliação não encontrada."
        }), 404

    responses = query_db(
    """
    WITH base AS (
        SELECT
            q.text AS question,
            q.category,
            r.score,
            r.evidence,

            r.action_plan,
            r.action_why,
            r.action_where,
            r.action_deadline,
            r.action_responsible,
            r.action_how,
            r.action_cost,

            CASE
                WHEN r.risk_probability BETWEEN 1 AND 5
                THEN r.risk_probability
                WHEN r.score <= 1
                THEN 4
                WHEN r.score = 2
                THEN 3
                WHEN r.score = 3
                THEN 2
                ELSE 1
            END AS risk_probability_effective,

            CASE
                WHEN r.risk_impact BETWEEN 1 AND 5
                THEN r.risk_impact
                WHEN q.category ILIKE '%%segurança%%'
                  OR q.category ILIKE '%%conformidade%%'
                  OR q.category ILIKE '%%risco%%'
                  OR q.category ILIKE '%%continuidade%%'
                  OR q.category ILIKE '%%governança%%'
                THEN 5
                WHEN r.score <= 1
                THEN 4
                WHEN r.score = 2
                THEN 4
                WHEN r.score = 3
                THEN 3
                ELSE 2
            END AS risk_impact_effective,

            CASE
                WHEN r.risk_probability BETWEEN 1 AND 5
                 AND r.risk_impact BETWEEN 1 AND 5
                THEN 'Informado no diagnóstico'
                ELSE 'Estimado automaticamente com base na nota de maturidade e no domínio avaliado'
            END AS risk_origin

        FROM responses r
        JOIN questions q ON r.question_id = q.id
        WHERE r.assessment_id = %s
    )

    SELECT
        question,
        category,
        score,
        evidence,

        action_plan,
        action_why,
        action_where,
        action_deadline,
        action_responsible,
        action_how,
        action_cost,

        risk_probability_effective AS risk_probability,
        risk_impact_effective AS risk_impact,
        risk_probability_effective * risk_impact_effective AS risk_score,

        CASE
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 1 AND 5
            THEN 'Baixo'
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 6 AND 10
            THEN 'Moderado'
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 11 AND 15
            THEN 'Alto'
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 16 AND 25
            THEN 'Crítico'
            ELSE 'Não informado'
        END AS risk_classification,

        CASE
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 20 AND 25
            THEN 'Altíssima'
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 16 AND 19
            THEN 'Alta'
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 11 AND 15
            THEN 'Média'
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 6 AND 10
            THEN 'Baixa'
            ELSE 'Baixa'
        END AS action_priority,

        CASE
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 20 AND 25
            THEN 1
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 16 AND 19
            THEN 2
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 11 AND 15
            THEN 3
            WHEN risk_probability_effective * risk_impact_effective BETWEEN 6 AND 10
            THEN 4
            ELSE 5
        END AS priority_order,

        risk_origin

    FROM base
    ORDER BY
        priority_order ASC,
        risk_probability_effective * risk_impact_effective DESC,
        action_deadline ASC,
        category ASC
    """,
    (assessment_id,)
)

    nome_avaliador = session.get("user_name")
    if not nome_avaliador or nome_avaliador.strip() == "":
        nome_avaliador = "Consultoria Radar.TI"

    periodo_pdti = "2026-2028"

    score_atual = float(assessment.get("overall_score") or 0)

    classificacao_maturidade = assessment.get("maturity_level")

    if not classificacao_maturidade or str(classificacao_maturidade).strip() == "":
        classificacao_maturidade, classe_maturidade, descricao_maturidade = maturity_from_score(score_atual)
    else:
         _, classe_maturidade, descricao_maturidade = maturity_from_score(score_atual)

    contexto_dados = f"""
Empresa: {assessment["company_name"]}
Score Geral Atual: {assessment.get("overall_score", 0)}%
Classificação de Maturidade: {classificacao_maturidade}
Descrição da Maturidade: {descricao_maturidade}
Período do PDTI: {periodo_pdti}
Consultor/Avaliador: {nome_avaliador}

DETALHES DO DIAGNÓSTICO, EVIDÊNCIAS, RISCOS E PLANO DE AÇÃO 5W2H:
"""

    for r in responses:
        contexto_dados += f"""
DOMÍNIO: {r.get("category") or "Não informado"}
QUESITO AVALIADO: {r.get("question") or "Não informado"}
NOTA DE MATURIDADE: {r.get("score") if r.get("score") is not None else "Não informado"}/5
EVIDÊNCIA REGISTRADA: {r.get("evidence") or "Não informado"}

RISCO:
Probabilidade (P): {r.get("risk_probability") if r.get("risk_probability") is not None else "Não informado"}
Impacto (I): {r.get("risk_impact") if r.get("risk_impact") is not None else "Não informado"}
Score do Risco (S = P x I): {r.get("risk_score") if r.get("risk_score") is not None else "Não informado"}
Classificação do Risco: {r.get("risk_classification") or "Não informado"}
Prioridade Obrigatória da Ação: {r.get("action_priority") or "Não informado"}
Origem da avaliação de risco: {r.get("risk_origin") or "Não informado"}

PLANO DE AÇÃO 5W2H:
Prioridade: {r.get("action_priority") or "Não informado"}
Risco Mitigado: {r.get("risk_classification") or "Não informado"} - Score {r.get("risk_score") if r.get("risk_score") is not None else "Não informado"}
What: {r.get("action_plan") or "Não informado"}
Why: {r.get("action_why") or "Não informado"}
Where: {r.get("action_where") or "Não informado"}
When: {r.get("action_deadline") or "Não informado"}
Who: {r.get("action_responsible") or "Não informado"}
How: {r.get("action_how") or "Não informado"}
How Much: {r.get("action_cost") or "Não informado"}
"""

    instrucoes = f"""
Você é um Consultor Sênior de Governança de TI, especializado em PDTI, COBIT, ITIL, ISO 27001, LGPD, Gestão de Riscos, Gestão de Serviços e Planejamento Estratégico de TI.

Sua tarefa é gerar um PDTI — Plano Diretor de Tecnologia da Informação — a partir dos dados do diagnóstico corporativo, da matriz de maturidade, dos riscos identificados e do plano de ação 5W2H fornecidos pela aplicação.

O período oficial deste PDTI é: {periodo_pdti}.
Todas as análises, cronogramas, metas e ações devem respeitar esse período.

O documento deve ser formal, executivo, técnico e aderente a um trabalho acadêmico de Governança de TI.

REGRA CRÍTICA:
A saída NÃO pode ser apenas conceitual.
É obrigatório gerar tabelas estruturadas para SWOT, matriz de riscos, plano de ação 5W2H, KPIs, CAPEX/OPEX e Curva S.
É proibido substituir essas tabelas por texto corrido.

REGRA CRÍTICA SOBRE RISCOS:
É proibido gerar riscos críticos com Probabilidade 0, Impacto 0 ou Score 0.
A escala válida de Probabilidade e Impacto é obrigatoriamente de 1 a 5.
Quando a aplicação fornecer Probabilidade, Impacto, Score e Classificação, use exatamente esses valores.
Quando a aplicação informar que o risco foi estimado automaticamente, mantenha os valores estimados e informe na justificativa que a pontuação foi derivada da nota de maturidade e do domínio avaliado.
Quando houver gap com nota 0, 1 ou 2, ele deve obrigatoriamente aparecer na matriz de riscos com score maior que zero.
Nunca use Score 0 para representar ausência de avaliação. Use "Não informado" apenas quando realmente não houver dados suficientes, mas não para gaps críticos.

REGRA CRÍTICA SOBRE PRIORIDADE:
A prioridade da ação deve ser definida pelo Score de Risco, e não apenas pelo prazo.
Use obrigatoriamente o campo "Prioridade Obrigatória da Ação" fornecido no contexto.
É proibido rebaixar uma ação de risco crítico para prioridade "Baixa".
Riscos com Score entre 20 e 25 devem aparecer como prioridade "Altíssima".
Riscos com Score entre 16 e 19 devem aparecer como prioridade "Alta".
Riscos com Score entre 11 e 15 devem aparecer como prioridade "Média".
Riscos com Score abaixo de 11 podem aparecer como prioridade "Baixa".
A mesma prioridade deve ser preservada no Plano de Ação 5W2H e no Plano Diretor de Ações Estratégicas.

REGRAS GERAIS:
- Formate toda a resposta em Markdown.
- Não use HTML.
- Não use bloco de código Markdown.
- Não invente dados numéricos sem base.
- Quando houver dados numéricos no diagnóstico, utilize-os obrigatoriamente.
- Quando algum dado não for fornecido, escreva "Não informado".
- Pode inferir classificação qualitativa quando necessário, desde que com base nos dados fornecidos.
- Não invente responsáveis, custos ou prazos.
- Preserve as ações 5W2H fornecidas pela aplicação.
- Não simplifique o plano de ação em lista comum.
- Não transforme 5W2H em texto corrido.
- Não omita riscos críticos.
- Não omita KPIs quantitativos quando houver valores atuais e metas disponíveis.
- Use linguagem consultiva, formal e objetiva.
- O documento deve demonstrar ligação lógica entre diagnóstico, SWOT, riscos, plano de ação e indicadores.

ESTRUTURA OBRIGATÓRIA DO PDTI:

# Plano Diretor de Tecnologia da Informação — PDTI

Informe obrigatoriamente:
- Empresa;
- Período do PDTI: {periodo_pdti};
- Score geral de maturidade de TI;
- Classificação de maturidade, se fornecida;
- Avaliador ou consultor responsável.

## 1. Introdução

Apresente:
- O objetivo do PDTI;
- O contexto da organização;
- A importância da TI para a estratégia do negócio;
- A relação entre o PDTI, a governança corporativa e os objetivos estratégicos da empresa;
- A necessidade de alinhar tecnologia, riscos, controles, investimentos e geração de valor.

## 2. Análise Situacional — SWOT

Crie obrigatoriamente uma matriz SWOT em tabela Markdown.

A tabela deve ter exatamente esta estrutura:

| Forças | Fraquezas |
|---|---|
| ... | ... |

| Oportunidades | Ameaças |
|---|---|
| ... | ... |

Regras:
- As Forças devem vir de evidências positivas do diagnóstico.
- As Fraquezas devem vir de notas baixas, processos inexistentes, falhas operacionais e lacunas de governança.
- As Oportunidades devem estar relacionadas a melhoria de governança, automação, integração, segurança, conformidade, eficiência e valor de negócio.
- As Ameaças devem estar relacionadas a riscos regulatórios, financeiros, operacionais, segurança da informação, continuidade, LGPD, perda de confiança e indisponibilidade.
- Não invente fatos externos.
- A SWOT precisa servir de ponte entre o diagnóstico e o plano de ação.

## 3. Diagnóstico Situacional

Apresente uma análise do diagnóstico de maturidade.

Inclua obrigatoriamente:
- Score geral atual;
- Interpretação do score;
- Principais domínios avaliados;
- Domínios com maior fragilidade;
- Gaps críticos identificados;
- Relação entre os gaps e o cenário operacional da empresa.

Organize os gaps por domínio em uma tabela:

| Domínio | Quesito Avaliado | Nota | Gap Identificado | Consequência para o Negócio |
|---|---:|---:|---|---|

Regras:
- Utilize as notas fornecidas.
- Dê destaque para notas 0, 1 e 2.
- Não omita domínios críticos.
- Conecte cada gap ao impacto no negócio.

## 4. Análise de Riscos

Esta seção é obrigatória e deve conter uma MATRIZ NUMÉRICA DE RISCOS.

Use obrigatoriamente a regra:

S = P × I

Onde:
- S = Score de Risco;
- P = Probabilidade;
- I = Impacto.

Escala:
- Probabilidade: 1 a 5;
- Impacto: 1 a 5;
- Score máximo: 25.

Classificação:
- 1 a 5 = Baixo;
- 6 a 10 = Moderado;
- 11 a 15 = Alto;
- 16 a 25 = Crítico.

Crie obrigatoriamente a tabela:

| ID | Domínio | Risco Identificado | Probabilidade (P) | Impacto (I) | Score S = P x I | Classificação | Evidência/Justificativa | Ação Mitigadora |
|---|---|---|---:|---:|---:|---|---|---|

Regras:
- Use obrigatoriamente os valores de Probabilidade, Impacto, Score e Classificação fornecidos no contexto.
- Não recalcule nem substitua os valores recebidos.
- É proibido usar P = 0, I = 0 ou Score = 0.
- Se a origem do risco for "Estimado automaticamente com base na nota de maturidade e no domínio avaliado", informe isso na coluna de Evidência/Justificativa.
- Todos os gaps com nota 0, 1 ou 2 devem aparecer na matriz de riscos.
- Riscos de segurança da informação, continuidade, acesso, backup, indisponibilidade, LGPD, auditoria, governança, ativos, mudanças e serviços críticos devem aparecer quando existirem no diagnóstico.
- Não apresente apenas Top 3 riscos. Apresente uma matriz de riscos compatível com os gaps críticos.
- Ordene os riscos do maior score para o menor.

Após a tabela, escreva um parágrafo explicando quais riscos exigem mitigação imediata nos primeiros 90 dias.

## 5. Plano de Ação dos Primeiros 90 Dias — 5W2H

Esta seção é obrigatória.

REGRA OBRIGATÓRIA DE PRIORIDADE:
A coluna "Prioridade" do plano 5W2H deve copiar exatamente o campo "Prioridade" recebido em cada PLANO DE AÇÃO 5W2H.

É proibido recalcular, reinterpretar ou alterar a prioridade.

Riscos com classificação "Crítico" jamais podem aparecer como prioridade "Baixa" ou "Média".

Use obrigatoriamente:
- Score 20 a 25: Altíssima
- Score 16 a 19: Alta
- Score 11 a 15: Média
- Score 6 a 10: Baixa
- Score 1 a 5: Baixa

Crie uma tabela 5W2H com ações priorizadas para os primeiros 90 dias.

A tabela deve ter exatamente as colunas:

| Prioridade | Risco Mitigado | What | Why | Where | When | Who | How | How Much |
|---|---|---|---|---|---|---|---|---|

Regras:
- Use as ações fornecidas no plano de ação da aplicação.
- Preserve os campos What, Why, Where, When, Who, How e How Much.
- Não transforme o 5W2H em lista.
- Não omita custo, prazo ou responsável quando forem fornecidos.
- Se algum campo não existir, escreva "Não informado".
- Priorize ações com prazo dentro dos primeiros 90 dias.
- Ações ligadas a riscos críticos devem aparecer primeiro.
- Cada ação precisa estar conectada a um risco mitigado.
- O campo "Risco Mitigado" deve apontar claramente qual risco da matriz está sendo tratado.
- A coluna "Prioridade" deve usar exatamente o valor informado em "Prioridade Obrigatória da Ação".
- Nunca classifique como "Baixa" uma ação cujo risco mitigado tenha classificação "Crítico".
- Ordene as ações por prioridade: Altíssima, Alta, Média e Baixa.

## 6. Plano Diretor de Ações Estratégicas — 2026-2028

Depois do plano de 90 dias, apresente o roadmap geral do PDTI para o período completo.

Use a tabela:

| Eixo Estratégico | Ação | Justificativa | Prazo | Responsável | Custo Estimado | Prioridade |
|---|---|---|---|---|---|---|

Eixos recomendados:
1. Governança e Alinhamento Estratégico;
2. Gestão de Serviços de TI;
3. Segurança da Informação, Riscos e Continuidade;
4. Infraestrutura, Ferramentas e Automação;
5. Dados, Integração e Sistemas;
6. Pessoas, Cultura e Melhoria Contínua.


REGRA OBRIGATÓRIA DE PRIORIDADE:
A prioridade no Plano Diretor de Ações Estratégicas deve ser igual à prioridade informada no bloco PLANO DE AÇÃO 5W2H.
Não use o prazo para rebaixar prioridades.
Não classifique como "Baixa" ações ligadas a riscos críticos.

Regras:
- Use apenas ações existentes no plano de ação.
- Não invente novas ações.
- Classifique prioridade como Alta, Média ou Baixa.
- A justificativa deve relacionar a ação ao gap, risco ou objetivo estratégico correspondente.
- A prioridade da ação deve ser igual à "Prioridade Obrigatória da Ação" recebida no contexto.
- Não altere a prioridade com base apenas no prazo ou no custo.
- Risco crítico nunca pode gerar prioridade Baixa.

## 7. Viabilidade Financeira — CAPEX e OPEX

Esta seção é obrigatória.

Classifique os custos das ações entre CAPEX e OPEX.

Use a tabela:

| Ação | Tipo de Gasto | Valor Estimado | Justificativa da Classificação |
|---|---|---:|---|

Critérios:
- CAPEX = investimento em aquisição, implantação, infraestrutura, sistemas, consultoria de implantação, integração ou ativo tecnológico.
- OPEX = despesa recorrente, mensalidade, SaaS, suporte, operação, treinamento recorrente ou serviço contínuo.
- Se o custo informado for "R$ 0,00", "0", "0,00", "-", ou indicar ausência de custo direto, classifique o Tipo de Gasto como "Sem custo direto".
- Para ações sem custo direto, a justificativa deve explicar que se trata de ação interna, administrativa, processual, de governança ou organizacional.
- Não use "Não informado" quando o valor estiver claramente indicado como R$ 0,00.
- Use "Não informado" apenas quando realmente não houver dado de custo.
- Não invente valores.
- Se o custo for mensal, mantenha como mensal.
- Se o custo for único, mantenha como único.

Depois da tabela, apresente um resumo:

| Total CAPEX Identificado | Total OPEX Mensal Identificado | Observação |
|---:|---:|---|

Regras:
- Some apenas valores claramente numéricos.
- Não some valores ambíguos.
- Quando não for possível somar, escreva "Não consolidado por ausência de dados padronizados".

## 8. Curva S Financeira e Técnica

Esta seção é obrigatória.

Apresente uma Curva S simplificada em tabela, dividindo as ações por horizonte de execução.

Use a tabela:

| Fase | Período | Foco Técnico | Ações Principais | Investimento Previsto | Resultado Esperado |
|---|---|---|---|---|---|

Fases obrigatórias:
- Fase 1 — Estabilização: 0 a 90 dias;
- Fase 2 — Estruturação: 3 a 12 meses;
- Fase 3 — Otimização: 12 a 36 meses.

Regras:
- A Fase 1 deve conter ações críticas de risco, continuidade, acessos, backup, governança e monitoramento.
- A Fase 2 deve conter ações de estruturação de processos, ITSM, ITIL, SLAs, KPIs e integração.
- A Fase 3 deve conter ações de maturidade, automação, inovação, melhoria contínua e otimização.
- Não invente ações.
- O investimento previsto deve usar os custos fornecidos.
- Se não houver custo consolidado, escreva "Conforme plano de ação".

## 9. Indicadores de Sucesso — KPIs Quantitativos

Esta seção é obrigatória.

Crie uma tabela com indicadores operacionais quantitativos.

Use exatamente esta estrutura:

| Indicador | Situação Atual | Meta | Prazo de Acompanhamento | Fonte de Medição |
|---|---:|---:|---|---|

Regras:
- Use valores atuais e metas quando eles aparecerem no diagnóstico, evidências, plano de ação ou texto do quesito.
- Não invente valores atuais.
- Caso o valor atual não exista, escreva "Baseline a coletar nos primeiros 30 dias".
- Caso a meta não exista, defina uma meta operacional mensurável apenas quando ela decorrer diretamente da ação proposta.
- Quando a ação for implantação de ITSM, utilize indicadores como percentual de chamados registrados no ITSM, cumprimento de SLA e MTTR.
- Quando a ação for backup/DRP, utilize indicadores como sucesso em testes de restauração, periodicidade dos testes e RPO/RTO, se informados.
- Quando a ação for controle de acessos, utilize indicadores como percentual de contas revisadas, contas órfãs removidas, usuários com MFA e acessos recertificados.
- Quando a ação for inventário, utilize percentual de ativos inventariados.
- Quando a ação for governança, utilize percentual de ações reportadas ao comitê, percentual de riscos acompanhados e percentual de projetos priorizados por critério formal.
- Quando a ação for integração ou automação, utilize percentual de processos automatizados ou integrações implantadas.
- Inclua obrigatoriamente indicadores operacionais, não apenas indicadores conceituais.

## 10. Governança de Acompanhamento e Controle

Explique como o PDTI será acompanhado.

Inclua:
- Comitê responsável;
- Periodicidade de revisão;
- Forma de reporte;
- Responsáveis por atualizar indicadores;
- Como riscos e ações serão acompanhados;
- Como a alta direção validará o progresso.

Use uma tabela:

| Mecanismo de Controle | Periodicidade | Responsável | Evidência Esperada |
|---|---|---|---|

## 11. Conclusão

Finalize com uma conclusão executiva.

A conclusão deve:
- Retomar o cenário atual;
- Reforçar a necessidade de estabilização da governança;
- Destacar os riscos mais críticos;
- Relacionar o plano de 90 dias com a mitigação imediata;
- Reforçar a importância da matriz de riscos;
- Reforçar a importância dos KPIs quantitativos;
- Destacar a necessidade de apoio da alta direção;
- Apontar a evolução esperada da TI como área estratégica.

IMPORTANTE:
O resultado final deve conter apenas o PDTI em Markdown.
Não explique o que você fez.
Não inclua comentários fora do documento.
Não use linguagem informal.

REGRA CRÍTICA DE ASSINATURA:
O documento foi elaborado por "{nome_avaliador}".
No final da conclusão, assine exatamente como:
Consultor: {nome_avaliador}
É proibido usar [Seu Nome], [Nome da Empresa] ou qualquer placeholder.
"""

    try:
        prompt_completo = f"{instrucoes}\n\n--- DADOS DA EMPRESA ---\n{contexto_dados}"

        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt_completo
        )

        pdti_text = response.text or ""
        pdti_text = (
            pdti_text
            .replace("```markdown", "")
            .replace("```md", "")
            .replace("```", "")
            .strip()
        )

        execute_db(
            """
            UPDATE assessments
            SET pdti_markdown = %s,
                pdti_generated_at = NOW()
            WHERE id = %s
            """,
            (pdti_text, assessment_id)
        )

        return jsonify({
            "status": "success",
            "pdti": pdti_text
        })

    except Exception as e:
        print(f"Erro na IA: {e}", flush=True)
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@app.route("/assessments/<int:assessment_id>/download-pdti", methods=["GET"])
@require_login
def download_pdti_pdf(assessment_id):
    from flask import render_template, redirect, url_for, flash
    import html
    import re

    def markdown_para_html_basico(markdown_text):
        def inline_format(text):
            text = html.escape(text)
            text = re.sub(r"\*\*(.*?)\*\*", r"<strong>\1</strong>", text)
            text = re.sub(r"\*(.*?)\*", r"<em>\1</em>", text)
            return text

        def parse_table(lines, start_index):
            table_lines = []
            i = start_index

            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1

            if len(table_lines) < 2:
                return None, start_index

            separator = table_lines[1]
            if not re.match(r"^\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?$", separator):
                return None, start_index

            html_table = ["<table>"]

            for index, row in enumerate(table_lines):
                if index == 1:
                    continue

                cells = [cell.strip() for cell in row.strip("|").split("|")]
                tag = "th" if index == 0 else "td"

                html_table.append("<tr>")
                for cell in cells:
                    html_table.append(f"<{tag}>{inline_format(cell)}</{tag}>")
                html_table.append("</tr>")

            html_table.append("</table>")

            return "\n".join(html_table), i

        lines = markdown_text.splitlines()
        html_parts = []
        in_ul = False
        i = 0

        while i < len(lines):
            line = lines[i].rstrip()
            stripped = line.strip()

            if not stripped:
                if in_ul:
                    html_parts.append("</ul>")
                    in_ul = False
                i += 1
                continue

            if stripped.startswith("|"):
                table_html, new_index = parse_table(lines, i)
                if table_html:
                    if in_ul:
                        html_parts.append("</ul>")
                        in_ul = False
                    html_parts.append(table_html)
                    i = new_index
                    continue

            if stripped.startswith("#"):
                if in_ul:
                    html_parts.append("</ul>")
                    in_ul = False

                level = len(stripped) - len(stripped.lstrip("#"))
                level = min(max(level, 1), 6)
                title = stripped[level:].strip()
                html_parts.append(f"<h{level}>{inline_format(title)}</h{level}>")
                i += 1
                continue

            if stripped.startswith("- "):
                if not in_ul:
                    html_parts.append("<ul>")
                    in_ul = True

                item = stripped[2:].strip()
                html_parts.append(f"<li>{inline_format(item)}</li>")
                i += 1
                continue

            if in_ul:
                html_parts.append("</ul>")
                in_ul = False

            html_parts.append(f"<p>{inline_format(stripped)}</p>")
            i += 1

        if in_ul:
            html_parts.append("</ul>")

        return "\n".join(html_parts)

    assessment = query_db(
        """
        SELECT a.*, c.name as company_name
        FROM assessments a
        JOIN companies c ON a.company_id = c.id
        WHERE a.id = %s
        """,
        (assessment_id,),
        one=True
    )

    if not assessment:
        flash("Avaliação não encontrada.")
        return redirect(url_for("dashboard"))

    pdti_markdown = assessment.get("pdti_markdown")

    if not pdti_markdown or pdti_markdown.strip() == "":
        flash("Nenhum PDTI foi gerado ainda. Gere o PDTI antes de baixar.")
        return redirect(url_for("view_assessment", assessment_id=assessment_id))

    try:
        html_from_markdown = markdown_para_html_basico(pdti_markdown)

        return render_template(
            "pdti_pdf_template.html",
            company_name=assessment["company_name"],
            score=assessment.get("overall_score", 0),
            content=html_from_markdown
        )

    except Exception as e:
        flash(f"Erro ao gerar o PDF do PDTI: {str(e)}")
        return redirect(url_for("view_assessment", assessment_id=assessment_id))
    
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