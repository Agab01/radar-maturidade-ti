from __future__ import annotations

import os
import secrets
import hashlib
import smtplib
import ssl
from email.message import EmailMessage
from datetime import datetime, timedelta
from functools import wraps
from typing import Dict, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "fallback-inseguro-apenas-para-dev")
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("ERRO CRÍTICO: DATABASE_URL não encontrada. Verifique seu arquivo .env!")

SCORING = {0: "Não se aplica", 1: "Inexistente", 2: "Inicial", 3: "Parcial", 4: "Consistente", 5: "Totalmente implementado"}
CATEGORIES = ["Processos de TI", "Ferramentas de TI", "Nível de Serviço", "Alinhamento Estratégico", "Governança de TI", "Gestão de Riscos", "Cultura de TI"]
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
            session["user_id"], session["user_name"], session["role"] = user["id"], user["name"], user["role"]
            return redirect(url_for("dashboard"))
        flash("Acesso Negado. Credenciais Incorretas.")
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
            "companies": query_db("SELECT COUNT(*) c FROM companies WHERE auditor_id = %s", (u_id,), one=True)["c"],
            "questions": 0, 
            "assessments": query_db("SELECT COUNT(a.*) c FROM assessments a JOIN companies c ON c.id = a.company_id WHERE c.auditor_id = %s", (u_id,), one=True)["c"],
        }
        recent = query_db("""
            SELECT a.id, a.title, c.name company_name, a.overall_score, a.maturity_level, a.completed_at 
            FROM assessments a JOIN companies c ON c.id = a.company_id 
            WHERE c.auditor_id = %s ORDER BY a.id DESC LIMIT 5
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
            
        company_name = request.form["name"].strip()

        existing_company = query_db("SELECT id FROM companies WHERE lower(name) = %s AND auditor_id = %s", (company_name.lower(), u_id), one=True)
        
        if existing_company:
            flash(f"ERRO: A empresa '{company_name}' já está cadastrada na sua conta.")
            return redirect(url_for("companies"))
            
        execute_db("""
            INSERT INTO companies (name, sector, size, contact_name, contact_email, created_at, auditor_id) 
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (company_name, request.form.get("sector"), request.form.get("size"), 
              request.form.get("contact_name"), request.form.get("contact_email"), 
              datetime.now().isoformat(timespec="seconds"), u_id))
        flash("Empresa registrada com sucesso.")
        return redirect(url_for("companies"))

    if role in ["admin", "analista", "avaliador"]:
        rows = query_db("SELECT * FROM companies ORDER BY id DESC")
    else:
        rows = query_db("SELECT * FROM companies WHERE auditor_id = %s ORDER BY id DESC", (u_id,))
    
    return render_template("companies.html", rows=rows, title="Diretório_Empresas")

@app.route("/companies/<int:company_id>/edit", methods=["GET", "POST"])
@require_login
@require_perm("manage_companies")
def edit_company(company_id):
    company = query_db("SELECT * FROM companies WHERE id = %s", (company_id,), one=True)
    if not company:
        flash("Empresa não localizada.")
        return redirect(url_for("companies"))
    
    if session.get("role") != "admin" and company.get("auditor_id") != session.get("user_id"):
        flash("ACESSO NEGADO: Esta empresa pertence à carteira de outro auditor.")
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
        execute_db("INSERT INTO questions (category, text, weight, guidance, created_at) VALUES (%s, %s, %s, %s, %s)",
                   (request.form["category"], request.form["text"], float(request.form.get("weight", 1) or 1), request.form.get("guidance"), datetime.now().isoformat(timespec="seconds")))
        flash("Quesito Adicionado.")
        return redirect(url_for("questions"))
    rows = query_db("SELECT * FROM questions ORDER BY category, id")
    return render_template("questions.html", rows=rows, categories=CATEGORIES, title="Base_Questões")

@app.route("/questions/<int:question_id>/edit", methods=["GET", "POST"])
@require_login
@require_perm("manage_questions")
def edit_question(question_id):
    question = query_db("SELECT * FROM questions WHERE id = %s", (question_id,), one=True)
    if not question:
        flash("Questão não encontrada.")
        return redirect(url_for("questions"))
    if request.method == "POST":
        execute_db("UPDATE questions SET category=%s, text=%s, weight=%s, guidance=%s WHERE id=%s",
                   (request.form["category"], request.form["text"], float(request.form.get("weight", 1) or 1), request.form.get("guidance"), question_id))
        flash("Quesito atualizado.")
        return redirect(url_for("questions"))
    return render_template("edit_question.html", question=question, categories=CATEGORIES, title="Editar_Quesito")

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
        rows = query_db("""SELECT a.*, c.name company_name, u.name evaluator_name FROM assessments a JOIN companies c ON c.id = a.company_id JOIN users u ON u.id = a.evaluator_id WHERE c.auditor_id = %s ORDER BY a.id DESC""", (u_id,))
        
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
    # O Avaliador e Admin precisam ver todas as empresas na lista para escolher qual vão auditar
    companies = query_db("SELECT id, name FROM companies ORDER BY name")
    
    if request.method == "POST":
        assessment_id = execute_db("INSERT INTO assessments (company_id, title, evaluator_id, started_at) VALUES (%s, %s, %s, %s) RETURNING id",
                                   (request.form["company_id"], request.form["title"], session["user_id"], datetime.now().isoformat(timespec="seconds")))
        return redirect(url_for("answer_assessment", assessment_id=assessment_id))
    return render_template("new_assessment.html", companies=companies, pre_company=request.args.get("company_id", ""), title="Nova_Avaliação")

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
            score, evidence, action_plan, note = int(request.form.get(f"score_{q['id']}", 0)), request.form.get(f"evidence_{q['id']}", "").strip(), request.form.get(f"action_{q['id']}", "").strip(), request.form.get(f"note_{q['id']}", "").strip()
            execute_db("""INSERT INTO responses (assessment_id, question_id, score, evidence, action_plan, note, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT(assessment_id, question_id) DO UPDATE SET score=EXCLUDED.score, evidence=EXCLUDED.evidence, action_plan=EXCLUDED.action_plan, note=EXCLUDED.note""",
                       (assessment_id, q["id"], score, evidence, action_plan, note, datetime.now().isoformat(timespec="seconds")))
        result = compute_assessment(assessment_id)
        execute_db("UPDATE assessments SET completed_at = %s, overall_score = %s, maturity_level = %s WHERE id = %s", (datetime.now().isoformat(timespec="seconds"), result["overall"], result["level"][0], assessment_id))
        flash("Respostas Gravadas. Relatório Consolidado.")
        return redirect(url_for("view_assessment", assessment_id=assessment_id))
    existing = {r["question_id"]: r for r in query_db("SELECT * FROM responses WHERE assessment_id = %s", (assessment_id,))}
    return render_template("answer_assessment.html", assessment=assessment, questions=questions_rows, existing=existing, title=f"Questionário: {assessment['title']}")

@app.route("/assessments/<int:assessment_id>")
@require_login
@require_perm("view_reports")
def view_assessment(assessment_id: int):
    assessment = query_db("SELECT a.*, c.name company_name, c.sector, c.size, u.name evaluator_name FROM assessments a JOIN companies c ON c.id = a.company_id JOIN users u ON u.id = a.evaluator_id WHERE a.id = %s", (assessment_id,), one=True)
    if not assessment:
        flash("Relatório não localizado.")
        return redirect(url_for("assessments"))
    result = compute_assessment(assessment_id)
    questions_by_category = {}
    for row in result["rows"]: questions_by_category.setdefault(row["category"], []).append(row)
    gaps = query_db("SELECT q.category, q.text, r.score, r.action_plan, r.evidence FROM responses r JOIN questions q ON q.id = r.question_id WHERE r.assessment_id = %s AND r.score <= 2 ORDER BY q.category, r.score ASC", (assessment_id,))
    strengths = query_db("SELECT q.category, q.text, r.score, r.evidence FROM responses r JOIN questions q ON q.id = r.question_id WHERE r.assessment_id = %s AND r.score >= 4 ORDER BY q.category, r.score DESC", (assessment_id,))
    
    return render_template("view_assessment.html", assessment=assessment, result=result, level_name=result["level"][0], level_class=result["level"][1], explanation=result["level"][2], strengths=strengths, gaps=gaps, questions_by_category=questions_by_category, title=f"RELATÓRIO: {assessment['company_name']}")

if __name__ == "__main__":
    init_db()
    app.run(debug=os.environ.get("FLASK_DEBUG", False), host="0.0.0.0", port=5000)