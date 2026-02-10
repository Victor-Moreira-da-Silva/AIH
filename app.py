from flask import Flask, render_template, request, redirect, flash, send_from_directory, session, url_for
import os
from datetime import datetime
import pdfplumber
import csv
import sqlite3
import hashlib
import hmac
import secrets
import base64
from functools import wraps
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from PyPDF2 import PdfReader, PdfWriter
from functools import wraps

# ---------------- BANCO ----------------

def conectar_db():
    caminho = os.path.abspath("aih.db")

    conn = sqlite3.connect(
        caminho,
        timeout=10,
        check_same_thread=False
    )

    conn.row_factory = sqlite3.Row
    return conn


def criar_tabela():

    conn = conectar_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS aih (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        -- PACIENTE
        nome_paciente TEXT,
        prontuario TEXT,
        cns TEXT,
        data_nascimento TEXT,
        sexo TEXT,
        raca_cor TEXT,
        etnia TEXT,
        nome_mae TEXT,
        telefone1 TEXT,
        telefone2 TEXT,
        responsavel TEXT,
        endereco TEXT,
        municipio TEXT,
        ibge TEXT,
        uf TEXT,
        cep TEXT,

        -- JUSTIFICATIVA
        sinais TEXT,
        condicoes TEXT,
        provas TEXT,
        diagnostico TEXT,
        cid_principal TEXT,
        cid_secundario TEXT,
        cid_associado TEXT,

        -- PROCEDIMENTO
        descricao_procedimento TEXT,
        codigo_procedimento TEXT,
        clinica TEXT,
        carater TEXT,
        doc_prof TEXT,
        numero_doc_prof TEXT,
        nome_prof TEXT,
        data_solicitacao TEXT,

        -- CAUSA EXTERNA
        tipo_acidente TEXT,
        cnpj_seguradora TEXT,
        cnpj_empresa TEXT,
        numero_bilhete TEXT,
        cnae TEXT,
        serie TEXT,
        cbor TEXT,
        vinculo_empresa TEXT,

        -- AUTORIZAÇÃO
        nome_autorizador TEXT,
        orgao_emissor TEXT,
        doc_autorizador TEXT,
        numero_doc_autorizador TEXT,
        data_autorizacao TEXT,
        numero_autorizacao TEXT,

        -- ARQUIVO
        arquivo_pdf TEXT,
        necessita_apa TEXT,
        status TEXT DEFAULT 'Pendente',
        usuario_aprovacao TEXT,
        data_aprovacao TEXT,
        usuario_reprovacao TEXT,
        data_reprovacao TEXT

    )
    """)

    conn.commit()
    conn.close()

def criar_tabela_usuarios():

    conn = conectar_db()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        perfil TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()


def gerar_hash_senha(senha, iteracoes=120000):
    sal = secrets.token_hex(16)
    senha_hash = hashlib.pbkdf2_hmac(
        "sha256",
        senha.encode("utf-8"),
        sal.encode("utf-8"),
        iteracoes,
    )
    senha_b64 = base64.b64encode(senha_hash).decode("utf-8")
    return f"pbkdf2_sha256${iteracoes}${sal}${senha_b64}"


def verificar_senha(senha, senha_hash):
    try:
        algoritmo, iteracoes, sal, hash_salvo = senha_hash.split("$", 3)
        if algoritmo != "pbkdf2_sha256":
            return False

        senha_calculada = hashlib.pbkdf2_hmac(
            "sha256",
            senha.encode("utf-8"),
            sal.encode("utf-8"),
            int(iteracoes),
        )
        senha_calculada_b64 = base64.b64encode(senha_calculada).decode("utf-8")
        return hmac.compare_digest(senha_calculada_b64, hash_salvo)
    except (ValueError, TypeError):
        return False


def garantir_usuarios_padrao():
    usuarios_padrao = [
        {
            "login": os.getenv("AIH_MEDICO_USER", "medico"),
            "senha": os.getenv("AIH_MEDICO_PASS", "123456"),
            "perfil": "MEDICO",
        },
        {
            "login": os.getenv("AIH_SECRETARIA_USER", "secretaria"),
            "senha": os.getenv("AIH_SECRETARIA_PASS", "123456"),
            "perfil": "SECRETARIA",
        },
    ]

    conn = conectar_db()
    cursor = conn.cursor()

    for usuario in usuarios_padrao:
        cursor.execute("SELECT id FROM usuarios WHERE login = ?", (usuario["login"],))
        existe = cursor.fetchone()

        if not existe:
            cursor.execute(
                """
                INSERT INTO usuarios (login, senha_hash, perfil)
                VALUES (?, ?, ?)
                """,
                (
                    usuario["login"],
                    gerar_hash_senha(usuario["senha"]),
                    usuario["perfil"],
                ),
            )

    conn.commit()
    conn.close()


def garantir_colunas_status():
    colunas_necessarias = {
        "usuario_aprovacao": "TEXT",
        "data_aprovacao": "TEXT",
        "usuario_reprovacao": "TEXT",
        "data_reprovacao": "TEXT",
    }

    conn = conectar_db()
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(aih)")
    colunas_existentes = {coluna[1] for coluna in cursor.fetchall()}

    for coluna, tipo in colunas_necessarias.items():
        if coluna not in colunas_existentes:
            cursor.execute(f"ALTER TABLE aih ADD COLUMN {coluna} {tipo}")

    conn.commit()
    conn.close()


# ---------------- CONFIG ----------------

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "aih_secret")
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# ---------------- logo da santa casa ----------------

LOGO_CANDIDATOS = [
    "logo_santa_casa.png",
    "logo_santa_casa.jpg",
    "logo_santa_casa.jpeg",
    "logo_santa_casa.webp",
    "logo_santa_casa.svg",
]

# Garante schema pronto mesmo quando a aplicação é iniciada via WSGI/flask run
criar_tabela()
garantir_colunas_status()
criar_tabela_usuarios()
garantir_usuarios_padrao()

# ---------------- AUX ----------------

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))

        if session.get("perfil") != "ADM":
            flash("Acesso restrito ao administrador.")
            return redirect(url_for("upload_aih"))

        return func(*args, **kwargs)
    return wrapper


@app.context_processor
def injetar_logo_santa_casa():
    static_dir = os.path.join(os.path.dirname(__file__), "static")

    for arquivo_logo in LOGO_CANDIDATOS:
        if os.path.exists(os.path.join(static_dir, arquivo_logo)):
            return {"logo_santa_casa": arquivo_logo}

    return {"logo_santa_casa": None}


# ---------------- IMPRIMIR PDF ----------------

#---------ADICIONA ESPAÇO NOS NUMEROS-------

def desenhar_campos(c, valor, x_inicial, y, espacamento=15):

    if not valor:
        return

    valor = "".join(filter(str.isdigit, valor))  # mantém só números

    for i, char in enumerate(valor):
        c.drawString(x_inicial + (i * espacamento), y, char)

#---------ADICIONA ESPAÇO NOS NUMEROS CEP-------

def desenhar_campos_cep(c, valor, x_inicial, y, espacamento=12):

    if not valor:
        return

    valor = "".join(filter(str.isdigit, valor))  # mantém só números

    for i, char in enumerate(valor):
        c.drawString(x_inicial + (i * espacamento), y, char)
#--------ARRUMA FORMATO DE DATA----------

def formatar_data(data_iso):

    if not data_iso:
        return ""

    try:
        return datetime.strptime(data_iso, "%Y-%m-%d").strftime("%d/%m/%Y")
    except ValueError:
        return data_iso
    
#----------ARRUMA O CAMPO SEXO--------   

def marcar_opcao(canvas, valor, esperado, x, y):

    if (valor or "").upper() == esperado:
        canvas.drawString(x, y, "X")

#--------------ARRUMA O CAMPO DE ESCRITA PARA PULAR LINHA-----------------

from reportlab.pdfbase.pdfmetrics import stringWidth

def draw_text_wrapped(canvas, texto, x, y, largura_max, altura_linha=12, fonte="Helvetica", tamanho=8):

    if not texto:
        return

    canvas.setFont(fonte, tamanho)

    palavras = texto.split(" ")
    linha_atual = ""
    y_atual = y

    for palavra in palavras:
        teste_linha = linha_atual + palavra + " "
        largura = stringWidth(teste_linha, fonte, tamanho)

        if largura <= largura_max:
            linha_atual = teste_linha
        else:
            canvas.drawString(x, y_atual, linha_atual)
            y_atual -= altura_linha
            linha_atual = palavra + " "

    if linha_atual:
        canvas.drawString(x, y_atual, linha_atual)

#------------------------------

def gerar_pdf_aih(dados, saida):

    modelo = "Modelo AIH.pdf"   # nome do seu arquivo modelo

    reader = PdfReader(modelo)
    writer = PdfWriter()

    # cria camada para escrever dados
    temp = "temp_aih.pdf"

    c = canvas.Canvas(temp, pagesize=A4)

    # =============================
    # EXEMPLO DE POSIÇÕES
    # =============================

    #---------CABEÇARIO--------

    c.drawString(35, 745, "IRMANDADE DA SANTA CASA DE MISERICÓRDIA DE PORTO FELIZ")
    c.drawString(474, 745, "2  0   7   9   9  2  5")
    c.drawString(35, 720, "IRMANDADE DA SANTA CASA DE MISERICÓRDIA DE PORTO FELIZ")
    c.drawString(474, 720, "2  0   7   9   9  2  5")

    #---------INDENTIFICAÇÃO DO PACIENTE--------

    c.drawString(35, 678, dados["nome_paciente"] or "")
    c.drawString(468, 680, dados["prontuario"] or "")
    desenhar_campos(c, dados["cns"], 42, 655, 17)
    c.drawString(322, 655, formatar_data(dados["data_nascimento"]))
    marcar_opcao(c, dados["sexo"], "M", 420, 655)
    marcar_opcao(c, dados["sexo"], "F", 470, 655)
    c.drawString(35, 632, dados["nome_mae"] or "")
    desenhar_campos(c, dados["telefone1"], 417, 632)
    desenhar_campos(c, dados["telefone2"], 417, 608)
    c.drawString(35, 609, dados["responsavel"] or "")
    c.drawString(35, 590, dados["endereco"] or "")
    c.drawString(35, 565, dados["municipio"] or "")
    c.drawString(510, 655, dados["raca_cor"] or "")
    c.drawString(370, 565, dados["ibge"] or "")
    c.drawString(450, 565, dados["uf"] or "")
    desenhar_campos_cep(c, dados["cep"], 482, 565)

    #---------JUSTIFICATIVA--------

    draw_text_wrapped(
    canvas=c,
    texto=dados["sinais"],
    x=35,
    y=530,
    largura_max=520,
    altura_linha=11,
    fonte="Helvetica",
    tamanho=10
)
    draw_text_wrapped(
    canvas=c,
    texto=dados["condicoes"],
    x=35,
    y=420,
    largura_max=520,
    altura_linha=11,
    fonte="Helvetica",
    tamanho=10
)
    draw_text_wrapped(
    canvas=c,
    texto=dados["provas"],
    x=35,
    y=365,
    largura_max=520,
    altura_linha=11,
    fonte="Helvetica",
    tamanho=10
)    
    c.drawString(275, 315, dados["cid_principal"] or "")
    c.drawString(380, 315, dados["cid_secundario"] or "")
    c.drawString(480, 315, dados["cid_associado"] or "")


    #---------INDENTIFICAÇÃO DO PROCEDIMENTO--------

    c.drawString(35, 250, dados["clinica"] or "")
    c.drawString(135, 250, dados["carater"] or "")
    c.drawString(35, 315, dados["diagnostico"] or "")
    c.drawString(35, 275, dados["descricao_procedimento"] or "")
    c.drawString(405, 275, dados["codigo_procedimento"] or "")
    c.drawString(306, 228, formatar_data(dados["data_solicitacao"]))
    c.drawString(45, 40, formatar_data(dados["data_autorizacao"]))
    c.drawString(35, 228, dados["nome_prof"] or "")
    desenhar_campos(c, dados["numero_doc_prof"], 340, 250)
    c.drawString(300, 250, dados["doc_prof"] or "")

    #---------CAUSAS EXTERNAS--------

    desenhar_campos(c, dados["cnpj_seguradora"], 182, 190)
    desenhar_campos(c, dados["cnpj_empresa"], 182, 165)
    c.drawString(425, 190, dados["numero_bilhete"] or "")
    c.drawString(425, 165, dados["cnae"] or "")
    c.drawString(515, 165, dados["cbor"] or "")
    c.drawString(515, 190, dados["serie"] or "")


    #---------Autorização--------

    c.drawString(400, 90, dados["numero_autorizacao"] or "")
    c.drawString(35, 100, dados["nome_autorizador"] or "")
    c.drawString(300, 100, dados["orgao_emissor"] or "") 
    desenhar_campos(c, dados["numero_doc_autorizador"], 157, 75) 
    c.drawString(35, 75, dados["doc_autorizador"] or "")
    

    

    c.save()

    # mistura modelo + texto
    overlay = PdfReader(temp)

    page = reader.pages[0]
    page.merge_page(overlay.pages[0])

    writer.add_page(page)

    with open(saida, "wb") as f:
        writer.write(f)

    os.remove(temp)




# ---------------- PDF ----------------

def extrair_texto_pdf(caminho):
    texto = ""
    try:
        with pdfplumber.open(caminho) as pdf:
            for pagina in pdf.pages:
                texto += pagina.extract_text() or ""
    except Exception as exc:
        app.logger.warning("Falha ao extrair texto do PDF %s: %s", caminho, exc)
    return texto


# ---------------- LOG ----------------

def registrar_log_aceite(arquivo, usuario, ip):

    log_file = "logs_aceite.csv"
    data_hora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    arquivo_existe = os.path.exists(log_file)

    with open(log_file, "a", newline="", encoding="utf-8") as csvfile:

        writer = csv.writer(csvfile)

        if not arquivo_existe:
            writer.writerow(["arquivo", "usuario", "ip", "data_hora"])

        writer.writerow([arquivo, usuario, ip, data_hora])


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        login = request.form.get("login")
        senha = request.form.get("senha")

        conn = conectar_db()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT login, senha_hash, perfil FROM usuarios WHERE login = ?",
            (login,),
        )
        usuario = cursor.fetchone()
        conn.close()

        if usuario and verificar_senha(senha or "", usuario["senha_hash"]):
            session["usuario"] = usuario["login"]
            session["perfil"] = usuario["perfil"]        
            return redirect(url_for("upload_aih"))

        flash("Usuário ou senha inválidos")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- ADMIN USUÁRIOS ----------------

@app.route("/admin/usuarios", methods=["GET", "POST"])
def admin_usuarios():

    if "usuario" not in session:
        return redirect(url_for("login"))

    if session.get("perfil") != "ADM":
        flash("Acesso restrito ao administrador.")
        return redirect(url_for("upload_aih"))

    if request.method == "POST":
        novo_login = (request.form.get("login") or "").strip()
        nova_senha = request.form.get("senha") or ""
        perfil = (request.form.get("perfil") or "").strip().upper()

        perfis_validos = {"ADM", "MEDICO", "SECRETARIA"}

        if not novo_login or not nova_senha:
            flash("Informe login e senha para cadastrar o usuário.")
            return redirect(url_for("admin_usuarios"))

        if perfil not in perfis_validos:
            flash("Perfil inválido. Escolha ADM, MEDICO ou SECRETARIA.")
            return redirect(url_for("admin_usuarios"))

        conn = conectar_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM usuarios WHERE login = ?", (novo_login,))
        existente = cursor.fetchone()

        if existente:
            conn.close()
            flash("Já existe um usuário com esse login.")
            return redirect(url_for("admin_usuarios"))

        cursor.execute(
            """
            INSERT INTO usuarios (login, senha_hash, perfil)
            VALUES (?, ?, ?)
            """,
            (novo_login, gerar_hash_senha(nova_senha), perfil),
        )

        conn.commit()
        conn.close()

        flash("Usuário cadastrado com sucesso.")
        return redirect(url_for("admin_usuarios"))

    conn = conectar_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, login, perfil FROM usuarios ORDER BY login ASC")
    usuarios = cursor.fetchall()
    conn.close()

    return render_template("admin_usuarios.html", usuarios=usuarios)

# ---------------- NOVA AIH ----------------
@app.route("/nova_aih", methods=["GET","POST"])
@login_required
def nova_aih():

    if request.method == "POST":

        # -------- SALVAR PDF --------
        file = request.files.get("file")
        necessita_apa = request.form.get("apa")

        arquivo_pdf = None

        # Garante valor padrão
        if necessita_apa not in ["SIM", "NAO"]:
            necessita_apa = "NAO"

        if file and file.filename != "" and allowed_file(file.filename):

            os.makedirs(UPLOAD_FOLDER, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

            arquivo_pdf = f"aih_{timestamp}_APA_{necessita_apa}.pdf"

            caminho = os.path.join(UPLOAD_FOLDER, arquivo_pdf)

            file.save(caminho)

# -------- SALVAR BANCO --------
        conn = conectar_db()
        cursor = conn.cursor()

        cursor.execute("""
INSERT INTO aih (
    nome_paciente, prontuario, cns, data_nascimento, sexo,
    raca_cor, etnia, nome_mae, telefone1, telefone2,
    responsavel, endereco, municipio, ibge, uf, cep,

    sinais, condicoes, provas, diagnostico,
    cid_principal, cid_secundario, cid_associado,

    descricao_procedimento, codigo_procedimento, clinica, carater,
    doc_prof, numero_doc_prof, nome_prof, data_solicitacao,

    tipo_acidente, cnpj_seguradora, cnpj_empresa, numero_bilhete,
    cnae, serie, cbor, vinculo_empresa,

    nome_autorizador, orgao_emissor, doc_autorizador,
    numero_doc_autorizador, data_autorizacao, numero_autorizacao,

    arquivo_pdf, necessita_apa
)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
""", (

    request.form.get("nome_paciente"),
    request.form.get("prontuario"),
    request.form.get("cns"),
    request.form.get("data_nascimento"),
    request.form.get("sexo"),

    request.form.get("raca_cor"),
    request.form.get("etnia"),
    request.form.get("nome_mae"),
    request.form.get("telefone1"),
    request.form.get("telefone2"),

    request.form.get("responsavel"),
    request.form.get("endereco"),
    request.form.get("municipio"),
    request.form.get("ibge"),
    request.form.get("uf"),
    request.form.get("cep"),

    request.form.get("sinais"),
    request.form.get("condicoes"),
    request.form.get("provas"),
    request.form.get("diagnostico"),

    request.form.get("cid_principal"),
    request.form.get("cid_secundario"),
    request.form.get("cid_associado"),

    request.form.get("descricao_procedimento"),
    request.form.get("codigo_procedimento"),
    request.form.get("clinica"),
    request.form.get("carater"),

    request.form.get("doc_prof"),
    request.form.get("numero_doc_prof"),
    request.form.get("nome_prof"),
    request.form.get("data_solicitacao"),

    request.form.get("tipo_acidente"),
    request.form.get("cnpj_seguradora"),
    request.form.get("cnpj_empresa"),
    request.form.get("numero_bilhete"),

    request.form.get("cnae"),
    request.form.get("serie"),
    request.form.get("cbor"),
    request.form.get("vinculo_empresa"),

    request.form.get("nome_autorizador"),
    request.form.get("orgao_emissor"),
    request.form.get("doc_autorizador"),
    request.form.get("numero_doc_autorizador"),
    request.form.get("data_autorizacao"),
    request.form.get("numero_autorizacao"),

    arquivo_pdf,
    necessita_apa
))


        conn.commit()
        conn.close()

        flash("AIH salva com sucesso!")
        return redirect("/lista")

    return render_template(
    "nova_aih.html",
    hoje=datetime.now().strftime("%Y-%m-%d")
)


#-------------------ROTA AIH----------------

@app.route("/aih")
@login_required
def listar_aih_completa():

    conn = conectar_db()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM aih ORDER BY id DESC")
    lista = cursor.fetchall()

    conn.close()

    return render_template("aih_lista.html", lista=lista)




# ---------------- UPLOAD PDF ----------------

@app.route("/", methods=["GET", "POST"])
@login_required
def upload_aih():

    if request.method == "POST":

        file = request.files.get("file")
        apa = request.form.get("apa")

        if not file or file.filename == "":
            flash("Selecione um arquivo")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("Apenas PDF permitido")
            return redirect(request.url)

        if apa not in ["SIM", "NAO"]:
            flash("Informe se necessita de APA")
            return redirect(request.url)

        os.makedirs(UPLOAD_FOLDER, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        nome_arquivo = f"aih_{timestamp}_APA_{apa}.pdf"

        caminho = os.path.join(UPLOAD_FOLDER, nome_arquivo)
        file.save(caminho)

        flash("AIH enviada com sucesso")

    return render_template("upload.html")


# ---------------- LISTAGEM ----------------

@app.route("/lista")
@login_required
def listar_aih():

    conn = conectar_db()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT * FROM aih
        ORDER BY id DESC
    """)

    dados = cursor.fetchall()
    conn.close()

    lista = []

    for item in dados:

        # -------- APA --------
        apa = "Sim" if item["necessita_apa"] == "SIM" else "Não"

        # -------- STATUS --------
        status = item["status"] or "Pendente"

        # -------- DATA BASE (BANCO AGORA) --------
        if item["data_solicitacao"]:
                data_hora = datetime.strptime(
                    item["data_solicitacao"],
                    "%Y-%m-%d"
                        ).strftime("%d/%m/%Y")
        else:
                data_hora = "-"

        # -------- DIAS NO SISTEMA --------
        dias_sistema = "-"

        if item["data_solicitacao"]:

            try:
                data_envio = datetime.strptime(
                    item["data_solicitacao"],
                    "%Y-%m-%d"
                )

                dias = (datetime.now() - data_envio).days

                if status == "Pendente":
                    dias_sistema = f"{dias} dia(s)"
                else:
                    dias_sistema = "✔ Finalizada"

            except ValueError:
                data_hora = "-"

        lista.append({
            "arquivo": item["arquivo_pdf"],
            "paciente": item["nome_paciente"],
            "id": item["id"],
            "apa": apa,
            "status": status,
            "data_hora": data_hora,
            "dias": dias_sistema
        })

    return render_template("lista.html", lista=lista)


#----------------LISTA CADASTROS----------------

@app.route("/listar_cadastros")
@login_required
def listar_cadastros():

    conn = conectar_db()
    cursor = conn.cursor()

    cursor.execute("SELECT id, nome_paciente, prontuario FROM aih ORDER BY id DESC")
    dados = cursor.fetchall()

    conn.close()

    return render_template("listar_cadastros.html", dados=dados)

#-----------------VER DETALHES DA AIH-----------------

@app.route("/ver_aih/<int:id>")
@login_required
def ver_aih(id):

    conn = conectar_db()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM aih WHERE id = ?", (id,))
    dados = cursor.fetchone()

    conn.close()

    return render_template("ver_aih.html", dados=dados)



# ---------------- ACEITAR ----------------

@app.route("/aceitar/<int:id>", methods=["POST"])
@login_required
def aceitar_aih(id):

    if session.get("perfil") != "SECRETARIA":
        return redirect(url_for("listar_aih"))

    conn = conectar_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE aih
        SET status = 'Aceita',
            usuario_aprovacao = ?,
            data_aprovacao = ?
        WHERE id = ?
    """, (
        session.get("usuario"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        id
    ))

    conn.commit()
    conn.close()

    return redirect(url_for("listar_aih"))


# ---------------- REPROVAR ----------------

@app.route("/reprovar/<int:id>", methods=["POST"])
@login_required
def reprovar_aih(id):

    if session.get("perfil") != "SECRETARIA":
        return redirect(url_for("listar_aih"))

    conn = conectar_db()
    cursor = conn.cursor()

    cursor.execute("""
        UPDATE aih
        SET status = 'Reprovada',
            usuario_reprovacao = ?,
            data_reprovacao = ?
        WHERE id = ?
    """, (
        session.get("usuario"),
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        id
    ))

    conn.commit()
    conn.close()

    return redirect(url_for("listar_aih"))


# ---------------- SERVIR PDF ----------------

@app.route("/uploads/<filename>")
@login_required
def ver_pdf(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


# ---------------- IMPRIMIR PDF ----------------

@app.route("/imprimir/<int:id>")
@login_required
def imprimir_aih(id):

    conn = conectar_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM aih WHERE id = ?", (id,))
    dados = cursor.fetchone()

    conn.close()

    if not dados:
        return "AIH não encontrada"

    dados_dict = dict(dados)

    saida = f"uploads/aih_impressa_{id}.pdf"

    gerar_pdf_aih(dados_dict, saida)

    return send_from_directory("uploads", f"aih_impressa_{id}.pdf")

# ---------------- START ----------------

if __name__ == "__main__":
    garantir_colunas_status()
    app.run(host="0.0.0.0", port=5000)


