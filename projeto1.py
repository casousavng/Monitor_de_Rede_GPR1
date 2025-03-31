import subprocess
import re
import sqlite3
import io
import os
import datetime
import requests
from flask import Flask, request, redirect, send_file, url_for, session, render_template
from functools import wraps
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
from dotenv import load_dotenv

DB_PATH = "network_devices.db" # Nome da base de dados

# Forçar carregamento do arquivo .env
dotenv_loaded = load_dotenv()

# Pesquisa as variáveis username e password no arquivo .env
USERNAME = os.getenv("APP_USERNAME")
PASSWORD = os.getenv("APP_PASSWORD")

# Ajustar conforme a rede a pesquisar ----------------------------------------------

# rede ispgaya projetos (menos IP's mais rapida a pesquisa)
network = "192.168.6.0/24" 

#rede ispgaya alunos 
#network = "10.103.102.22/24"

#rede caseira (para testes)
#network = "192.168.1.0/24" 

# ----------------------------------------------------------------------------------

# Configurações do Telegram

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# ----------------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = "secret_key"

# Criar BD
def setup_database():
    conn = sqlite3.connect(DB_PATH) # Conectar à base de dados
    cursor = conn.cursor() # Criar um cursor

    # Criar tabelas na BD (devices, history e logs)

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        mac TEXT NOT NULL UNIQUE,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        mac TEXT NOT NULL,
        ip TEXT NOT NULL,
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        action TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    # Guardar as alterações e fechar a conexão
    conn.commit()
    conn.close()
    print("Base de Dados criada com sucesso!")

# Enviar mensagem para o Telegram
def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    response = requests.post(url, data=data)

    # Verificar se a mensagem foi enviada com sucesso apenas para fins de depuração
    if response.status_code != 200:
        print("Erro ao enviar mensagem para o Telegram:", response.text)
    else:
        print("Mensagem enviada com sucesso para o Telegram!")

# Middleware para exigir login para aceder as páginas
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrap

# Página de login com autenticação de utilizador e password
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == USERNAME and password == PASSWORD:
            devices = scan_network()  # Scan inicial da rede após login
            save_to_db(devices) # Salvar dispositivos encontrados na BD
            session["logged_in"] = True
            return redirect(url_for("devices"))

    return render_template("login.html")

# Logout do utilizador e limpar a sessão
@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.clear() # Limpar a sessão
    return redirect(url_for("login"))

# Página de dispositivos conectados
@app.route("/devices")
@login_required
def devices():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    devices = cursor.fetchall()
    conn.close()
    return render_template("devices.html", devices=devices)

# Página de logs com pesquisa por IP ou MAC Address e paginação
@app.route("/logs")
@login_required
def logs():
    search_query = request.args.get("search", "")
    page = int(request.args.get("page", 1))
    per_page = 10  # Número de logs por página

    # Garantir que a página não seja menor que 1
    if page < 1:
        page = 1

    offset = (page - 1) * per_page

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if search_query:
        cursor.execute("SELECT COUNT(*) FROM logs WHERE action LIKE ?", ('%' + search_query + '%',))
    else:
        cursor.execute("SELECT COUNT(*) FROM logs")

    # Calcular o número total de logs e páginas
    total_logs = cursor.fetchone()[0]
    total_pages = (total_logs // per_page) + (1 if total_logs % per_page > 0 else 0)

    # Se a página solicitada for maior que o número de páginas, ajustar para a última página
    if page > total_pages:
        page = total_pages

    # Obter os logs com base na pesquisa e na paginação
    if search_query:
        cursor.execute("SELECT * FROM logs WHERE action LIKE ? ORDER BY timestamp DESC LIMIT ? OFFSET ?", 
                       ('%' + search_query + '%', per_page, offset))
    else:
        cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT ? OFFSET ?", (per_page, offset))

    logs = cursor.fetchall()
    conn.close()

    # Desabilitar os botões se estivermos na primeira ou última página
    prev_disabled = page == 1
    next_disabled = page == total_pages or logs == []

    return render_template("logs.html", logs=logs, search_query=search_query, page=page, prev_disabled=prev_disabled, next_disabled=next_disabled)

# Página de histórico com gráfico
@app.route("/history")
@login_required
def history():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT date(last_seen), COUNT(DISTINCT mac) FROM devices GROUP BY date(last_seen) ORDER BY date(last_seen) DESC LIMIT 10")
    history = cursor.fetchall()
    conn.close()
    # Obter as datas e contagens para o gráfico
    dates = [row[0] for row in history]
    counts = [row[1] for row in history]
    return render_template("history.html", dates=dates, counts=counts)

# Scan via linha de comandos com NMAP
def scan_network():
    send_telegram_message("🔍 *Iniciando varredura da rede...*")
    cmd = f"nmap -sn {network}"  # -sn para ping scan (sem varredura de portas)
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True) # Executar o comando e capturar a saída

    devices = [] # Lista para armazenar os dispositivos encontrados
    ip = None
    for line in result.stdout.split("\n"):
        if "Nmap scan report" in line:
            ip = re.findall(r'\d+\.\d+\.\d+\.\d+', line)[0]
        if "MAC Address" in line:
            mac = line.split()[2]
            devices.append({"IP": ip, "MAC": mac})

    return devices

# Gravar dispositivos e logs na BD
def save_to_db(devices):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Verificar se o dispositivo já existe na BD, se sim, atualizar a última vez visto, caso contrário, inserir
    for device in devices:
        cursor.execute("SELECT * FROM devices WHERE mac=?", (device["MAC"],))
        existing_device = cursor.fetchone()

        if existing_device:
            cursor.execute("UPDATE devices SET last_seen=CURRENT_TIMESTAMP WHERE mac=?", (device["MAC"],))
        else:
            cursor.execute("INSERT INTO devices (ip, mac) VALUES (?, ?)", (device["IP"], device["MAC"]))
            cursor.execute("INSERT INTO history (ip, mac) VALUES (?, ?)", (device["IP"], device["MAC"]))

            # Enviar alerta para o Telegram
            message = f"🔍 *Novo Dispositivo Detectado!*\n📡 IP: `{device['IP']}`\n🔗 MAC: `{device['MAC']}`"
            print(message)
            send_telegram_message(message)

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute("INSERT INTO logs (action, timestamp) VALUES (?, ?)", 
                       (f"IP: {device['IP']}  |   MAC: {device['MAC']}", timestamp))

    conn.commit()
    conn.close()

# Gerar Relatórios em PDF ----------------------------------------------   

# Função para dividir texto em múltiplas linhas, se necessário
def simpleSplit(text, font, font_size, max_width):
    # Função que quebra o texto em várias linhas
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    lines = []
    words = text.split(' ')
    current_line = ''
    pdf = canvas.Canvas(io.BytesIO(), pagesize=letter)
    pdf.setFont(font, font_size)
    for word in words:
        test_line = current_line + ' ' + word if current_line else word
        width, _ = pdf.stringWidth(test_line, font, font_size), font_size
        if width < max_width:
            current_line = test_line
        else:
            lines.append(current_line)
            current_line = word
    if current_line:
        lines.append(current_line)
    return lines

# Relatório de Dispositivos (PDF)
@app.route("/generate_devices_report")
@login_required
def generate_devices_report():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    devices = cursor.fetchall()
    conn.close()

    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=letter)
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(200, 750, "Relatório de Dispositivos Conectados")
    
    pdf.setFont("Helvetica", 11)
    y = 720
    pdf.drawString(50, y, "ID")
    pdf.drawString(100, y, "IP")
    pdf.drawString(200, y, "MAC")
    pdf.drawString(350, y, "Última Vez Visto")
    
    y -= 20
    for device in devices:
        pdf.drawString(50, y, str(device[0]))
        pdf.drawString(100, y, device[1])
        pdf.drawString(200, y, device[2])
        pdf.drawString(350, y, device[3])
        y -= 20

    pdf.save()
    output.seek(0)
    
    return send_file(output, as_attachment=True, download_name="dispositivos_conectados.pdf", mimetype="application/pdf")

# Relatório de Logs (PDF)
@app.route("/generate_logs_report")
@login_required
def generate_logs_report():
    search_query = request.args.get("search", "")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    if search_query:
        cursor.execute("SELECT * FROM logs WHERE action LIKE ?", ('%' + search_query + '%',))
    else:
        cursor.execute("SELECT * FROM logs")

    logs = cursor.fetchall()
    conn.close()

    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=letter)
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(220, 750, "Relatório de Logs")
    
    pdf.setFont("Helvetica", 11)
    y = 720
    pdf.drawString(50, y, "IP e MAC Address")
    pdf.drawString(300, y, "Timestamp")
    
    y -= 20
    page_height = 750  # Posição do topo da página
    bottom_margin = 40  # Margem inferior
    line_height = 15  # Altura da linha de cada item
    
    for log in logs:
        # Ajustando a impressão do IP e MAC para garantir a linha não se sobreponha
        text = simpleSplit(log[1], "Helvetica", 12, 250)  # Ajusta o texto para não estourar a margem
        for line in text:
            pdf.drawString(50, y, line)
            y -= line_height
            if y < bottom_margin:  # Se a posição y for menor que a margem inferior, cria uma nova página
                pdf.showPage()  # Cria uma nova página
                pdf.setFont("Helvetica-Bold", 14)
                pdf.drawString(220, 750, "Relatório de Logs")
                pdf.setFont("Helvetica", 11)
                y = 720
                pdf.drawString(50, y, "IP e MAC Address")
                pdf.drawString(300, y, "Timestamp")
                y -= 20  # Espaçamento após o cabeçalho
        
        # Adicionando o Timestamp na mesma linha, mas ajustando a posição
        pdf.drawString(300, y + (line_height * len(text)), log[2])
        y -= 20
        
        if y < bottom_margin:  # Se a posição y for menor que a margem inferior, cria uma nova página
            pdf.showPage()  # Cria uma nova página
            pdf.setFont("Helvetica-Bold", 14)
            pdf.drawString(220, 750, "Relatório de Logs")
            pdf.setFont("Helvetica", 11)
            y = 720
            pdf.drawString(50, y, "IP e MAC Address")
            pdf.drawString(300, y, "Timestamp")
            y -= 20  # Espaçamento após o cabeçalho

    pdf.save()
    output.seek(0)
    
    return send_file(output, as_attachment=True, download_name="relatorio_logs.pdf", mimetype="application/pdf")

# Relatório de Histórico de Conexões (PDF)
@app.route("/generate_history_report")
@login_required
def generate_history_report():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT date(last_seen), COUNT(DISTINCT mac) FROM devices GROUP BY date(last_seen) ORDER BY date(last_seen) DESC LIMIT 10")
    history = cursor.fetchall()
    conn.close()

    output = io.BytesIO()
    pdf = canvas.Canvas(output, pagesize=letter)
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(180, 750, "Relatório de Histórico de Conexões")
    
    pdf.setFont("Helvetica", 11)
    y = 720
    pdf.drawString(50, y, "Data")
    pdf.drawString(200, y, "Dispositivos Conectados")
    
    y -= 20
    for row in history:
        pdf.drawString(50, y, row[0])
        pdf.drawString(200, y, str(row[1]))
        y -= 20

    pdf.save()
    output.seek(0)
    
    return send_file(output, as_attachment=True, download_name="historico_conexoes.pdf", mimetype="application/pdf")

# Relatório Completo (PDF)
@app.route("/generate_full_report")
@login_required
def generate_full_report():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC")
    devices = cursor.fetchall()

    cursor.execute("SELECT * FROM logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()

    conn.close()

    # Criando PDF
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Relatório de dispositivos
    c.drawString(100, height - 100, "Relatório de Dispositivos Conectados")
    y_position = height - 120
    for device in devices:
        c.drawString(100, y_position, f"ID: {device[0]} | IP: {device[1]} | MAC: {device[2]} | Última vez visto: {device[3]}")
        y_position -= 20
    
    c.showPage()
    
    # Relatório de logs
    c.drawString(100, height - 100, "Relatório de Logs")
    y_position = height - 120
    for log in logs:
        c.drawString(100, y_position, f"{log[1]} | Timestamp: {log[2]}")
        y_position -= 20

    c.save()
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="relatorio_completo.pdf", mimetype="application/pdf")

# ----------------------------------------------    

if __name__ == "__main__":

    send_telegram_message("🚀 Programa Monitor de Rede Iniciado!")

    if not os.path.exists(DB_PATH):
        setup_database()
    else:
        print("Base de Dados já existe!")
    
    # ativar a depuração para testes alterando debug=True para poder ver os erros e updates rapido
    app.run(host="0.0.0.0", port=5654, debug=False)
    #app.run(host="192.168.1.193", port=5654, debug=False) # Para testes em casa