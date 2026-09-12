from flask import Flask, request, jsonify, render_template_string
from urllib.parse import urlparse
import re
import ipaddress
from datetime import datetime, timezone, timedelta
import json
import os
import html as html_lib
from urllib.request import Request, urlopen
from urllib.parse import quote
import xml.etree.ElementTree as ET

app = Flask(__name__)


# ==========================================================
# IAFOX - MOTOR DE SEGURANÇA
# ==========================================================

def calcular_nivel(pontos):
    """
    Converte a pontuação interna para uma escala de 0 a 5.
    """

    if pontos <= 10:
        return 0

    elif pontos <= 25:
        return 1

    elif pontos <= 40:
        return 2

    elif pontos <= 60:
        return 3

    elif pontos <= 80:
        return 4

    else:
        return 5


def analisar_link(link):

    pontos = 0
    motivos = []

    link = link.strip()

    if not link:
        return {
            "nivel": 0,
            "status": "SEM LINK",
            "motivos": ["Digite um link para analisar."]
        }

    # ------------------------------------------------------
    # Adiciona protocolo caso o usuário não coloque
    # ------------------------------------------------------

    url_original = link

    if not re.match(r"^https?://", link, re.IGNORECASE):
        link = "https://" + link

    try:
        parsed = urlparse(link)
    except Exception:
        return {
            "nivel": 5,
            "status": "PERIGOSO",
            "motivos": ["Não foi possível interpretar esse link."]
        }

    dominio = parsed.hostname

    if not dominio:
        return {
            "nivel": 5,
            "status": "PERIGOSO",
            "motivos": ["O endereço não possui um domínio válido."]
        }

    dominio = dominio.lower()

    # ------------------------------------------------------
    # HTTPS
    # ------------------------------------------------------

    if parsed.scheme.lower() != "https":
        pontos += 15
        motivos.append("O site não utiliza HTTPS.")

    # ------------------------------------------------------
    # IP diretamente no link
    # ------------------------------------------------------

    try:
        ipaddress.ip_address(dominio)

        pontos += 35
        motivos.append(
            "O endereço usa um IP diretamente em vez de um domínio."
        )

    except ValueError:
        pass

    # ------------------------------------------------------
    # Punycode / caracteres internacionais
    # ------------------------------------------------------

    if "xn--" in dominio:
        pontos += 30
        motivos.append(
            "O domínio utiliza Punycode, algo que pode ser usado em golpes de falsificação."
        )

    # ------------------------------------------------------
    # Encurtadores
    # ------------------------------------------------------

    encurtadores = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "cutt.ly",
        "shorturl.at"
    ]

    if dominio in encurtadores:
        pontos += 20
        motivos.append(
            "O link utiliza um serviço de encurtamento."
        )

    # ------------------------------------------------------
    # Palavras suspeitas no domínio
    # ------------------------------------------------------

    palavras_suspeitas = [
        "login",
        "verify",
        "verification",
        "secure",
        "security",
        "update",
        "confirm",
        "account",
        "password",
        "wallet",
        "bonus",
        "premio",
        "premios",
        "pix",
        "banco",
        "bank",
        "support",
        "suporte",
        "cliente",
        "seguro",
        "urgente",
        "ganhe",
        "ganhar",
        "free",
        "gift",
        "reward"
    ]

    encontradas = []

    for palavra in palavras_suspeitas:
        if palavra in dominio:
            encontradas.append(palavra)

    if encontradas:
        pontos += min(len(encontradas) * 8, 25)

        motivos.append(
            "O domínio contém termos frequentemente utilizados em páginas falsas: "
            + ", ".join(encontradas)
        )

    # ------------------------------------------------------
    # Domínio muito grande
    # ------------------------------------------------------

    if len(dominio) > 45:
        pontos += 10
        motivos.append(
            "O domínio possui um tamanho incomum."
        )

    # ------------------------------------------------------
    # Muitos subdomínios
    # ------------------------------------------------------

    partes = dominio.split(".")

    if len(partes) >= 5:
        pontos += 20
        motivos.append(
            "O endereço possui muitos níveis de subdomínio."
        )

    # ------------------------------------------------------
    # Muitos números
    # ------------------------------------------------------

    quantidade_numeros = sum(c.isdigit() for c in dominio)

    if quantidade_numeros >= 5:
        pontos += 10
        motivos.append(
            "O domínio possui uma quantidade incomum de números."
        )

    # ------------------------------------------------------
    # Caracteres estranhos
    # ------------------------------------------------------

    if "_" in dominio:
        pontos += 15
        motivos.append(
            "O domínio contém caracteres incomuns."
        )

    # ------------------------------------------------------
    # URLs muito grandes
    # ------------------------------------------------------

    if len(url_original) > 180:
        pontos += 15
        motivos.append(
            "O link é muito longo e possui muitos caracteres."
        )

    # ------------------------------------------------------
    # Palavras perigosas na URL inteira
    # ------------------------------------------------------

    url_lower = url_original.lower()

    termos_perigosos = [
        "verify-account",
        "verify-account-now",
        "confirm-account",
        "login-confirm",
        "password-reset",
        "free-money",
        "free-prize",
        "pix-gratis",
        "premio-gratis",
        "ganhe-dinheiro",
        "cartao-bloqueado",
        "conta-bloqueada"
    ]

    encontrados_url = []

    for termo in termos_perigosos:
        if termo in url_lower:
            encontrados_url.append(termo)

    if encontrados_url:
        pontos += 30

        motivos.append(
            "A URL contém padrões comuns em campanhas de phishing/golpes."
        )

    # ------------------------------------------------------
    # Muitos parâmetros
    # ------------------------------------------------------

    if parsed.query:
        quantidade_parametros = len(parsed.query.split("&"))

        if quantidade_parametros >= 6:
            pontos += 10
            motivos.append(
                "O link possui muitos parâmetros."
            )

    # ------------------------------------------------------
    # Limita pontos
    # ------------------------------------------------------

    pontos = min(pontos, 100)

    nivel = calcular_nivel(pontos)

    # ------------------------------------------------------
    # Status
    # ------------------------------------------------------

    if nivel == 0:
        status = "MUITO SEGURO"

    elif nivel == 1:
        status = "BAIXO RISCO"

    elif nivel == 2:
        status = "ATENÇÃO"

    elif nivel == 3:
        status = "RISCO MODERADO"

    elif nivel == 4:
        status = "ALTO RISCO"

    else:
        status = "PERIGOSO"

    if not motivos:
        motivos.append(
            "Nenhum comportamento suspeito foi identificado pela análise básica."
        )

    return {
        "nivel": nivel,
        "pontos": pontos,
        "status": status,
        "dominio": dominio,
        "motivos": motivos
    }


# ==========================================================
# ANALISADOR DE MENSAGENS
# ==========================================================

def analisar_mensagem(mensagem):

    mensagem_lower = mensagem.lower()

    pontos = 0
    motivos = []

    # ------------------------------------------------------
    # Urgência
    # ------------------------------------------------------

    urgencia = [
        "urgente",
        "imediatamente",
        "agora",
        "última chance",
        "ultima chance",
        "prazo",
        "bloqueada",
        "bloqueado",
        "será bloqueada",
        "sera bloqueada"
    ]

    encontrados = [x for x in urgencia if x in mensagem_lower]

    if encontrados:
        pontos += 15
        motivos.append(
            "A mensagem tenta criar sensação de urgência."
        )

    # ------------------------------------------------------
    # Dinheiro
    # ------------------------------------------------------

    dinheiro = [
        "pix",
        "transferência",
        "transferencia",
        "dinheiro",
        "pagamento",
        "boleto",
        "prêmio",
        "premio",
        "ganhou",
        "ganhe",
        "reembolso"
    ]

    encontrados = [x for x in dinheiro if x in mensagem_lower]

    if encontrados:
        pontos += 15
        motivos.append(
            "A mensagem fala sobre dinheiro, pagamento ou prêmio."
        )

    # ------------------------------------------------------
    # Dados pessoais
    # ------------------------------------------------------

    dados = [
        "cpf",
        "senha",
        "código",
        "codigo",
        "token",
        "cartão",
        "cartao",
        "número do cartão",
        "numero do cartao",
        "dados pessoais"
    ]

    encontrados = [x for x in dados if x in mensagem_lower]

    if encontrados:
        pontos += 25
        motivos.append(
            "A mensagem solicita ou menciona informações pessoais/sensíveis."
        )

    # ------------------------------------------------------
    # Links
    # ------------------------------------------------------

    links = re.findall(
        r"(https?://[^\s]+|www\.[^\s]+)",
        mensagem_lower
    )

    if links:
        pontos += 15
        motivos.append(
            "A mensagem contém um link."
        )

        # Analisa o link encontrado
        resultado_link = analisar_link(links[0])

        if resultado_link["nivel"] >= 3:
            pontos += 25

            motivos.append(
                "O link presente na mensagem possui características suspeitas."
            )

    # ------------------------------------------------------
    # WhatsApp
    # ------------------------------------------------------

    termos_whatsapp = [
        "whatsapp",
        "grupo",
        "contato",
        "chama no whatsapp"
    ]

    if any(x in mensagem_lower for x in termos_whatsapp):
        pontos += 5

    # ------------------------------------------------------
    # Falso atendimento
    # ------------------------------------------------------

    atendimento = [
        "suporte",
        "banco",
        "atendente",
        "central",
        "segurança",
        "seguranca",
        "mercado livre",
        "nubank",
        "caixa",
        "itau",
        "itaú",
        "bradesco",
        "paypal"
    ]

    encontrados = [x for x in atendimento if x in mensagem_lower]

    if encontrados:
        pontos += 10

        motivos.append(
            "A mensagem se apresenta como atendimento, banco ou empresa."
        )

    # ------------------------------------------------------
    # Pressão psicológica
    # ------------------------------------------------------

    pressao = [
        "clique agora",
        "clique aqui",
        "acesse agora",
        "não ignore",
        "nao ignore",
        "evite bloqueio",
        "evite perder",
        "confirme agora",
        "confirme seus dados"
    ]

    encontrados = [x for x in pressao if x in mensagem_lower]

    if encontrados:
        pontos += 20

        motivos.append(
            "A mensagem tenta pressionar você a realizar uma ação."
        )

    # ------------------------------------------------------
    # Escala
    # ------------------------------------------------------

    pontos = min(pontos, 100)

    nivel = calcular_nivel(pontos)

    if nivel == 0:
        status = "MUITO SEGURO"

    elif nivel == 1:
        status = "BAIXO RISCO"

    elif nivel == 2:
        status = "ATENÇÃO"

    elif nivel == 3:
        status = "RISCO MODERADO"

    elif nivel == 4:
        status = "ALTO RISCO"

    else:
        status = "POSSÍVEL GOLPE"

    if not motivos:
        motivos.append(
            "Não encontrei padrões fortes de golpe nessa mensagem."
        )

    return {
        "nivel": nivel,
        "pontos": pontos,
        "status": status,
        "motivos": motivos
    }



# ==========================================================
# IAFOX - RADAR DE GOLPES / NOTÍCIAS
# ==========================================================

ARQUIVO_NOTICIAS = "iafox_noticias.json"
INTERVALO_ATUALIZACAO = timedelta(days=7)

NOTICIAS_PADRAO = [
    {
        "titulo": "Como reconhecer tentativas de phishing",
        "resumo": "Golpes podem usar mensagens urgentes, páginas falsas e pedidos de dados para enganar a vítima.",
        "prevencao": "Não clique em links desconhecidos. Acesse o serviço diretamente pelo aplicativo ou site oficial.",
        "fonte": "CERT.br",
        "link": "https://cartilha.cert.br/fasciculos/",
        "imagem": "",
        "data": datetime.now().strftime("%d/%m/%Y")
    }
]


def carregar_dados_noticias():
    try:
        if os.path.exists(ARQUIVO_NOTICIAS):
            with open(ARQUIVO_NOTICIAS, "r", encoding="utf-8") as arquivo:
                return json.load(arquivo)
    except Exception:
        pass

    return {
        "ultima_atualizacao": "",
        "noticias": NOTICIAS_PADRAO
    }


def salvar_dados_noticias(dados):
    try:
        with open(ARQUIVO_NOTICIAS, "w", encoding="utf-8") as arquivo:
            json.dump(dados, arquivo, ensure_ascii=False, indent=2)
    except Exception:
        pass


def buscar_imagem_artigo(url):
    """Tenta encontrar a imagem principal publicada pelo próprio artigo."""
    try:
        req = Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 IAFOX-Security/1.0"}
        )

        with urlopen(req, timeout=8) as resposta:
            pagina = resposta.read(300000).decode("utf-8", errors="ignore")

        padroes = [
            r'<meta[^>]+property=["\']og:image["\'][^>]+content=["\']([^"\']+)',
            r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+property=["\']og:image["\']'
        ]

        for padrao in padroes:
            resultado = re.search(padrao, pagina, re.IGNORECASE)
            if resultado:
                return html_lib.unescape(resultado.group(1))

    except Exception:
        pass

    return ""


def extrair_texto(elemento, nome):
    filho = elemento.find(nome)
    if filho is not None and filho.text:
        return filho.text.strip()

    return ""


def atualizar_noticias():
    """
    Busca notícias públicas sobre golpes/phishing.
    A função é chamada no máximo uma vez a cada 7 dias.
    """
    consultas = [
        "golpes internet phishing Brasil",
        "golpe WhatsApp fraude Pix Brasil",
        "cybersecurity scam Brazil"
    ]

    noticias = []

    for consulta in consultas:
        try:
            url_rss = (
                "https://news.google.com/rss/search?q="
                + quote(consulta)
                + "&hl=pt-BR&gl=BR&ceid=BR:pt-419"
            )

            req = Request(
                url_rss,
                headers={"User-Agent": "Mozilla/5.0 IAFOX-Security/1.0"}
            )

            with urlopen(req, timeout=12) as resposta:
                xml = resposta.read()

            raiz = ET.fromstring(xml)

            for item in raiz.findall("./channel/item")[:5]:
                titulo = extrair_texto(item, "title")
                link = extrair_texto(item, "link")
                data_publicacao = extrair_texto(item, "pubDate")

                fonte_elemento = item.find("source")
                fonte = (
                    fonte_elemento.text.strip()
                    if fonte_elemento is not None and fonte_elemento.text
                    else "Fonte pública"
                )

                if not titulo or not link:
                    continue

                imagem = buscar_imagem_artigo(link)

                noticia = {
                    "titulo": titulo,
                    "resumo": (
                        "Notícia recente encontrada pelo radar da IAFOX. "
                        "Abra a fonte para conferir todos os detalhes."
                    ),
                    "prevencao": (
                        "Não clique em links suspeitos, não forneça senhas "
                        "ou códigos e confirme a informação diretamente "
                        "no canal oficial da empresa."
                    ),
                    "fonte": fonte,
                    "link": link,
                    "imagem": imagem,
                    "data": data_publicacao or datetime.now().strftime("%d/%m/%Y")
                }

                # Evita repetir a mesma notícia.
                if not any(n["link"] == link for n in noticias):
                    noticias.append(noticia)

        except Exception as erro:
            print("IAFOX - erro ao buscar notícias:", erro)

    # Mantém as 10 notícias mais recentes encontradas.
    noticias = noticias[:10]

    if not noticias:
        return None

    agora = datetime.now(timezone.utc).isoformat()

    dados = {
        "ultima_atualizacao": agora,
        "noticias": noticias
    }

    salvar_dados_noticias(dados)
    return dados


def noticias_precisam_atualizar(dados):
    ultima = dados.get("ultima_atualizacao", "")

    if not ultima:
        return True

    try:
        data = datetime.fromisoformat(ultima)
        if data.tzinfo is None:
            data = data.replace(tzinfo=timezone.utc)

        return datetime.now(timezone.utc) - data >= INTERVALO_ATUALIZACAO

    except Exception:
        return True


DADOS_NOTICIAS = carregar_dados_noticias()


def obter_noticias():
    global DADOS_NOTICIAS

    # Se passaram 7 dias, tenta buscar notícias novas.
    if noticias_precisam_atualizar(DADOS_NOTICIAS):
        novas = atualizar_noticias()

        if novas:
            DADOS_NOTICIAS = novas

    return DADOS_NOTICIAS


@app.route("/noticias", methods=["GET"])
def noticias_api():
    dados = obter_noticias()

    return jsonify(dados)


@app.route("/atualizar-noticias", methods=["POST"])
def atualizar_noticias_api():
    global DADOS_NOTICIAS

    novas = atualizar_noticias()

    if novas:
        DADOS_NOTICIAS = novas

    return jsonify(DADOS_NOTICIAS)

# ==========================================================
# API
# ==========================================================

@app.route("/analisar-link", methods=["POST"])
def analisar_link_api():

    dados = request.get_json()

    link = dados.get("link", "")

    resultado = analisar_link(link)

    return jsonify(resultado)


@app.route("/analisar-mensagem", methods=["POST"])
def analisar_mensagem_api():

    dados = request.get_json()

    mensagem = dados.get("mensagem", "")

    resultado = analisar_mensagem(mensagem)

    return jsonify(resultado)


# ==========================================================
# INTERFACE
# ==========================================================

HTML = """
<!DOCTYPE html>

<html lang="pt-br">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>IAFOX Security</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    font-family: Arial, sans-serif;

    background:
        radial-gradient(circle at top, #351600, #080808 45%);

    color: white;

    min-height: 100vh;
}

.container {

    width: 95%;

    max-width: 900px;

    margin: auto;

    padding: 25px 0 50px;
}

header {

    text-align: center;

    padding: 25px 10px;
}

.logo {

    font-size: 55px;

}

h1 {

    color: #ff7900;

    font-size: 42px;

    margin: 5px 0;
}

.subtitle {

    color: #aaa;

    font-size: 16px;
}

.card {

    background: rgba(20,20,20,0.95);

    border: 1px solid #3a3a3a;

    border-radius: 18px;

    padding: 25px;

    margin-top: 20px;

    box-shadow:
        0 0 30px rgba(255,100,0,0.08);
}

.card h2 {

    margin-top: 0;

    color: #ff7900;
}

textarea,
input {

    width: 100%;

    background: #101010;

    border: 1px solid #444;

    color: white;

    border-radius: 12px;

    padding: 15px;

    font-size: 15px;

    outline: none;
}

textarea:focus,
input:focus {

    border-color: #ff7900;

    box-shadow:
        0 0 10px rgba(255,121,0,.2);
}

textarea {

    min-height: 130px;

    resize: vertical;
}

button {

    margin-top: 15px;

    width: 100%;

    border: none;

    border-radius: 12px;

    padding: 15px;

    background: #ff7900;

    color: black;

    font-weight: bold;

    font-size: 16px;

    cursor: pointer;
}

button:hover {

    background: #ff941f;
}

.resultado {

    display: none;

    margin-top: 20px;

    border-radius: 15px;

    padding: 20px;

    background: #111;
}

.nivel {

    font-size: 60px;

    font-weight: bold;

    color: #ff7900;

    text-align: center;
}

.status {

    text-align: center;

    font-size: 20px;

    font-weight: bold;

    margin-bottom: 20px;
}

.motivo {

    background: #1c1c1c;

    padding: 12px;

    margin-top: 8px;

    border-radius: 8px;

    border-left: 3px solid #ff7900;
}

.safe {

    text-align: center;

    padding: 20px;

    background: #152015;

    border-radius: 12px;

    margin-top: 15px;

    color: #8cff8c;

    font-weight: bold;
}

.danger {

    text-align: center;

    padding: 20px;

    background: #2a1010;

    border-radius: 12px;

    margin-top: 15px;

    color: #ff6565;

    font-weight: bold;
}

footer {

    text-align: center;

    color: #666;

    margin-top: 35px;

    font-size: 13px;
}

.loading {

    display: none;

    text-align: center;

    margin-top: 15px;

    color: #ff7900;
}


/* ==========================================================
   ABAS E NOTÍCIAS
   ========================================================== */

.tabs {
    position: fixed;
    left: 50%;
    bottom: 15px;
    transform: translateX(-50%);
    width: min(900px, 94%);
    display: flex;
    gap: 8px;
    padding: 8px;
    background: rgba(15,15,15,.97);
    border: 1px solid #333;
    border-radius: 16px;
    box-shadow: 0 0 25px rgba(255,100,0,.15);
    z-index: 1000;
}

.tab-button {
    margin: 0;
    width: 50%;
    background: #151515;
    color: #aaa;
    border: 1px solid #333;
}

.tab-button.active {
    background: #ff7900;
    color: #000;
}

.pagina {
    display: none;
}

.pagina.active {
    display: block;
}

.noticia {
    overflow: hidden;
    background: #151515;
    border: 1px solid #333;
    border-left: 4px solid #ff7900;
    border-radius: 14px;
    margin-top: 15px;
}

.noticia-imagem {
    width: 100%;
    height: 190px;
    object-fit: cover;
    display: block;
    background: #0b0b0b;
}

.noticia-conteudo {
    padding: 18px;
}

.noticia h3 {
    margin-top: 0;
    color: #ff7900;
}

.noticia .data {
    color: #777;
    font-size: 12px;
    margin-top: 12px;
}

.noticia a {
    display: inline-block;
    margin-top: 12px;
    color: #ff941f;
    font-weight: bold;
    text-decoration: none;
}

.rodape-espaco {
    height: 95px;
}

</style>

</head>


<body>

<div class="container">

<header>

<div class="logo">🦊</div>

<h1>IAFOX</h1>

<div class="subtitle">
Inteligência Artificial de Proteção Digital
</div>

</header>


<div id="pagina-analisar" class="pagina active">
<!-- =====================================================
     ANALISADOR DE LINKS
===================================================== -->

<div class="card">

<h2>🔗 Analisar Link</h2>

<p>
Cole aqui o endereço do site que você quer verificar.
</p>

<input
id="link"
placeholder="https://exemplo.com"
>

<button onclick="analisarLink()">
🛡️ ANALISAR LINK
</button>

<div class="loading" id="loadingLink">
IAFOX analisando...
</div>

<div class="resultado" id="resultadoLink">

<div class="nivel" id="nivelLink">
0/5
</div>

<div class="status" id="statusLink">
-
</div>

<div id="motivosLink">
</div>

<div id="mensagemSegurancaLink">
</div>

</div>

</div>


<!-- =====================================================
     ANALISADOR DE MENSAGENS
===================================================== -->

<div class="card">

<h2>📨 Analisar Mensagem</h2>

<p>
Cole aqui um SMS ou mensagem suspeita do WhatsApp.
</p>

<textarea
id="mensagem"
placeholder="Cole a mensagem suspeita aqui..."
></textarea>

<button onclick="analisarMensagem()">
🕵️ ANALISAR MENSAGEM
</button>

<div class="loading" id="loadingMensagem">
IAFOX analisando mensagem...
</div>

<div class="resultado" id="resultadoMensagem">

<div class="nivel" id="nivelMensagem">
0/5
</div>

<div class="status" id="statusMensagem">
-
</div>

<div id="motivosMensagem">
</div>

<div id="mensagemSegurancaMensagem">
</div>

</div>

</div>



</div>

<div id="pagina-noticias" class="pagina">
    <div class="card">
        <h2>📰 Golpes da Semana</h2>
        <p>
            O radar da IAFOX procura notícias públicas sobre golpes e phishing.
        </p>

        <div id="statusNoticias" class="loading">
            🦊 IAFOX carregando o radar...
        </div>

        <div id="listaNoticias"></div>
    </div>
</div>

<div class="rodape-espaco"></div>

<div class="tabs">
    <button class="tab-button active" id="tabAnalisar"
            onclick="mostrarPagina('analisar')">
        🔍 Analisar
    </button>

    <button class="tab-button" id="tabNoticias"
            onclick="mostrarPagina('noticias')">
        📰 Golpes
    </button>
</div>

<footer>

IAFOX Security © 2026<br>
Sistema experimental de análise de segurança.

</footer>

</div>


<script>


// ======================================================
// ANALISAR LINK
// ======================================================

async function analisarLink() {

    const link = document.getElementById("link").value;

    if (!link) {

        alert("Digite um link primeiro.");

        return;
    }

    document.getElementById("loadingLink").style.display = "block";

    document.getElementById("resultadoLink").style.display = "none";


    const resposta = await fetch("/analisar-link", {

        method: "POST",

        headers: {
            "Content-Type": "application/json"
        },

        body: JSON.stringify({
            link: link
        })

    });


    const dados = await resposta.json();


    document.getElementById("loadingLink").style.display = "none";

    document.getElementById("resultadoLink").style.display = "block";


    document.getElementById("nivelLink").innerText =
        dados.nivel + "/5";


    document.getElementById("statusLink").innerText =
        dados.status;


    let html = "";

    dados.motivos.forEach(function(motivo) {

        html += `
        <div class="motivo">
            ⚠️ ${motivo}
        </div>
        `;

    });


    document.getElementById("motivosLink").innerHTML = html;


    if (dados.nivel <= 1) {

        document.getElementById(
            "mensagemSegurancaLink"
        ).innerHTML = `
        <div class="safe">
            🛡️ VOCÊ ESTÁ SEGURO COM A IAFOX
            <br><br>
            Nenhum sinal forte de perigo foi encontrado.
        </div>
        `;

    } else {

        document.getElementById(
            "mensagemSegurancaLink"
        ).innerHTML = `
        <div class="danger">
            🚨 CUIDADO!
            <br><br>
            A IAFOX encontrou sinais que merecem atenção.
        </div>
        `;

    }

}


// ======================================================
// ANALISAR MENSAGEM
// ======================================================

async function analisarMensagem() {

    const mensagem =
        document.getElementById("mensagem").value;


    if (!mensagem) {

        alert("Cole uma mensagem primeiro.");

        return;
    }


    document.getElementById(
        "loadingMensagem"
    ).style.display = "block";


    document.getElementById(
        "resultadoMensagem"
    ).style.display = "none";


    const resposta = await fetch(
        "/analisar-mensagem",
        {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                mensagem: mensagem
            })

        }
    );


    const dados = await resposta.json();


    document.getElementById(
        "loadingMensagem"
    ).style.display = "none";


    document.getElementById(
        "resultadoMensagem"
    ).style.display = "block";


    document.getElementById(
        "nivelMensagem"
    ).innerText = dados.nivel + "/5";


    document.getElementById(
        "statusMensagem"
    ).innerText = dados.status;


    let html = "";


    dados.motivos.forEach(function(motivo) {

        html += `
        <div class="motivo">
            ⚠️ ${motivo}
        </div>
        `;

    });


    document.getElementById(
        "motivosMensagem"
    ).innerHTML = html;


    if (dados.nivel <= 1) {

        document.getElementById(
            "mensagemSegurancaMensagem"
        ).innerHTML = `
        <div class="safe">
            🛡️ MENSAGEM COM BAIXO RISCO
        </div>
        `;

    } else {

        document.getElementById(
            "mensagemSegurancaMensagem"
        ).innerHTML = `
        <div class="danger">
            🚨 POSSÍVEL GOLPE
            <br><br>
            Não clique em links nem envie seus dados.
        </div>
        `;

    }

}


// ======================================================
// NAVEGAÇÃO DAS ABAS
// ======================================================

function mostrarPagina(pagina) {
    document.getElementById("pagina-analisar").classList.remove("active");
    document.getElementById("pagina-noticias").classList.remove("active");

    document.getElementById("tabAnalisar").classList.remove("active");
    document.getElementById("tabNoticias").classList.remove("active");

    if (pagina === "noticias") {
        document.getElementById("pagina-noticias").classList.add("active");
        document.getElementById("tabNoticias").classList.add("active");
        carregarNoticias();
    } else {
        document.getElementById("pagina-analisar").classList.add("active");
        document.getElementById("tabAnalisar").classList.add("active");
    }
}


// ======================================================
// RADAR DE NOTÍCIAS
// ======================================================

async function carregarNoticias() {
    const lista = document.getElementById("listaNoticias");
    const status = document.getElementById("statusNoticias");

    status.style.display = "block";

    try {
        const resposta = await fetch("/noticias");
        const dados = await resposta.json();

        let html = "";

        if (!dados.noticias || dados.noticias.length === 0) {
            html = `
                <div class="danger">
                    🚨 Ainda não foi possível encontrar notícias.
                </div>
            `;
        }

        (dados.noticias || []).forEach(function(noticia) {

            const imagem = noticia.imagem
                ? `<img class="noticia-imagem"
                        src="${noticia.imagem}"
                        alt="Imagem ilustrativa da notícia">`
                : "";

            html += `
                <article class="noticia">
                    ${imagem}

                    <div class="noticia-conteudo">
                        <h3>🚨 ${noticia.titulo}</h3>

                        <p>${noticia.resumo}</p>

                        <p>
                            <strong>🛡️ Como evitar:</strong><br>
                            ${noticia.prevencao}
                        </p>

                        <div class="data">
                            📅 ${noticia.data}
                            · 📰 ${noticia.fonte}
                        </div>

                        <a href="${noticia.link}"
                           target="_blank"
                           rel="noopener noreferrer">
                            🔗 Ler fonte original
                        </a>
                    </div>
                </article>
            `;
        });

        lista.innerHTML = html;

    } catch (erro) {
        lista.innerHTML = `
            <div class="danger">
                🚨 Não foi possível carregar o radar de notícias.
            </div>
        `;
    }

    status.style.display = "none";
}

</script>

</body>

</html>
"""


# ==========================================================
# PÁGINA PRINCIPAL
# ==========================================================

@app.route("/")
def home():

    return render_template_string(HTML)


# ==========================================================
# INICIAR SERVIDOR
# ==========================================================

if __name__ == "__main__":

    print("")
    print("======================================")
    print("        🦊 IAFOX SECURITY")
    print("======================================")
    print("")
    print("Computador:")
    print("http://127.0.0.1:5000")
    print("")
    print("Para abrir no celular:")
    print("http://SEU_IP:5000")
    print("")
    print("======================================")
    print("📰 Radar de golpes: atualização automática a cada 7 dias")
    print("======================================")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
