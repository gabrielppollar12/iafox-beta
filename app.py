from flask import Flask, request, jsonify, render_template_string
from urllib.parse import urlparse
import re
import ipaddress

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

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )