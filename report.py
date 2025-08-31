import json
import os
import sys
import datetime
import re
from googletrans import Translator

# Inicializa o tradutor
tradutor = Translator()

def traduzir_mensagem(mensagem):
    """Traduz mensagens de achados do inglês para português."""
    try:
        return tradutor.translate(mensagem, src="en", dest="pt").text
    except Exception:
        return mensagem  # fallback: mantém em inglês se falhar

def formatar_texto(mensagem):
    """Normaliza espaçamento e formatação do texto traduzido."""
    if not mensagem:
        return mensagem
    # Espaço após pontuações
    mensagem = re.sub(r'([.,;!?])([^\s])', r'\1 \2', mensagem)
    # Remove múltiplos espaços
    mensagem = re.sub(r'\s{2,}', ' ', mensagem)
    # Corrige casos de "palavra.outra" → "palavra. outra"
    mensagem = re.sub(r'([a-zA-Z])\.([A-ZÁÉÍÓÚ])', r'\1. \2', mensagem)
    # Corrige espaços antes de vírgulas e pontos
    mensagem = mensagem.replace(" .", ".").replace(" ,", ",")
    return mensagem.strip()

def processar_semgrep(dados):
    """Extrai e formata os achados do Semgrep."""
    achados = []
    for resultado in dados.get("results", []):
        mensagem = resultado["extra"]["message"].split('\n')[0]
        mensagem_traduzida = traduzir_mensagem(mensagem)
        mensagem_formatada = formatar_texto(mensagem_traduzida)
        achados.append({
            "tipo": "SAST",
            "regra": resultado["check_id"],
            "severidade": resultado["extra"]["severity"],
            "arquivo": resultado["path"],
            "linha": resultado["start"]["line"],
            "mensagem": mensagem_formatada
        })
    return achados

def processar_gitleaks(dados):
    """Extrai e formata os achados do Gitleaks."""
    achados = []
    for resultado in dados:
        achados.append({
            "tipo": "SEGREDO",
            "regra": resultado["Description"],
            "severidade": "CRÍTICA",
            "arquivo": resultado["File"],
            "linha": resultado["StartLine"],
            "padrao": resultado["Secret"][:6] + '...'
        })
    return achados

def processar_trivy(dados):
    """Extrai e formata os achados do Trivy."""
    achados = []
    if not dados.get("Results"):
        return []
    for resultado in dados["Results"]:
        alvo_arquivo = os.path.basename(resultado.get("Target", ""))
        if "requirements.txt" in alvo_arquivo:
            for vulnerabilidade in resultado.get("Vulnerabilities", []):
                achados.append({
                    "tipo": "SCA",
                    "regra": vulnerabilidade.get("VulnerabilityID", "N/A"),
                    "severidade": vulnerabilidade.get("Severity", "DESCONHECIDA"),
                    "pacote": vulnerabilidade.get("PkgName", "N/A"),
                    "versao": vulnerabilidade.get("InstalledVersion", "N/A"),
                    "titulo": vulnerabilidade.get("Title", "N/A")
                })
    return achados

def gerar_relatorio(nome_repositorio, achados_sast, achados_gitleaks, achados_trivy):
    """Gera o conteúdo do relatório em Markdown traduzido e formatado."""
    todos_achados = achados_sast + achados_gitleaks + achados_trivy
    severidades = [f["severidade"] for f in todos_achados]

    conteudo_md = f"""
# Relatório de Análise de Segurança

**Repositório Analisado:** `{nome_repositorio}`  
**Data do Scan:** {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}  

---

## Resumo Executivo

| Métrica | Quantidade |
|---------|------------|
| **Total de Achados** | **{len(todos_achados)}** |
| Análise Estática (SAST) | {len(achados_sast)} |
| Vazamento de Segredos | {len(achados_gitleaks)} |
| Análise de Dependências (SCA) | {len(achados_trivy)} |

---

## Distribuição por Severidade

| Severidade | Quantidade |
|------------|------------|
| CRÍTICA | {severidades.count("CRITICAL") + severidades.count("CRÍTICA")} |
| ALTA | {severidades.count("HIGH") + severidades.count("ALTA")} |
| MÉDIA | {severidades.count("MEDIUM") + severidades.count("MÉDIA")} |
| BAIXA | {severidades.count("LOW") + severidades.count("BAIXA")} |
| DESCONHECIDA | {severidades.count("UNKNOWN") + severidades.count("DESCONHECIDA")} |

---

## Detalhamento dos Achados
"""

    # SAST
    conteudo_md += "\n### Análise Estática (SAST)\n"
    if achados_sast:
        for f in sorted(achados_sast, key=lambda x: x['arquivo']):
            conteudo_md += f"""
**Severidade:** {f['severidade']}  
**Regra:** {f['regra']}  
**Localização:** `{f['arquivo']}:{f['linha']}`  
**Descrição:** {f['mensagem']}  

---
"""
    else:
        conteudo_md += "\nNenhum achado de SAST.\n"

    # Segredos
    conteudo_md += "\n### Vazamento de Segredos\n"
    if achados_gitleaks:
        for f in sorted(achados_gitleaks, key=lambda x: x['arquivo']):
            conteudo_md += f"""
**Severidade:** {f['severidade']}  
**Descrição:** {f['regra']}  
**Localização:** `{f['arquivo']}:{f['linha']}`  
**Padrão identificado:** `{f['padrao']}`  

---
"""
    else:
        conteudo_md += "\nNenhum segredo encontrado.\n"

    # SCA
    conteudo_md += "\n### Análise de Dependências (SCA)\n"
    if achados_trivy:
        for f in sorted(achados_trivy, key=lambda x: x['pacote']):
            conteudo_md += f"""
**Severidade:** {f['severidade']}  
**Pacote:** `{f['pacote']} (versão: {f['versao']})`  
**Vulnerabilidade:** `{f['regra']}`  
**Título:** {f['titulo']}  

---
"""
    else:
        conteudo_md += "\nNenhuma dependência vulnerável encontrada.\n"

    # Conclusão
    conteudo_md += """
---

## Conclusões e Recomendações

- Corrigir vulnerabilidades críticas imediatamente.  
- Revogar e rotacionar segredos expostos.  
- Evitar interpolação insegura em scripts e workflows.  
- Aplicar boas práticas de desenvolvimento seguro em Flask e SQL.  
- Reexecutar os scans após aplicar correções.  
"""

    # Salvar arquivos
    arquivo_relatorio_md = f"relatorio-{nome_repositorio}.md"
    with open(arquivo_relatorio_md, "w", encoding="utf-8") as f:
        f.write(conteudo_md)

    arquivo_temp_pdf_md = "temp-report-for-pdf.md"
    with open(arquivo_temp_pdf_md, "w", encoding="utf-8") as f:
        f.write(conteudo_md)

if __name__ == "__main__":
    nome_repositorio = sys.argv[1] if len(sys.argv) > 1 else "desconhecido"

    try:
        with open("semgrep-output.json") as f: dados_semgrep = json.load(f)
    except: dados_semgrep = {}
    try:
        with open("gitleaks-output.json") as f: dados_gitleaks = json.load(f)
    except: dados_gitleaks = []
    try:
        with open("trivy-output.json") as f: dados_trivy = json.load(f)
    except: dados_trivy = {}

    achados_sast = processar_semgrep(dados_semgrep)
    achados_gitleaks = processar_gitleaks(dados_gitleaks)
    achados_trivy = processar_trivy(dados_trivy)
    gerar_relatorio(nome_repositorio, achados_sast, achados_gitleaks, achados_trivy)
