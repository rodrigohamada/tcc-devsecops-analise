import json
import os
import sys
import datetime
import re
from collections import Counter
from googletrans import Translator

# Inicializa o tradutor
translator = Translator()

def traduzir_mensagem(msg):
    """Traduz mensagens de achados do inglês para português."""
    try:
        return translator.translate(msg, src="en", dest="pt").text
    except Exception:
        return msg  # fallback: mantém em inglês se falhar

def ajustar_texto(msg):
    """Corrige espaçamento e termos técnicos em traduções automáticas."""
    if not msg:
        return msg

    # Espaço após pontuação
    msg = re.sub(r'([.,;!?])([^\s])', r'\1 \2', msg)

    # Termos técnicos
    substituicoes = {
        "github": "GitHub",
        "Github": "GitHub",
        "git hub": "GitHub",
        "env:": "`env:`",
        "Env:": "`env:`",
        "run:": "`run:`",
        "Run:": "`run:`",
        "$ Envvar": "`$ENVVAR`",
        "$ EnvVar": "`$ENVVAR`",
        "$ Env": "`$ENVVAR`",
        "scriptrun:": "script `run:`",
        "comEnv:": "com `env:`",
        "Flask": "**Flask**",
        "SQL": "**SQL**"
    }

    for errado, certo in substituicoes.items():
        msg = msg.replace(errado, certo)

    # Remove múltiplos espaços
    msg = re.sub(r'\s{2,}', ' ', msg)

    return msg.strip()

def process_semgrep(data):
    """Extrai e formata os achados do Semgrep."""
    findings = []
    for r in data.get("results", []):
        msg = r["extra"]["message"].split('\n')[0]
        traduzida = traduzir_mensagem(msg)
        ajustada = ajustar_texto(traduzida)
        findings.append({
            "tipo": "SAST",
            "regra": r["check_id"],
            "severidade": r["extra"]["severity"],
            "arquivo": r["path"],
            "linha": r["start"]["line"],
            "mensagem": ajustada
        })
    return findings

def process_gitleaks(data):
    """Extrai e formata os achados do Gitleaks."""
    findings = []
    for r in data:
        findings.append({
            "tipo": "SEGREDO",
            "regra": r["Description"],
            "severidade": "CRÍTICA",
            "arquivo": r["File"],
            "linha": r["StartLine"],
            "padrao": r["Secret"][:6] + '...'
        })
    return findings

def process_trivy(data):
    """Extrai e formata os achados do Trivy."""
    findings = []
    if not data.get("Results"):
        return []
    for res in data["Results"]:
        file_target = os.path.basename(res.get("Target", ""))
        if "requirements.txt" in file_target:
            for v in res.get("Vulnerabilities", []):
                findings.append({
                    "tipo": "SCA",
                    "regra": v.get("VulnerabilityID", "N/A"),
                    "severidade": v.get("Severity", "DESCONHECIDA"),
                    "pacote": v.get("PkgName", "N/A"),
                    "versao": v.get("InstalledVersion", "N/A"),
                    "titulo": ajustar_texto(traduzir_mensagem(v.get("Title", "N/A")))
                })
    return findings

def gerar_grafico_ascii(severidades):
    """Gera um gráfico de barras ASCII da distribuição de severidades."""
    contagem = Counter(severidades)
    ordem = ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA", "DESCONHECIDA"]
    grafico = "\n### Gráfico de Severidades (ASCII)\n\n"
    for nivel in ordem:
        qtd = contagem.get(nivel, 0) + contagem.get(nivel.upper(), 0)
        grafico += f"{nivel:<12} | {'#' * qtd} ({qtd})\n"
    return grafico

def generate_report(repo_name, sast_f, gitleaks_f, trivy_f):
    """Gera o conteúdo do relatório em Markdown traduzido e formatado."""
    all_findings = sast_f + gitleaks_f + trivy_f
    severidades = [f["severidade"] for f in all_findings]

    total = len(all_findings)
    percentuais = {
        "CRÍTICA": (severidades.count("CRITICAL") + severidades.count("CRÍTICA")) / total * 100 if total else 0,
        "ALTA": (severidades.count("HIGH") + severidades.count("ALTA")) / total * 100 if total else 0,
        "MÉDIA": (severidades.count("MEDIUM") + severidades.count("MÉDIA")) / total * 100 if total else 0,
        "BAIXA": (severidades.count("LOW") + severidades.count("BAIXA")) / total * 100 if total else 0,
        "DESCONHECIDA": (severidades.count("UNKNOWN") + severidades.count("DESCONHECIDA")) / total * 100 if total else 0,
    }

    # Top 5 regras mais encontradas
    regras = Counter([f["regra"] for f in sast_f])
    top_regras = regras.most_common(5)

    md_content = f"""
# Relatório de Análise de Segurança

**Repositório Analisado:** `{repo_name}`  
**Data do Scan:** {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}  

---

## Resumo Executivo

| Métrica | Quantidade |
|---------|------------|
| **Total de Achados** | **{len(all_findings)}** |
| Análise Estática (SAST) | {len(sast_f)} |
| Vazamento de Segredos | {len(gitleaks_f)} |
| Análise de Dependências (SCA) | {len(trivy_f)} |

---

## Distribuição por Severidade

| Severidade | Quantidade | Percentual |
|------------|------------|------------|
| CRÍTICA | {severidades.count("CRITICAL") + severidades.count("CRÍTICA")} | {percentuais["CRÍTICA"]:.1f}% |
| ALTA | {severidades.count("HIGH") + severidades.count("ALTA")} | {percentuais["ALTA"]:.1f}% |
| MÉDIA | {severidades.count("MEDIUM") + severidades.count("MÉDIA")} | {percentuais["MÉDIA"]:.1f}% |
| BAIXA | {severidades.count("LOW") + severidades.count("BAIXA")} | {percentuais["BAIXA"]:.1f}% |
| DESCONHECIDA | {severidades.count("UNKNOWN") + severidades.count("DESCONHECIDA")} | {percentuais["DESCONHECIDA"]:.1f}% |

{gerar_grafico_ascii(severidades)}

---

## Top 5 Regras Mais Encontradas (SAST)

| Regra | Ocorrências |
|-------|-------------|
"""
    if top_regras:
        for regra, qtd in top_regras:
            md_content += f"| {regra} | {qtd} |\n"
    else:
        md_content += "| Nenhuma regra encontrada | 0 |\n"

    md_content += """

---

## Detalhamento dos Achados
"""

    # SAST
    md_content += "\n### Análise Estática (SAST)\n"
    if sast_f:
        for f in sorted(sast_f, key=lambda x: x['arquivo']):
            md_content += f"""
**Severidade:** {f['severidade']}  
**Regra:** {f['regra']}  
**Localização:** `{f['arquivo']}:{f['linha']}`  
**Descrição:** {f['mensagem']}  

---
"""
    else:
        md_content += "\nNenhum achado de SAST.\n"

    # Segredos
    md_content += "\n### Vazamento de Segredos\n"
    if gitleaks_f:
        for f in sorted(gitleaks_f, key=lambda x: x['arquivo']):
            md_content += f"""
**Severidade:** {f['severidade']}  
**Descrição:** {f['regra']}  
**Localização:** `{f['arquivo']}:{f['linha']}`  
**Padrão identificado:** `{f['padrao']}`  

---
"""
    else:
        md_content += "\nNenhum segredo encontrado.\n"

    # SCA
    md_content += "\n### Análise de Dependências (SCA)\n"
    if trivy_f:
        for f in sorted(trivy_f, key=lambda x: x['pacote']):
            md_content += f"""
**Severidade:** {f['severidade']}  
**Pacote:** `{f['pacote']} (versão: {f['versao']})`  
**Vulnerabilidade:** `{f['regra']}`  
**Título:** {f['titulo']}  

---
"""
    else:
        md_content += "\nNenhuma dependência vulnerável encontrada.\n"

    # Conclusão
    md_content += """
---

## Conclusões e Recomendações

- Corrigir vulnerabilidades críticas imediatamente.  
- Revogar e rotacionar segredos expostos.  
- Evitar interpolação insegura em scripts e workflows.  
- Aplicar boas práticas de desenvolvimento seguro em **Flask** e **SQL**.  
- Reexecutar os scans após aplicar correções.  
"""

    # Salvar arquivos
    report_filename_md = f"relatorio-{repo_name}.md"
    with open(report_filename_md, "w", encoding="utf-8") as f:
        f.write(md_content)

    temp_pdf_md_filename = "temp-report-for-pdf.md"
    with open(temp_pdf_md_filename, "w", encoding="utf-8") as f:
        f.write(md_content)

if __name__ == "__main__":
    repo_name = sys.argv[1] if len(sys.argv) > 1 else "desconhecido"

    try:
        with open("semgrep-output.json") as f: semgrep_data = json.load(f)
    except: semgrep_data = {}
    try:
        with open("gitleaks-output.json") as f: gitleaks_data = json.load(f)
    except: gitleaks_data = []
    try:
        with open("trivy-output.json") as f: trivy_data = json.load(f)
    except: trivy_data = {}

    sast = process_semgrep(semgrep_data)
    gitleaks = process_gitleaks(gitleaks_data)
    trivy = process_trivy(trivy_data)
    generate_report(repo_name, sast, gitleaks, trivy)
