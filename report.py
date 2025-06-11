import json
import sys
import datetime

# --- Funções para Processar os Resultados de Cada Ferramenta (sem alterações) ---
def process_semgrep(data):
    results = data.get("results", [])
    findings = []
    for r in results:
        findings.append({
            "descricao": r["check_id"], "severidade": r["extra"]["severity"],
            "arquivo": r["path"], "linha": r["start"]["line"],
            "mensagem": r["extra"]["message"].split('\n')[0]
        })
    return findings

def process_gitleaks(data):
    findings = []
    for r in data:
        findings.append({
            "descricao": r["Description"], "severidade": "CRITICAL",
            "arquivo": r["File"], "linha": r["StartLine"],
            "segredo": r["Secret"][:6] + '...'
        })
    return findings

def process_trivy(data):
    results = data.get("Results", [])
    findings = []
    if not results: return findings
    for res in results:
        vulnerabilities = res.get("Vulnerabilities", [])
        for v in vulnerabilities:
            findings.append({
                "id_vuln": v.get("VulnerabilityID", "N/A"), "pacote": v.get("PkgName", "N/A"),
                "versao_instalada": v.get("InstalledVersion", "N/A"), "severidade": v.get("Severity", "UNKNOWN"),
                "titulo": v.get("Title", "N/A")
            })
    return findings

# --- Geração do Relatório em Markdown ---
def generate_report(repo_name, semgrep_f, gitleaks_f, trivy_f):
    total_findings = len(semgrep_f) + len(gitleaks_f) + len(trivy_f)
    sast_count = len(semgrep_f); secret_count = len(gitleaks_f); sca_count = len(trivy_f)
    severities = [f["severidade"] for f in semgrep_f + gitleaks_f + trivy_f]
    crit_count = severities.count("CRITICAL"); high_count = severities.count("HIGH")
    med_count = severities.count("MEDIUM"); low_count = severities.count("LOW")

    # Conteúdo do relatório COM ÍCONES (para o arquivo .md)
    md_content = f"""
# Relatório de Análise de Segurança - DevSecOps Scanner

**Repositório Analisado:** `{repo_name}`
**Data do Scan:** {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}

***
## 📊 Resumo Executivo e Métricas

| Métrica | Quantidade |
|---|---|
| 🚨 **Total de Achados de Segurança** | **{total_findings}** |
| Análise Estática (SAST) | {sast_count} |
| Análise de Dependências (SCA) | {sca_count} |
| Vazamento de Segredos | {secret_count} |

### Distribuição por Severidade

| Severidade | Quantidade |
|---|---|
| 🔥 CRÍTICA | {crit_count} |
| 🟧 ALTA | {high_count} |
| 🟨 MÉDIA | {med_count} |
| INFORMACIONAL/BAIXA | {low_count} |

***
## 🔬 Detalhamento dos Achados
"""
    md_content += "\n### 🛡️ SAST (Análise Estática do Código-Fonte)\n\n"
    if semgrep_f:
        md_content += "| Severidade | Descrição da Regra | Arquivo:Linha | Mensagem |\n|---|---|---|---|\n"
        for f in semgrep_f: md_content += f"| {f['severidade']} | `{f['descricao']}` | {f['arquivo']}:{f['linha']} | {f['mensagem']} |\n"
    else: md_content += "✅ Nenhum achado de SAST com as regras padrão.\n"
    md_content += "\n### 🔑 Vazamento de Segredos\n\n"
    if gitleaks_f:
        md_content += "| Severidade | Descrição | Arquivo:Linha | Padrão do Segredo |\n|---|---|---|---|\n"
        for f in gitleaks_f: md_content += f"| {f['severidade']} | {f['descricao']} | {f['arquivo']}:{f['linha']} | `{f['segredo']}` |\n"
    else: md_content += "✅ Nenhum segredo encontrado.\n"
    md_content += "\n### 📦 SCA (Análise de Dependências de Terceiros)\n\n"
    if trivy_f:
        md_content += "| Severidade | ID da Vulnerabilidade | Pacote Afetado | Versão Instalada | Título |\n|---|---|---|---|---|\n"
        for f in trivy_f: md_content += f"| {f['severidade']} | `{f['id_vuln']}` | {f['pacote']} | {f['versao_instalada']} | {f['titulo']} |\n"
    else: md_content += "✅ Nenhuma dependência vulnerável encontrada.\n"

    # Salva o relatório .md com ícones
    report_filename_md = f"relatorio-{repo_name}.md"
    with open(report_filename_md, "w", encoding="utf-8") as f:
        f.write(md_content)

    # NOVO: Cria uma versão do conteúdo SEM ÍCONES para o PDF
    pdf_content = md_content
    emojis_to_remove = ["📊", "🚨", "🔥", "🟧", "🟨", "🔬", "🛡️", "🔑", "📦", "✅"]
    for emoji in emojis_to_remove:
        pdf_content = pdf_content.replace(emoji, "")
    
    # Salva o conteúdo limpo em um arquivo temporário para o Pandoc usar
    temp_pdf_md_filename = "temp-report-for-pdf.md"
    with open(temp_pdf_md_filename, "w", encoding="utf-8") as f:
        f.write(pdf_content)

# --- Função Principal ---
if __name__ == "__main__":
    repo_name = sys.argv[1] if len(sys.argv) > 1 else "desconhecido"
    # Carrega os dados dos arquivos JSON
    try:
        with open("semgrep-output.json") as f: semgrep_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): semgrep_data = {}
    try:
        with open("gitleaks-output.json") as f: gitleaks_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): gitleaks_data = []
    try:
        with open("trivy-output.json") as f: trivy_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError): trivy_data = {}
    
    semgrep_findings = process_semgrep(semgrep_data); gitleaks_findings = process_gitleaks(gitleaks_data)
    trivy_findings = process_trivy(trivy_data)

    generate_report(repo_name, semgrep_findings, gitleaks_findings, trivy_findings)
