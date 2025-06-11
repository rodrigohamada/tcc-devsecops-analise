import json
import sys
import datetime

# --- Funções para Processar os Resultados de Cada Ferramenta ---

def process_semgrep(data):
    results = data.get("results", [])
    findings = []
    for r in results:
        findings.append({
            "descricao": r["check_id"],
            "severidade": r["extra"]["severity"],
            "arquivo": r["path"],
            "linha": r["start"]["line"],
            "mensagem": r["extra"]["message"].split('\n')[0]
        })
    return findings

def process_gitleaks(data):
    findings = []
    for r in data:
        findings.append({
            "descricao": r["Description"],
            "severidade": "CRITICAL",
            "arquivo": r["File"],
            "linha": r["StartLine"],
            "segredo": r["Secret"][:6] + '...' # Mostra apenas o início do segredo
        })
    return findings

def process_trivy(data):
    results = data.get("Results", [])
    findings = []
    if not results:
        return findings
        
    for res in results:
        vulnerabilities = res.get("Vulnerabilities", [])
        for v in vulnerabilities:
            findings.append({
                "id_vuln": v.get("VulnerabilityID", "N/A"),
                "pacote": v.get("PkgName", "N/A"),
                "versao_instalada": v.get("InstalledVersion", "N/A"),
                "severidade": v.get("Severity", "UNKNOWN"),
                "titulo": v.get("Title", "N/A")
            })
    return findings

# --- Geração do Relatório em Markdown ---

def generate_report(repo_name, semgrep_f, gitleaks_f, trivy_f):
    # Contagem de métricas
    total_findings = len(semgrep_f) + len(gitleaks_f) + len(trivy_f)
    sast_count = len(semgrep_f)
    secret_count = len(gitleaks_f)
    sca_count = len(trivy_f)

    # Contagem por severidade
    severities = [f["severidade"] for f in semgrep_f + gitleaks_f + trivy_f]
    crit_count = severities.count("CRITICAL")
    high_count = severities.count("HIGH")
    med_count = severities.count("MEDIUM")
    low_count = severities.count("LOW")

    # Construção do conteúdo do relatório
    report_content = f"""
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

    # Seção SAST (Semgrep)
    report_content += "### 🛡️ SAST (Análise Estática do Código-Fonte)\n\n"
    if semgrep_f:
        report_content += "| Severidade | Descrição da Regra | Arquivo:Linha | Mensagem |\n|---|---|---|---|\n"
        for f in semgrep_f:
            report_content += f"| {f['severidade']} | `{f['descricao']}` | {f['arquivo']}:{f['linha']} | {f['mensagem']} |\n"
    else:
        report_content += "✅ Nenhum achado de SAST com as regras padrão.\n"
    report_content += "\n"

    # Seção Segredos (Gitleaks)
    report_content += "### 🔑 Vazamento de Segredos\n\n"
    if gitleaks_f:
        report_content += "| Severidade | Descrição | Arquivo:Linha | Padrão do Segredo |\n|---|---|---|---|\n"
        for f in gitleaks_f:
            report_content += f"| {f['severidade']} | {f['descricao']} | {f['arquivo']}:{f['linha']} | `{f['segredo']}` |\n"
    else:
        report_content += "✅ Nenhum segredo encontrado.\n"
    report_content += "\n"
    
    # Seção SCA (Trivy)
    report_content += "### 📦 SCA (Análise de Dependências de Terceiros)\n\n"
    if trivy_f:
        report_content += "| Severidade | ID da Vulnerabilidade | Pacote Afetado | Versão Instalada | Título |\n|---|---|---|---|---|\n"
        for f in trivy_f:
            report_content += f"| {f['severidade']} | `{f['id_vuln']}` | {f['pacote']} | {f['versao_instalada']} | {f['titulo']} |\n"
    else:
        report_content += "✅ Nenhuma dependência vulnerável encontrada.\n"

    # Salva o relatório em um arquivo .md
    report_filename = f"relatorio-{repo_name}.md"
    with open(report_filename, "w", encoding="utf-8") as f:
        f.write(report_content)
    
    return report_filename

# --- Função Principal ---

if __name__ == "__main__":
    repo_name = sys.argv[1] if len(sys.argv) > 1 else "desconhecido"
    
    try:
        with open("semgrep-output.json") as f:
            semgrep_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        semgrep_data = {}

    try:
        with open("gitleaks-output.json") as f:
            gitleaks_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        gitleaks_data = []

    try:
        with open("trivy-output.json") as f:
            trivy_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        trivy_data = {}
        
    semgrep_findings = process_semgrep(semgrep_data)
    gitleaks_findings = process_gitleaks(gitleaks_data)
    trivy_findings = process_trivy(trivy_data)

    generate_report(repo_name, semgrep_findings, gitleaks_findings, trivy_findings)
