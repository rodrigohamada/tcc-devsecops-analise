import json
import os
import sys
import datetime

def process_semgrep(data):
    """Extrai e formata os achados do Semgrep."""
    findings = []
    for r in data.get("results", []):
        findings.append({
            "type": "SAST", "rule": r["check_id"], "severity": r["extra"]["severity"],
            "file": r["path"], "line": r["start"]["line"],
            "message": r["extra"]["message"].split('\n')[0]
        })
    return findings

def process_gitleaks(data):
    """Extrai e formata os achados do Gitleaks."""
    findings = []
    for r in data:
        findings.append({
            "type": "SECRET", "rule": r["Description"], "severity": "CRITICAL",
            "file": r["File"], "line": r["StartLine"],
            "secret_pattern": r["Secret"][:6] + '...'
        })
    return findings

def process_trivy(data):
    """Extrai e formata os achados do Trivy."""
    findings = []
    if not data.get("Results"): return []
    for res in data["Results"]:
        file_target = os.path.basename(res.get("Target", ""))
        if "requirements.txt" in file_target:
            for v in res.get("Vulnerabilities", []):
                findings.append({
                    "type": "SCA", "rule": v.get("VulnerabilityID", "N/A"), "severity": v.get("Severity", "UNKNOWN"),
                    "package": v.get("PkgName", "N/A"), "version": v.get("InstalledVersion", "N/A"),
                    "title": v.get("Title", "N/A")
                })
    return findings

def generate_report(repo_name, sast_f, gitleaks_f, trivy_f):
    """Gera o conteúdo do relatório em Markdown."""
    all_findings = sast_f + gitleaks_f + trivy_f
    severities = [f["severity"] for f in all_findings]
    
    # Conteúdo do cabeçalho e resumo (sem separadores problemáticos)
    md_content = f"""
# Relatório de Análise de Segurança

**Repositório Analisado:** `{repo_name}`
**Data do Scan:** {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}

## Resumo Executivo e Métricas

| Métrica | Quantidade |
|---|---|
| **Total de Achados de Segurança** | **{len(all_findings)}** |
| Análise Estática (SAST) | {len(sast_f)} |
| Análise de Dependências (SCA) | {len(trivy_f)} |
| Vazamento de Segredos | {len(gitleaks_f)} |

### Distribuição por Severidade

| Severidade | Quantidade |
|---|---|
| CRÍTICA | {severities.count("CRITICAL")} |
| ALTA | {severities.count("HIGH")} |
| MÉDIA | {severities.count("MEDIUM")} |
| BAIXA | {severities.count("LOW")} |
| DESCONHECIDA | {severities.count("UNKNOWN")} |

## Detalhamento dos Achados
"""

    # Seção SAST (formato de bloco, sem separador '---')
    md_content += "\n### SAST (Análise Estática do Código-Fonte)\n"
    if sast_f:
        for f in sorted(sast_f, key=lambda x: x['file']):
            md_content += f"\n**Severidade:** `{f['severity']}`\n\n"
            md_content += f"**Regra:** `{f['rule']}`\n\n"
            md_content += f"**Localização:** `{f['file']}:{f['line']}`\n\n"
            md_content += f"**Mensagem:** {f['message']}\n\n"
    else: md_content += "\nNenhum achado de SAST com as regras padrão.\n"

    # Seção Segredos (formato de bloco, sem separador '---')
    md_content += "\n### Vazamento de Segredos\n"
    if gitleaks_f:
        for f in sorted(gitleaks_f, key=lambda x: x['file']):
            md_content += f"\n**Severidade:** `{f['severity']}`\n\n"
            md_content += f"**Descrição:** {f['rule']}\n\n"
            md_content += f"**Localização:** `{f['file']}:{f['line']}`\n\n"
            md_content += f"**Padrão do Segredo:** `{f['secret_pattern']}`\n\n"
    else: md_content += "\nNenhum segredo encontrado.\n"

    # Seção SCA (formato de bloco, sem separador '---')
    md_content += "\n### SCA (Análise de Dependências de Terceiros)\n"
    if trivy_f:
        for f in sorted(trivy_f, key=lambda x: x['package']):
            md_content += f"\n**Severidade:** `{f['severity']}`\n\n"
            md_content += f"**Pacote Afetado:** `{f['package']} (versão: {f['version']})`\n\n"
            md_content += f"**Vulnerabilidade (ID):** `{f['rule']}`\n\n"
            md_content += f"**Título:** {f['title']}\n\n"
    else: md_content += "\nNenhuma dependência vulnerável encontrada.\n"

    # Salva o relatório .md (agora sem ícones para o PDF não ter problemas)
    report_filename_md = f"relatorio-{repo_name}.md"
    with open(report_filename_md, "w", encoding="utf-8") as f:
        f.write(md_content)

    # Salva o mesmo conteúdo no arquivo temporário para o Pandoc usar
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

