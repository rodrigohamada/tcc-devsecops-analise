import json
import os
import sys
import datetime
import re
from googletrans import Translator

# Inicializa o tradutor
translator = Translator()

def traduzir_texto(texto, dest='pt'):
    """Tenta traduzir um texto, retornando o original em caso de erro."""
    try
        # A API pode retornar None, então garantimos uma string
        traducao = translator.translate(texto, dest=dest)
        return traducao.text if traducao and traducao.text else texto
    except Exception as e:
        print(f"Aviso: Falha na tradução de '{texto[:30]}...'. Erro: {e}")
        return texto

def process_semgrep(data):
    """Extrai, traduz e formata os achados do Semgrep."""
    findings = []
    for r in data.get("results", []):
        findings.append({
            "tipo": "SAST",
            "regra": r["check_id"],
            "severidade": r["extra"]["severity"],
            "arquivo": r["path"],
            "linha": r["start"]["line"],
            "mensagem": traduzir_texto(r["extra"]["message"].split('\n')[0])
        })
    return findings

def process_gitleaks(data):
    """Extrai, traduz e formata os achados do Gitleaks."""
    findings = []
    for r in data:
        findings.append({
            "tipo": "SEGREDO",
            "regra": traduzir_texto(r["Description"]),
            "severidade": "CRÍTICA",
            "arquivo": r["File"],
            "linha": r["StartLine"],
            "padrao": r["Secret"][:6] + '...'
        })
    return findings

def process_trivy(data):
    """Extrai, traduz e formata os achados do Trivy."""
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
                    "titulo": traduzir_texto(v.get("Title", "N/A"))
                })
    return findings

def generate_report(repo_name, sast_f, gitleaks_f, trivy_f):
    """Gera o conteúdo do relatório em Markdown traduzido e formatado."""
    all_findings = sast_f + gitleaks_f + trivy_f
    severidades = [f["severidade"] for f in all_findings]

    md_content = f"""
# Relatório de Análise de Segurança

**Repositório Analisado:** `{repo_name}`
**Data do Scan:** {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}

## Resumo Executivo

| Métrica | Quantidade |
|---|---|
| **Total de Achados** | **{len(all_findings)}** |
| Análise Estática (SAST) | {len(sast_f)} |
| Vazamento de Segredos | {len(gitleaks_f)} |
| Análise de Dependências (SCA) | {len(trivy_f)} |

## Distribuição por Severidade

| Severidade | Quantidade |
|---|---|
| CRÍTICA | {severidades.count("CRITICAL") + severidades.count("CRÍTICA")} |
| ALTA | {severidades.count("HIGH") + severidades.count("ALTA")} |
| MÉDIA | {severidades.count("MEDIUM") + severidades.count("MÉDIA")} |
| BAIXA | {severidades.count("LOW") + severidades.count("BAIXA")} |
| DESCONHECIDA | {severidades.count("UNKNOWN") + severidades.count("DESCONHECIDA")} |

---
## Detalhamento dos Achados
"""

    # Seção SAST (formato de bloco)
    md_content += "\n### Análise Estática (SAST)\n"
    if sast_f:
        for f in sorted(sast_f, key=lambda x: x['arquivo']):
            md_content += f"\n---\n**Severidade:** {f['severidade']}\n\n"
            md_content += f"**Regra:** `{f['regra']}`\n\n"
            md_content += f"**Localização:** `{f['arquivo']}:{f['linha']}`\n\n"
            md_content += f"**Descrição:** {f['mensagem']}\n"
    else:
        md_content += "\nNenhum achado de SAST.\n"

    # Seção Segredos (formato de bloco)
    md_content += "\n### Vazamento de Segredos\n"
    if gitleaks_f:
        for f in sorted(gitleaks_f, key=lambda x: x['arquivo']):
            md_content += f"\n---\n**Severidade:** {f['severidade']}\n\n"
            md_content += f"**Descrição:** {f['regra']}\n\n"
            md_content += f"**Localização:** `{f['arquivo']}:{f['linha']}`\n\n"
            md_content += f"**Padrão identificado:** `{f['padrao']}`\n"
    else:
        md_content += "\nNenhum segredo encontrado.\n"

    # Seção SCA (formato de bloco)
    md_content += "\n### Análise de Dependências (SCA)\n"
    if trivy_f:
        for f in sorted(trivy_f, key=lambda x: x['pacote']):
            md_content += f"\n---\n**Severidade:** {f['severidade']}\n\n"
            md_content += f"**Pacote:** `{f['pacote']} (versão: {f['versao']})`\n\n"
            md_content += f"**Vulnerabilidade:** `{f['regra']}`\n\n"
            md_content += f"**Título:** {f['titulo']}\n"
    else:
        md_content += "\nNenhuma dependência vulnerável encontrada.\n"

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

