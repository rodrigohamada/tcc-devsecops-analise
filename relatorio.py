import json
import os
import sys
from datetime import datetime

def carregar_resultados(caminho_semgrep, caminho_gitleaks, caminho_trivy):
    resultados = {
        "sast": [],
        "secrets": [],
        "sca": []
    }

    # SEMGREP
    if os.path.isfile(caminho_semgrep):
        with open(caminho_semgrep, 'r', encoding='utf-8') as f:
            try:
                dados = json.load(f)
                for item in dados.get("results", []):
                    sev_orig = item.get("extra", {}).get("severity", "").upper()
                    if sev_orig == "ERROR":
                        severidade = "CRÍTICA"
                    elif sev_orig == "WARNING":
                        severidade = "MÉDIA"
                    elif sev_orig == "CRITICAL":
                        severidade = "CRÍTICA"
                    elif sev_orig == "HIGH":
                        severidade = "ALTA"
                    elif sev_orig == "MEDIUM":
                        severidade = "MÉDIA"
                    elif sev_orig == "LOW":
                        severidade = "BAIXA"
                    elif sev_orig == "UNKNOWN":
                        severidade = "DESCONHECIDA"
                    else:
                        severidade = "DESCONHECIDA"

                    resultados["sast"].append({
                        "severidade": severidade,
                        "regra": item.get("check_id", ""),
                        "localizacao": f"{item.get('path', '')}:{item.get('start', {}).get('line', '')}",
                        "descricao": item.get("extra", {}).get("message", "")
                    })
            except json.JSONDecodeError:
                print("Aviso: JSON do Semgrep inválido.")

    # GITLEAKS
    if os.path.isfile(caminho_gitleaks):
        with open(caminho_gitleaks, 'r', encoding='utf-8') as f:
            try:
                dados = json.load(f)
                for item in dados:
                    resultados["secrets"].append({
                        "severidade": "CRÍTICA",
                        "descricao": item.get("Description", "Segredo exposto"),
                        "localizacao": f"{item.get('File', '')}:{item.get('StartLine', '')}",
                        "padrao": item.get("Secret", "N/A")
                    })
            except json.JSONDecodeError:
                print("Aviso: JSON do Gitleaks inválido.")

    # TRIVY
    if os.path.isfile(caminho_trivy):
        with open(caminho_trivy, 'r', encoding='utf-8') as f:
            try:
                dados = json.load(f)
                resultados_trivy = dados.get("Results", [])
                for r in resultados_trivy:
                    for v in r.get("Vulnerabilities", []):
                        sev = v.get("Severity", "UNKNOWN").upper()
                        if sev == "CRITICAL":
                            severidade = "CRÍTICA"
                        elif sev == "HIGH":
                            severidade = "ALTA"
                        elif sev == "MEDIUM":
                            severidade = "MÉDIA"
                        elif sev == "LOW":
                            severidade = "BAIXA"
                        else:
                            severidade = "DESCONHECIDA"

                        resultados["sca"].append({
                            "severidade": severidade,
                            "descricao": f"{v.get('Title', 'Vuln')} - {v.get('PkgName', '')}@{v.get('InstalledVersion', '')}"
                        })
            except json.JSONDecodeError:
                print("Aviso: JSON do Trivy inválido.")

    return resultados

def gerar_relatorio(nome_repositorio, resultados, caminho_saida):
    todos = resultados['sast'] + resultados['secrets'] + resultados['sca']
    dist = {s: 0 for s in ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA", "DESCONHECIDA"]}
    for f in todos:
        dist[f.get("severidade", "DESCONHECIDA")] += 1

    with open(caminho_saida, 'w', encoding='utf-8') as f:
        f.write(f"""
# Relatório de Análise de Segurança

**Repositório Analisado:** `{nome_repositorio}`  
**Data do Scan:** {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}

---

## Resumo Executivo

| Métrica | Quantidade |
|---------|------------|
| **Total de Achados** | **{len(todos)}** |
| Análise Estática (SAST) | {len(resultados['sast'])} |
| Vazamento de Segredos | {len(resultados['secrets'])} |
| Análise de Dependências (SCA) | {len(resultados['sca'])} |

---

## Distribuição por Severidade

| Severidade | Quantidade |
|------------|------------|
| CRÍTICA | {dist['CRÍTICA']} |
| ALTA | {dist['ALTA']} |
| MÉDIA | {dist['MÉDIA']} |
| BAIXA | {dist['BAIXA']} |
| DESCONHECIDA | {dist['DESCONHECIDA']} |

---

## Detalhamento dos Achados

### Análise Estática (SAST)
""")
        if resultados['sast']:
            for fnd in resultados['sast']:
                f.write(f"""
**Severidade:** {fnd['severidade']}  
**Regra:** {fnd['regra']}  
**Localização:** `{fnd['localizacao']}`  
**Descrição:** {fnd['descricao']}  

---
""")
        else:
            f.write("Nenhum achado SAST encontrado.\n")

        f.write("""
### Vazamento de Segredos
""")
        if resultados['secrets']:
            for fnd in resultados['secrets']:
                f.write(f"""
**Severidade:** {fnd['severidade']}  
**Descrição:** {fnd['descricao']}  
**Localização:** `{fnd['localizacao']}`  
**Padrão identificado:** `{fnd['padrao'][:6]}...`  

---
""")
        else:
            f.write("Nenhum segredo encontrado.\n")

        f.write("""
### Análise de Dependências (SCA)
""")
        if resultados['sca']:
            for fnd in resultados['sca']:
                f.write(f"""
**Severidade:** {fnd['severidade']}  
**Descrição:** {fnd['descricao']}  

---
""")
        else:
            f.write("Nenhuma vulnerabilidade em dependências.\n")

        f.write("""
---

## Conclusões e Recomendações

- Corrigir vulnerabilidades críticas imediatamente.  
- Revogar e rotacionar segredos expostos.  
- Evitar interpolação insegura em scripts e workflows.  
- Aplicar boas práticas de desenvolvimento seguro em Flask e SQL.  
- Reexecutar os scans após aplicar correções.  
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Erro: nome do repositório não informado.")
        sys.exit(1)

    nome_repositorio = sys.argv[1]
    caminho_semgrep = "saida-semgrep.json"
    caminho_gitleaks = "saida-gitleaks.json"
    caminho_trivy = "saida-trivy.json"
    caminho_saida = f"relatorio-{nome_repositorio}.md"

    resultados = carregar_resultados(caminho_semgrep, caminho_gitleaks, caminho_trivy)
    gerar_relatorio(nome_repositorio, resultados, caminho_saida)
    print(f"Relatório gerado: {caminho_saida}")
