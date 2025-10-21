#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime
from googletrans import Translator

tradutor = Translator()

def traduzir_mensagem(mensagem):
    try:
        return tradutor.translate(mensagem, src="en", dest="pt").text
    except Exception:
        return mensagem

def _safe_load_json(path):
    """Carrega JSON e retorna objeto ou None (com log de erro)."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"⚠️  Arquivo não encontrado: {path}")
    except json.JSONDecodeError as e:
        print(f"⚠️  JSON inválido em {path}: {e}")
    except Exception as e:
        print(f"⚠️  Erro ao ler {path}: {e}")
    return None

def carregar_resultados(caminho_semgrep, caminho_gitleaks, caminho_trivy):
    resultados = {
        "sast": [],
        "secrets": [],
        "sca": []
    }

    # ========== SEMGREP ==========
    dados = _safe_load_json(caminho_semgrep)
    if isinstance(dados, dict):
        for item in dados.get("results", []):
            sev_orig = item.get("extra", {}).get("severity", "") or ""
            sev_orig = sev_orig.upper()
            mapeamento_severidade = {
                "ERROR": "CRÍTICA",
                "CRITICAL": "CRÍTICA",
                "HIGH": "ALTA",
                "WARNING": "MÉDIA",
                "MEDIUM": "MÉDIA",
                "LOW": "BAIXA",
                "INFO": "BAIXA",
                "UNKNOWN": "DESCONHECIDA"
            }
            severidade = mapeamento_severidade.get(sev_orig, "DESCONHECIDA")
            descricao = item.get("extra", {}).get("message", "")
            resultados["sast"].append({
                "severidade": severidade,
                "regra": item.get("check_id", ""),
                "localizacao": f"{item.get('path', '')}:{item.get('start', {}).get('line', '')}",
                "descricao": traduzir_mensagem(descricao)
            })

    # ========== GITLEAKS ==========
    dados = _safe_load_json(caminho_gitleaks)
    if isinstance(dados, list):
        for item in dados:
            descricao = item.get("Description", "Segredo exposto")
            resultados["secrets"].append({
                "severidade": "CRÍTICA",
                "descricao": traduzir_mensagem(descricao),
                "localizacao": f"{item.get('File', '')}:{item.get('StartLine', '')}",
                "padrao": item.get("Secret", "N/A")
            })
    elif isinstance(dados, dict) and "results" in dados:
        # some gitleaks versions produce dict with results
        for item in dados.get("results", []):
            descricao = item.get("Description", "Segredo exposto")
            resultados["secrets"].append({
                "severidade": "CRÍTICA",
                "descricao": traduzir_mensagem(descricao),
                "localizacao": f"{item.get('File', '')}:{item.get('StartLine', '')}",
                "padrao": item.get("Secret", "N/A")
            })

    # ========== TRIVY (SCA) ==========
    dados = _safe_load_json(caminho_trivy)
    if dados is None:
        print(f"⚠️  Nenhum JSON do Trivy carregado ({caminho_trivy}).")
        return resultados

    # Debug: mostrar estrutura inicial
    if isinstance(dados, dict):
        if "Results" in dados:
            resultados_trivy = dados.get("Results", [])
            print(f"📊 Trivy: 'Results' encontrado com {len(resultados_trivy)} item(s).")
        else:
            # Em alguns casos Trivy pode devolver uma lista direta ou outro layout
            # Tentamos detectar vulnerabilidades diretamente
            resultados_trivy = []
            # Se o dict tiver uma chave "Vulnerabilities" direta (menos comum)
            if "Vulnerabilities" in dados:
                resultados_trivy = [dados]
                print("📊 Trivy: 'Vulnerabilities' direto no objeto raiz.")
            else:
                # tentar varrer valores para achar listas de resultados
                for k, v in dados.items():
                    if isinstance(v, list) and any(isinstance(x, dict) and "Vulnerabilities" in x for x in v):
                        resultados_trivy.extend(v)
                if resultados_trivy:
                    print(f"📊 Trivy: detectado 'Results'-like em outra chave, total {len(resultados_trivy)}.")
    elif isinstance(dados, list):
        # Trivy às vezes pode retornar lista de resultados
        resultados_trivy = dados
        print(f"📊 Trivy: JSON é uma lista com {len(resultados_trivy)} item(s).")
    else:
        resultados_trivy = []
        print("📊 Trivy: formato JSON inesperado.")

    total_vulns = 0
    for idx, r in enumerate(resultados_trivy):
        target = r.get("Target", r.get("target", "desconhecido"))
        vulns = r.get("Vulnerabilities", r.get("vulnerabilities", [])) or []
        print(f"   - Target {idx+1}: {target} -> {len(vulns)} vulnerabilidade(s) detectada(s).")
        for v in vulns:
            total_vulns += 1
            sev = (v.get("Severity") or v.get("severity") or "UNKNOWN").upper()
            mapeamento_severidade = {
                "CRITICAL": "CRÍTICA",
                "HIGH": "ALTA",
                "MEDIUM": "MÉDIA",
                "LOW": "BAIXA",
                "UNKNOWN": "DESCONHECIDA"
            }
            severidade = mapeamento_severidade.get(sev, "DESCONHECIDA")

            titulo = v.get('Title') or v.get('title') or v.get('VulnerabilityID') or 'Vulnerabilidade'
            vuln_id = v.get('VulnerabilityID') or v.get('vulnerability_id') or v.get('id') or 'N/A'
            pacote = v.get('PkgName') or v.get('pkgName') or v.get('package') or ''
            versao_instalada = v.get('InstalledVersion') or v.get('installedVersion') or v.get('installed_version') or ''
            versao_corrigida = v.get('FixedVersion') or v.get('fixedVersion') or v.get('fixed_version') or 'N/A'
            descricao_parts = [titulo]
            if pacote:
                descricao_parts.append(f"Pacote: {pacote}")
            if versao_instalada:
                descricao_parts.append(f"Versão instalada: {versao_instalada}")
            if versao_corrigida and versao_corrigida != 'N/A':
                descricao_parts.append(f"Versão corrigida: {versao_corrigida}")
            descricao = " | ".join(descricao_parts)

            resultados["sca"].append({
                "severidade": severidade,
                "vuln_id": vuln_id,
                "title": titulo,
                "target": target,
                "pacote": pacote,
                "versao_instalada": versao_instalada,
                "versao_corrigida": versao_corrigida,
                "descricao": traduzir_mensagem(descricao)
            })

    print(f"✅ Trivy: total de vulnerabilidades SCA encontradas e processadas: {len(resultados['sca'])} (contagem interna: {total_vulns})")

    return resultados

def gerar_relatorio(nome_repositorio, resultados, caminho_saida):
    todos = resultados['sast'] + resultados['secrets'] + resultados['sca']
    dist = {s: 0 for s in ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA", "DESCONHECIDA"]}
    for f in todos:
        dist[f.get("severidade", "DESCONHECIDA")] += 1

    with open(caminho_saida, 'w', encoding='utf-8') as f:
        f.write(f"""# Relatório de Análise de Segurança

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
            for idx, fnd in enumerate(resultados['sast'], 1):
                f.write(f"""
#### Achado SAST #{idx}

**Severidade:** {fnd['severidade']}  
**Regra:** `{fnd.get('regra','')}`  
**Localização:** `{fnd.get('localizacao','')}`  
**Descrição:** {fnd.get('descricao','')}  

---
""")
        else:
            f.write("\nNenhum achado SAST encontrado.\n")

        f.write("\n### Vazamento de Segredos\n")
        if resultados['secrets']:
            for idx, fnd in enumerate(resultados['secrets'], 1):
                pad = fnd.get('padrao','N/A')
                f.write(f"""
#### Segredo #{idx}

**Severidade:** {fnd['severidade']}  
**Descrição:** {fnd['descricao']}  
**Localização:** `{fnd['localizacao']}`  
**Padrão identificado:** `{pad[:8]}...`  

---
""")
        else:
            f.write("\nNenhum segredo encontrado.\n")

        f.write("\n### Análise de Dependências (SCA)\n")
        if resultados['sca']:
            # agrupa por severidade
            sca_por_sev = {}
            for fnd in resultados['sca']:
                sev = fnd.get('severidade','DESCONHECIDA')
                sca_por_sev.setdefault(sev, []).append(fnd)

            ordem = ["CRÍTICA","ALTA","MÉDIA","BAIXA","DESCONHECIDA"]
            contador = 1
            for sev in ordem:
                itens = sca_por_sev.get(sev, [])
                if not itens:
                    continue
                f.write(f"\n#### Vulnerabilidades de Severidade {sev}\n\n")
                for fnd in itens:
                    f.write(f"""
##### Vulnerabilidade SCA #{contador}

**Severidade:** {fnd.get('severidade')}  
**ID da Vulnerabilidade:** `{fnd.get('vuln_id','N/A')}`  
**Título:** {fnd.get('title','N/A')}  
**Alvo:** `{fnd.get('target','N/A')}`  
**Pacote:** `{fnd.get('pacote','N/A')}`  
**Versão Instalada:** `{fnd.get('versao_instalada','N/A')}`  
**Versão Corrigida:** `{fnd.get('versao_corrigida','N/A')}`  
**Descrição:** {fnd.get('descricao','')}  

---
""")
                    contador += 1
        else:
            f.write("\nNenhuma vulnerabilidade em dependências encontrada.\n")

        f.write("""
---

## Conclusões e Recomendações

- Corrigir vulnerabilidades críticas imediatamente.  
- Revogar e rotacionar segredos expostos.  
- Aplicar boas práticas de desenvolvimento seguro.  
- Reexecutar os scans após aplicar correções.  
""")

    print(f"✅ Relatório gerado com sucesso: {caminho_saida}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Erro: nome do repositório não informado.")
        sys.exit(1)

    nome_repositorio = sys.argv[1]
    caminho_semgrep = "saida-semgrep.json"
    caminho_gitleaks = "saida-gitleaks.json"
    caminho_trivy = "saida-trivy.json"
    caminho_saida = f"relatorio-{nome_repositorio}.md"

    print(f"\n🔍 Iniciando geração de relatório para: {nome_repositorio}")
    print("=" * 60)

    resultados = carregar_resultados(caminho_semgrep, caminho_gitleaks, caminho_trivy)
    gerar_relatorio(nome_repositorio, resultados, caminho_saida)

    # Cópia temporária para o Pandoc usar no PDF
    with open("temp-report-for-pdf.md", "w", encoding="utf-8") as temp:
        temp.write(open(caminho_saida, encoding="utf-8").read())

    print(f"Relatório salvo: {caminho_saida}")
