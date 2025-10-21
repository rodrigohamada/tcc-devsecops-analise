#!/usr/bin/env python3
import json
import os
import sys
from datetime import datetime
from zoneinfo import ZoneInfo
from googletrans import Translator

tradutor = Translator()


def traduzir_mensagem(mensagem):
    try:
        texto = (mensagem or "").strip()
        if not texto:
            return ""
        traducao = tradutor.translate(texto, src="en", dest="pt").text
        return traducao
    except Exception:
        return mensagem


def _safe_load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"⚠️  Arquivo não encontrado: {path}")
    except json.JSONDecodeError as e:
        print(f"⚠️  JSON inválido em {path}: {e}")
    except Exception as e:
        print(f"⚠️  Erro ao ler {path}: {e}")
    return None


def carregar_resultados(caminho_semgrep, caminho_gitleaks, caminho_trivy, caminho_trivy_imagem):
    resultados = {
        "sast": [],
        "secrets": [],
        "sca": [],
        "imagem": []
    }

    # ========= SEMGREP =========
    dados = _safe_load_json(caminho_semgrep)
    if isinstance(dados, dict):
        for item in dados.get("results", []):
            sev_orig = (item.get("extra", {}).get("severity", "") or "").upper()
            mapeamento = {
                "ERROR": "CRÍTICA",
                "CRITICAL": "CRÍTICA",
                "HIGH": "ALTA",
                "WARNING": "MÉDIA",
                "MEDIUM": "MÉDIA",
                "LOW": "BAIXA",
                "INFO": "BAIXA",
                "UNKNOWN": "DESCONHECIDA",
            }
            severidade = mapeamento.get(sev_orig, "DESCONHECIDA")
            descricao = item.get("extra", {}).get("message", "")
            resultados["sast"].append({
                "severidade": severidade,
                "regra": item.get("check_id", ""),
                "localizacao": f"{item.get('path', '')}:{item.get('start', {}).get('line', '')}",
                "descricao": traduzir_mensagem(descricao)
            })

    # ========= GITLEAKS =========
    dados = _safe_load_json(caminho_gitleaks)
    if isinstance(dados, list):
        for item in dados:
            descricao = item.get("Description", "Segredo exposto")
            resultados["secrets"].append({
                "severidade": "CRÍTICA",
                "descricao": traduzir_mensagem(descricao),
                "localizacao": f"{item.get('File', '')}:{item.get('StartLine', '')}",
                "padrao": item.get("Secret", "N/A"),
            })

    # ========= TRIVY (SCA) =========
    print("\n📊 Trivy (SCA): análise de dependências Python")
    dados_trivy = _safe_load_json(caminho_trivy)
    resultados_sca = processar_trivy(dados_trivy)
    resultados["sca"].extend(resultados_sca)

    # ========= TRIVY (Imagem) =========
    print("\n🐳 Trivy (Imagem): análise de vulnerabilidades da imagem base")
    dados_img = _safe_load_json(caminho_trivy_imagem)
    resultados_img = processar_trivy(dados_img, is_imagem=True)

    # Deduplicação cruzada: imagem x dependências
    print("\n🧹 Verificando duplicatas entre imagem e dependências...")
    vistos_sca = {(v['vuln_id'], v['pacote'], v['versao_instalada'], v['versao_corrigida'])
                  for v in resultados['sca']}
    imagem_filtrada = []
    duplicatas = 0
    for v in resultados_img:
        chave = (v['vuln_id'], v['pacote'], v['versao_instalada'], v['versao_corrigida'])
        if chave in vistos_sca:
            duplicatas += 1
            continue
        imagem_filtrada.append(v)
    print(f"✅ Duplicatas entre imagem e dependências removidas: {duplicatas}")
    resultados["imagem"].extend(imagem_filtrada)

    return resultados


def processar_trivy(dados, is_imagem=False):
    achados = []
    vistos = set()
    if not dados:
        print("⚠️  Nenhum resultado do Trivy encontrado.")
        return achados

    resultados_trivy = []
    if isinstance(dados, dict):
        resultados_trivy = dados.get("Results", [])
    elif isinstance(dados, list):
        resultados_trivy = dados

    total = 0
    duplicados = 0
    for idx, r in enumerate(resultados_trivy):
        target = r.get("Target", f"alvo-{idx+1}")
        vulns = r.get("Vulnerabilities", [])
        for v in vulns:
            total += 1
            vuln_id = v.get("VulnerabilityID", "N/A")
            pacote = v.get("PkgName", "")
            versao_instalada = v.get("InstalledVersion", "")
            versao_corrigida = v.get("FixedVersion", "N/A")
            chave = (vuln_id, pacote, versao_instalada, versao_corrigida, target)
            if chave in vistos:
                duplicados += 1
                continue
            vistos.add(chave)

            sev = (v.get("Severity") or "UNKNOWN").upper()
            mapeamento = {
                "CRITICAL": "CRÍTICA",
                "HIGH": "ALTA",
                "MEDIUM": "MÉDIA",
                "LOW": "BAIXA",
                "UNKNOWN": "DESCONHECIDA",
            }
            severidade = mapeamento.get(sev, "DESCONHECIDA")

            titulo = traduzir_mensagem(v.get("Title", "Vulnerabilidade"))
            descricao_parts = [titulo]
            if pacote:
                descricao_parts.append(f"Pacote: {pacote}")
            if versao_instalada:
                descricao_parts.append(f"Versão instalada: {versao_instalada}")
            if versao_corrigida and versao_corrigida != "N/A":
                descricao_parts.append(f"Versão corrigida: {versao_corrigida}")
            descricao = " | ".join(descricao_parts)

            achados.append({
                "severidade": severidade,
                "vuln_id": vuln_id,
                "title": titulo,
                "target": target,
                "pacote": pacote,
                "versao_instalada": versao_instalada,
                "versao_corrigida": versao_corrigida,
                "descricao": traduzir_mensagem(descricao),
            })
    print(f"✅ Trivy {'Imagem' if is_imagem else 'SCA'}: {len(achados)} achados (ignoradas {duplicados} duplicatas).")
    return achados


def gerar_relatorio(nome_repositorio, resultados, caminho_saida):
    agora = datetime.now(ZoneInfo("America/Sao_Paulo"))
    todos = resultados["sast"] + resultados["secrets"] + resultados["sca"] + resultados["imagem"]
    dist = {s: 0 for s in ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA", "DESCONHECIDA"]}
    for f in todos:
        dist[f.get("severidade", "DESCONHECIDA")] += 1

    with open(caminho_saida, "w", encoding="utf-8") as f:
        f.write(f"""# Relatório de Análise de Segurança

**Repositório Analisado:** `{nome_repositorio}`  
**Data do Scan:** {agora.strftime('%d/%m/%Y %H:%M:%S')} (Horário de Brasília)

---

## Resumo Executivo

| Métrica | Quantidade |
|---------|------------|
| **Total de Achados** | **{len(todos)}** |
| Análise Estática (SAST) | {len(resultados['sast'])} |
| Vazamento de Segredos | {len(resultados['secrets'])} |
| Dependências (SCA)** | {len(resultados['sca'])} |
| Imagem Base (Docker)** | {len(resultados['imagem'])} |

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
""")

        _escrever_secao(f, "Análise Estática (SAST)", resultados["sast"], tipo="sast")
        _escrever_secao(f, "Vazamento de Segredos", resultados["secrets"], tipo="secrets")
        _escrever_secao(f, "Análise de Dependências (SCA - Python)", resultados["sca"])
        _escrever_secao(f, "Vulnerabilidades na Imagem Base (Docker)", resultados["imagem"])

        f.write("""
---

## Conclusões e Recomendações

- Corrigir vulnerabilidades críticas imediatamente.  
- Revogar e rotacionar segredos expostos.  
- Atualizar pacotes e imagem base para versões seguras.  
- Reexecutar os scans após aplicar correções.  
- Adotar práticas DevSecOps contínuas no pipeline de CI/CD.  
""")

    print(f"\n✅ Relatório gerado com sucesso: {caminho_saida}")


def _escrever_secao(f, titulo, dados, tipo="vuln"):
    f.write(f"\n### {titulo}\n")
    if not dados:
        f.write("\nNenhum achado encontrado.\n")
        return

    if tipo == "sast":
        for idx, fnd in enumerate(dados, 1):
            f.write(f"""
#### Achado SAST #{idx}
**Severidade:** {fnd['severidade']}  
**Regra:** `{fnd['regra']}`  
**Localização:** `{fnd['localizacao']}`  
**Descrição:** {fnd['descricao']}  
---
""")
    elif tipo == "secrets":
        for idx, fnd in enumerate(dados, 1):
            f.write(f"""
#### Segredo #{idx}
**Severidade:** {fnd['severidade']}  
**Descrição:** {fnd['descricao']}  
**Localização:** `{fnd['localizacao']}`  
**Padrão identificado:** `{fnd.get('padrao', 'N/A')[:8]}...`  
---
""")
    else:
        _escrever_vulns(f, dados)


def _escrever_vulns(f, vulnerabilidades):
    agrupadas = {}
    for v in vulnerabilidades:
        agrupadas.setdefault(v["severidade"], []).append(v)
    ordem = ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA", "DESCONHECIDA"]
    contador = 1
    for sev in ordem:
        vulns = agrupadas.get(sev, [])
        if not vulns:
            continue
        f.write(f"\n#### Vulnerabilidades de Severidade {sev}\n\n")
        for v in vulns:
            f.write(f"""
##### Vulnerabilidade #{contador}
**Severidade:** {v['severidade']}  
**ID da Vulnerabilidade:** `{v['vuln_id']}`  
**Título:** {v['title']}  
**Alvo:** `{v['target']}`  
**Pacote:** `{v['pacote']}`  
**Versão Instalada:** `{v['versao_instalada']}`  
**Versão Corrigida:** `{v['versao_corrigida']}`  
**Descrição:** {v['descricao']}  
---
""")
            contador += 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Erro: nome do repositório não informado.")
        sys.exit(1)

    nome_repositorio = sys.argv[1]
    caminho_semgrep = "saida-semgrep.json"
    caminho_gitleaks = "saida-gitleaks.json"
    caminho_trivy = "saida-trivy.json"
    caminho_trivy_imagem = "saida-trivy-imagem.json"
    caminho_saida = f"relatorio-{nome_repositorio}.md"

    print(f"\n🔍 Iniciando geração de relatório para: {nome_repositorio}")
    print("=" * 60)
    resultados = carregar_resultados(caminho_semgrep, caminho_gitleaks, caminho_trivy, caminho_trivy_imagem)
    gerar_relatorio(nome_repositorio, resultados, caminho_saida)

    with open("temp-report-for-pdf.md", "w", encoding="utf-8") as temp:
        temp.write(open(caminho_saida, encoding="utf-8").read())

    print(f"📄 Relatório salvo: {caminho_saida}")
