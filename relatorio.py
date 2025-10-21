import json
import os
import sys
from datetime import datetime
from googletrans import Translator

tradutor = Translator()

def traduzir_mensagem(mensagem):
    """Traduz mensagem do inglês para português"""
    try:
        return tradutor.translate(mensagem, src="en", dest="pt").text
    except:
        return mensagem

def carregar_resultados(caminho_semgrep, caminho_gitleaks, caminho_trivy):
    """Carrega e processa resultados das ferramentas de segurança"""
    resultados = {
        "sast": [],
        "secrets": [],
        "sca": []
    }

    # ========== SEMGREP ==========
    if os.path.isfile(caminho_semgrep):
        with open(caminho_semgrep, 'r', encoding='utf-8') as f:
            try:
                dados = json.load(f)
                for item in dados.get("results", []):
                    sev_orig = item.get("extra", {}).get("severity", "").upper()
                    
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
            except json.JSONDecodeError as e:
                print(f"⚠️  Aviso: JSON do Semgrep inválido: {e}")
            except Exception as e:
                print(f"⚠️  Erro ao processar Semgrep: {e}")

    # ========== GITLEAKS ==========
    if os.path.isfile(caminho_gitleaks):
        with open(caminho_gitleaks, 'r', encoding='utf-8') as f:
            try:
                dados = json.load(f)
                if isinstance(dados, list):
                    for item in dados:
                        descricao = item.get("Description", "Segredo exposto")
                        resultados["secrets"].append({
                            "severidade": "CRÍTICA",
                            "descricao": traduzir_mensagem(descricao),
                            "localizacao": f"{item.get('File', '')}:{item.get('StartLine', '')}",
                            "padrao": item.get("Secret", "N/A")
                        })
            except json.JSONDecodeError as e:
                print(f"⚠️  Aviso: JSON do Gitleaks inválido: {e}")
            except Exception as e:
                print(f"⚠️  Erro ao processar Gitleaks: {e}")

    # ========== TRIVY ==========
    if os.path.isfile(caminho_trivy):
        with open(caminho_trivy, 'r', encoding='utf-8') as f:
            try:
                dados = json.load(f)
                resultados_trivy = dados.get("Results", [])
                
                print(f"📊 Trivy encontrou {len(resultados_trivy)} resultado(s)")
                
                for idx, r in enumerate(resultados_trivy):
                    target = r.get("Target", "desconhecido")
                    vulns = r.get("Vulnerabilities", [])
                    
                    print(f"   Target {idx+1}: {target} - {len(vulns)} vulnerabilidade(s)")
                    
                    for v in vulns:
                        sev = v.get("Severity", "UNKNOWN").upper()
                        mapeamento_severidade = {
                            "CRITICAL": "CRÍTICA",
                            "HIGH": "ALTA",
                            "MEDIUM": "MÉDIA",
                            "LOW": "BAIXA",
                            "UNKNOWN": "DESCONHECIDA"
                        }
                        severidade = mapeamento_severidade.get(sev, "DESCONHECIDA")

                        titulo = v.get('Title', 'Vulnerabilidade')
                        vuln_id = v.get('VulnerabilityID', 'N/A')
                        pacote = v.get('PkgName', '')
                        versao_instalada = v.get('InstalledVersion', '')
                        versao_corrigida = v.get('FixedVersion', 'N/A')
                        
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
                            "target": target,
                            "pacote": pacote,
                            "versao_instalada": versao_instalada,
                            "versao_corrigida": versao_corrigida,
                            "descricao": traduzir_mensagem(descricao)
                        })
                
                print(f"✅ Total de vulnerabilidades SCA processadas: {len(resultados['sca'])}")
                
            except json.JSONDecodeError as e:
                print(f"⚠️  Aviso: JSON do Trivy inválido: {e}")
            except Exception as e:
                print(f"⚠️  Erro ao processar Trivy: {e}")
    else:
        print(f"⚠️  Arquivo {caminho_trivy} não encontrado")

    return resultados

def gerar_relatorio(nome_repositorio, resultados, caminho_saida):
    """Gera relatório em formato Markdown"""
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
**Regra:** `{fnd['regra']}`  
**Localização:** `{fnd['localizacao']}`  
**Descrição:** {fnd['descricao']}  

---
""")
        else:
            f.write("\nNenhum achado SAST encontrado.\n")

        f.write("""
### Vazamento de Segredos
""")
        if resultados['secrets']:
            for idx, fnd in enumerate(resultados['secrets'], 1):
                f.write(f"""
#### Segredo #{idx}

**Severidade:** {fnd['severidade']}  
**Descrição:** {fnd['descricao']}  
**Localização:** `{fnd['localizacao']}`  
**Padrão identificado:** `{fnd['padrao'][:8]}...`  

---
""")
        else:
            f.write("\nNenhum segredo encontrado.\n")

        f.write("""
### Análise de Dependências (SCA)
""")
        if resultados['sca']:
            sca_por_severidade = {}
            for fnd in resultados['sca']:
                sev = fnd['severidade']
                sca_por_severidade.setdefault(sev, []).append(fnd)
            
            ordem_severidade = ["CRÍTICA", "ALTA", "MÉDIA", "BAIXA", "DESCONHECIDA"]
            contador_global = 1
            for severidade in ordem_severidade:
                if severidade in sca_por_severidade:
                    f.write(f"\n#### Vulnerabilidades de Severidade {severidade}\n\n")
                    for fnd in sca_por_severidade[severidade]:
                        f.write(f"""
##### Vulnerabilidade SCA #{contador_global}

**Severidade:** {fnd['severidade']}  
**ID da Vulnerabilidade:** `{fnd.get('vuln_id', 'N/A')}`  
**Alvo:** `{fnd.get('target', 'N/A')}`  
**Pacote:** `{fnd.get('pacote', 'N/A')}`  
**Versão Instalada:** `{fnd.get('versao_instalada', 'N/A')}`  
**Versão Corrigida:** `{fnd.get('versao_corrigida', 'N/A')}`  
**Descrição:** {fnd['descricao']}  

---
""")
                        contador_global += 1
        else:
            f.write("\nNenhuma vulnerabilidade em dependências encontrada.\n")

        f.write(f"""
---

## Conclusões e Recomendações

### Ações Imediatas (Severidade Crítica: {dist['CRÍTICA']})
""")
        
        if dist['CRÍTICA'] > 0:
            f.write("""
- Prioridade máxima: corrigir todas as vulnerabilidades críticas imediatamente
- Revogar e rotacionar todos os segredos expostos
- Implementar sanitização adequada nas entradas de usuário
- Atualizar dependências vulneráveis para versões seguras
""")
        else:
            f.write("\nNenhuma vulnerabilidade crítica encontrada.\n")

        f.write("""
### Boas Práticas Gerais

1. **Desenvolvimento Seguro**
   - Validar e sanitizar entradas
   - Usar consultas parametrizadas
   - Evitar funções inseguras como eval()

2. **Gerenciamento de Segredos**
   - Não commitar credenciais
   - Usar gerenciadores de segredos
   - Rotacionar periodicamente

3. **Dependências**
   - Atualizar regularmente
   - Usar ferramentas de análise no CI/CD

4. **Configuração**
   - Desativar modo debug em produção
   - Aplicar logging e monitoramento adequados

5. **Revalidação**
   - Reexecutar scans após correções
   - Realizar auditorias periódicas

---

**Relatório gerado automaticamente pelo Scanner de Segurança Universal**
""")

    print(f"✅ Relatório gerado com sucesso: {caminho_saida}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("❌ Erro: nome do repositório não informado.")
        print("Uso: python3 relatorio.py <nome-repositorio>")
        sys.exit(1)

    nome_repositorio = sys.argv[1]
    caminho_semgrep = "saida-semgrep.json"
    caminho_gitleaks = "saida-gitleaks.json"
    caminho_trivy = "saida-trivy.json"
    caminho_saida = f"relatorio-{nome_repositorio}.md"

    print(f"\n🔍 Iniciando geração de relatório para: {nome_repositorio}")
    print("=" * 60)

    resultados = carregar_resultados(caminho_semgrep, caminho_gitleaks, caminho_trivy)
    
    print("\n📊 Resumo dos resultados:")
    print(f"   - SAST: {len(resultados['sast'])} achados")
    print(f"   - Secrets: {len(resultados['secrets'])} achados")
    print(f"   - SCA: {len(resultados['sca'])} achados")
    print("=" * 60)
    
    gerar_relatorio(nome_repositorio, resultados, caminho_saida)

    # Cópia temporária para PDF
    with open("temp-report-for-pdf.md", "w", encoding="utf-8") as temp:
        temp.write(open(caminho_saida, encoding="utf-8").read())

    print(f"📄 Relatório salvo em: {caminho_saida}")
    print(f"📄 Cópia temporária para PDF: temp-report-for-pdf.md\n")

    # ========= GERAÇÃO DE PDF =========
    print("🧾 Gerando PDF com pandoc (XeLaTeX)...")
    os.system(
        'pandoc '
        '-V geometry:"a4paper, margin=1in" '
        '-V mainfont="DejaVu Sans" '
        '--pdf-engine=xelatex '
        '--table-of-contents '
        '"temp-report-for-pdf.md" '
        f'-o "relatorio-{nome_repositorio}.pdf"'
    )

    print(f"✅ PDF gerado com sucesso: relatorio-{nome_repositorio}.pdf")
