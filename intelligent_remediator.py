# remediation_report.py
import json
import sys
import datetime

def generate_remediation_report(repo_url):
    """
    Lê o plano de remediação e gera um relatório detalhado em Markdown.
    """
    try:
        with open("remediation_plan.json", 'r', encoding='utf-8') as f:
            plan = json.load(f)
    except FileNotFoundError:
        print("Arquivo remediation_plan.json não encontrado.")
        return

    # Extrai as informações do plano
    repo_name = repo_url.split('/')[-1]
    rule = plan.get('rule', 'N/A')
    severity = plan.get('severity', 'N/A')
    file_path = plan.get('file', 'N/A')
    line = plan.get('line', 'N/A')
    vulnerable_code = plan.get('vulnerable_code', '# Código vulnerável não encontrado')
    suggested_fix = plan.get('suggested_fix', '# Sugestão da IA não encontrada')

    # Monta o conteúdo do relatório
    md_content = f"""
# Relatório de Remediação Automática por IA

- **Repositório Alvo:** `{repo_url}`
- **Data da Ação:** {datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")}
- **Agente Executor:** DevSecOps AI Bot

## Detalhes da Vulnerabilidade Detectada

- **Severidade:** `{severity}`
- **Tipo de Problema:** `{rule}`
- **Arquivo Afetado:** `{file_path}`
- **Linha:** `{line}`

---

## Análise e Ação de Remediação

O agente de IA analisou a vulnerabilidade e propôs a seguinte correção, que foi aplicada em uma nova branch para revisão.

### Código Vulnerável Identificado:
```
{vulnerable_code}
```

### Correção Sugerida pela IA e Aplicada:
```
{suggested_fix}
```

**Próximos Passos:**
Um Pull Request foi gerado automaticamente com esta correção. A revisão e o teste por um humano são necessários antes de aprovar e integrar a mudança.
"""

    # Salva o relatório em um arquivo .md
    with open("remediation-report.md", "w", encoding="utf-8") as f:
        f.write(md_content)
    
    print("✅ Relatório de remediação (remediation-report.md) gerado com sucesso.")


if __name__ == "__main__":
    # A URL do repositório será passada como um argumento pelo workflow
    target_repo_url = sys.argv[1] if len(sys.argv) > 1 else "URL não fornecida"
    generate_remediation_report(target_repo_url)

