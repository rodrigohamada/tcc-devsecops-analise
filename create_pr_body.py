# create_pr_body.py
import json

def create_pull_request_body():
    """Lê o plano de remediação e gera o corpo do Pull Request em um arquivo."""
    
    try:
        with open("remediation_plan.json", 'r', encoding='utf-8') as f:
            plan = json.load(f)
    except FileNotFoundError:
        print("Erro: remediation_plan.json não encontrado.")
        return

    # Extrai os detalhes do plano
    rule_id = plan.get('rule', 'N/A')
    file_to_fix = plan.get('file', 'N/A')
    vulnerable_code = plan.get('vulnerable_code', '# Código vulnerável não encontrado')
    suggested_fix = plan.get('suggested_fix', '# Sugestão da IA não encontrada')
    
    # Monta o corpo do PR no formato Markdown
    pr_body = f"""
### 🤖 Remediação Automática por IA

Este Pull Request foi gerado automaticamente pelo Agente de Segurança para corrigir a vulnerabilidade **{rule_id}**.

**Arquivo Afetado:** `{file_to_fix}`
***
#### Código Vulnerável Identificado
```
{vulnerable_code}
```

#### Correção Sugerida pela IA
```
{suggested_fix}
```
***
**Ação Necessária:** Por favor, revise a alteração, execute os testes necessários e aprove este Pull Request.

*Um relatório detalhado em PDF desta ação está disponível nos artefatos desta execução do workflow.*
"""

    # Salva o corpo em um arquivo
    with open("pr_body.md", "w", encoding='utf-8') as f:
        f.write(pr_body)

    print("✅ Corpo do Pull Request (pr_body.md) gerado com sucesso.")


if __name__ == "__main__":
    create_pull_request_body()

