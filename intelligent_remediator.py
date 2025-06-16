# intelligent_remediator.py
import json
import os
import sys

# ==============================================================================
# FUNÇÕES DE CHAMADA DA IA (usando a API do Gemini)
# ==============================================================================
async def ask_generative_ai(prompt):
    """Função genérica para enviar um prompt para a IA e retornar a resposta."""
    print(f"🤖 Enviando prompt para a IA:\n---\n{prompt}\n---")
    chatHistory = [{"role": "user", "parts": [{"text": prompt}]}]
    payload = {"contents": chatHistory}
    apiKey = ""  # Deixe em branco para o ambiente do Canvas
    apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={apiKey}"
    
    try:
        response = await fetch(apiUrl, {
            "method": 'POST',
            "headers": {'Content-Type': 'application/json'},
            "body": JSON.stringify(payload)
        })
        result = await response.json()
        
        if result.get("candidates"):
            fix = result["candidates"][0]["content"]["parts"][0]["text"].strip()
            print(f"🧠 IA respondeu:\n---\n{fix}\n---")
            # Remove ``` e nomes de linguagem para obter apenas o código puro
            if fix.startswith("```"):
                fix = '\n'.join(fix.split('\n')[1:-1])
            return fix
    except Exception as e:
        print(f"❌ Erro ao chamar a API da IA: {e}")
    return None

# ==============================================================================
# FUNÇÕES DE PROMPT ENGINEERING (O CORAÇÃO DA INTELIGÊNCIA)
# ==============================================================================
def create_remediation_plan(finding):
    """Cria um prompt específico baseado no tipo de vulnerabilidade."""
    file_path = finding['file']
    line_number = finding['line']
    
    # Lê o trecho de código original do arquivo para dar contexto à IA
    try:
        with open(os.path.join("target_repo", file_path), 'r') as f:
            lines = f.readlines()
            # Pega 3 linhas de contexto antes e depois
            context_start = max(0, line_number - 4)
            context_end = min(len(lines), line_number + 3)
            code_snippet = "".join(lines[context_start:context_end])
            vulnerable_line = lines[line_number - 1].strip()
    except Exception:
        code_snippet = "Não foi possível ler o trecho de código."
        vulnerable_line = ""

    prompt = ""
    # ---- LÓGICA PARA VULNERABILIDADES DE SAST (SEMREP) ----
    if finding['type'] == 'SAST':
        prompt = f"""
        **Contexto:** Análise de Segurança de Código (SAST).
        **Problema:** A ferramenta Semgrep encontrou a vulnerabilidade de '{finding['rule']}' no arquivo '{file_path}' na linha {line_number}.
        **Severidade:** {finding['severity']}
        **Trecho de Código Vulnerável:**
        ```
        {code_snippet}
        ```
        **Linha exata com o problema:**
        `{vulnerable_line}`

        **Sua Tarefa:**
        Reescreva APENAS a linha exata que contém a vulnerabilidade (`{vulnerable_line}`) de forma corrigida. Se a correção exigir mais de uma linha, reescreva o trecho de código necessário. Sua resposta deve conter APENAS o código corrigido, sem nenhuma explicação.
        """
        finding['action'] = 'REPLACE_LINE' # Define a ação que o robô deve tomar
        finding['vulnerable_code'] = vulnerable_line
        
    # ---- LÓGICA PARA SEGREDOS EXPOSTOS (GITLEAKS) ----
    elif finding['type'] == 'SECRET':
        prompt = f"""
        **Contexto:** Vazamento de Segredo.
        **Problema:** A ferramenta Gitleaks encontrou um segredo do tipo '{finding['rule']}' no arquivo '{file_path}' na linha {line_number}.
        
        **Sua Tarefa:**
        Remova esta linha e, em seu lugar, gere um código de exemplo genérico para a linguagem do arquivo '{file_path}' que carregue esta variável a partir de uma variável de ambiente.
        Sua resposta deve conter APENAS o código corrigido, sem nenhuma explicação.
        Exemplo para Python: `API_KEY = os.getenv("API_KEY_SECRET")`
        """
        finding['action'] = 'REPLACE_LINE' # A ação é substituir a linha do segredo
        finding['vulnerable_code'] = vulnerable_line
        
    # ---- LÓGICA PARA DEPENDÊNCIAS VULNERÁVEIS (TRIVY) ----
    elif finding['type'] == 'SCA':
        prompt = f"""
        **Contexto:** Análise de Dependências (SCA).
        **Problema:** A ferramenta Trivy encontrou que a dependência '{finding['package']}' na versão '{finding['version']}' é vulnerável ({finding['vuln_id']}). O arquivo de dependências é o '{file_path}'.
        
        **Sua Tarefa:**
        Qual é a versão estável e segura mais recente para corrigir isso?
        Responda APENAS com a linha corrigida para o arquivo de dependência, sem nenhuma outra explicação.
        Exemplo de resposta para requirements.txt: `{finding['package']}==1.2.3`
        """
        finding['action'] = 'REPLACE_LINE' # A ação é substituir a linha da dependência
        finding['vulnerable_code'] = f"{finding['package']}=={finding['version']}"

    finding['prompt'] = prompt
    return finding

# ==============================================================================
# FUNÇÃO PRINCIPAL
# ==============================================================================
async def main():
    # Carrega todos os relatórios
    with open("semgrep-output.json") as f: semgrep_data = json.load(f)
    with open("gitleaks-output.json") as f: gitleaks_data = json.load(f)
    with open("trivy-output.json") as f: trivy_data = json.load(f)

    all_findings = []
    # Processa e unifica os achados de todas as ferramentas
    for r in semgrep_data.get("results", []):
        all_findings.append({'type': 'SAST', 'rule': r["check_id"], 'severity': r["extra"]["severity"], 'file': r["path"], 'line': r["start"]["line"]})
    for r in gitleaks_data:
        all_findings.append({'type': 'SECRET', 'rule': r["Description"], 'severity': 'CRITICAL', 'file': r["File"], 'line': r["StartLine"]})
    if trivy_data.get("Results"):
        for res in trivy_data["Results"]:
            if res.get("Target") == "requirements.txt":
                for v in res.get("Vulnerabilities", []):
                    all_findings.append({'type': 'SCA', 'vuln_id': v.get("VulnerabilityID"), 'package': v.get("PkgName"), 'version': v.get("InstalledVersion"), 'severity': v.get("Severity"), 'file': res.get("Target"), 'line': -1}) # Linha não é relevante para SCA

    # Filtra apenas por vulnerabilidades críticas ou altas
    critical_findings = [f for f in all_findings if f['severity'] in ['CRITICAL', 'HIGH']]

    if not critical_findings:
        print("✅ Nenhuma vulnerabilidade crítica ou alta encontrada. Nenhuma ação necessária.")
        return

    # Pega apenas o primeiro achado crítico para este exemplo
    first_critical_finding = critical_findings[0]
    
    # Cria o plano de remediação (com o prompt dinâmico)
    remediation_plan = create_remediation_plan(first_critical_finding)
    
    # Pede a correção para a IA
    suggested_fix = await ask_generative_ai(remediation_plan['prompt'])

    if suggested_fix:
        remediation_plan['suggested_fix'] = suggested_fix
        # Salva o plano completo em um arquivo JSON que o workflow irá ler
        with open("remediation_plan.json", "w") as f:
            json.dump(remediation_plan, f)
        print("✅ Plano de remediação com sugestão da IA foi salvo em remediation_plan.json")
    else:
        print("❌ A IA não conseguiu gerar uma sugestão de correção.")

# Execução da função principal
try:
    import asyncio
    asyncio.run(main())
except:
    main()
