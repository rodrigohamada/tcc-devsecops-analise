import json
import os
import sys
import requests # Usando a biblioteca padrão 'requests' para chamadas de rede

# ==============================================================================
# FUNÇÃO DE CHAMADA DA IA (usando a API do Gemini com a biblioteca 'requests')
# ==============================================================================
def ask_generative_ai(prompt):
    """Função genérica para enviar um prompt para a IA e retornar a resposta."""
    print(f"🤖 Enviando prompt para a IA:\n---\n{prompt}\n---")
    
    chatHistory = [{"role": "user", "parts": [{"text": prompt}]}]
    payload = {"contents": chatHistory}
    apiKey = ""  # Deixe em branco para o ambiente do Canvas
    apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={apiKey}"
    
    try:
        response = requests.post(apiUrl, json=payload, headers={'Content-Type': 'application/json'})
        response.raise_for_status() # Lança um erro se a resposta for um erro de HTTP
        result = response.json()
        
        if result.get("candidates"):
            fix = result["candidates"][0]["content"]["parts"][0]["text"].strip()
            print(f"🧠 IA respondeu:\n---\n{fix}\n---")
            if fix.startswith("```"):
                fix = '\n'.join(fix.split('\n')[1:-1])
            return fix
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao chamar a API da IA: {e}")
    return None

# ==============================================================================
# FUNÇÕES DE PROMPT ENGINEERING (O CORAÇÃO DA INTELIGÊNCIA)
# ==============================================================================
def create_remediation_plan(finding):
    """Cria um prompt específico baseado no tipo de vulnerabilidade."""
    file_path = finding['file']
    
    # Contexto de código apenas para SAST e Segredos
    code_snippet = "N/A"
    vulnerable_line = ""
    if finding['type'] in ['SAST', 'SECRET']:
        line_number = finding['line']
        try:
            with open(os.path.join("target_repo", file_path), 'r') as f:
                lines = f.readlines()
                context_start = max(0, line_number - 4)
                context_end = min(len(lines), line_number + 3)
                code_snippet = "".join(lines[context_start:context_end])
                vulnerable_line = lines[line_number - 1].strip()
        except Exception as e:
            print(f"Aviso: não foi possível ler o trecho de código para {file_path}. Erro: {e}")
            code_snippet = "Não foi possível ler o trecho de código."
    
    prompt = ""
    if finding['type'] == 'SAST':
        prompt = f"**Contexto:** Análise de Segurança de Código (SAST).\n**Problema:** A ferramenta Semgrep encontrou a vulnerabilidade de '{finding['rule']}' no arquivo '{file_path}' na linha {finding['line']}.\n**Trecho de Código Vulnerável:**\n```\n{code_snippet}\n```\n**Linha exata com o problema:**\n`{vulnerable_line}`\n\n**Sua Tarefa:**\nReescreva APENAS a linha exata que contém a vulnerabilidade (`{vulnerable_line}`) de forma corrigida. Se a correção exigir mais de uma linha, reescreva o trecho de código necessário. Sua resposta deve conter APENAS o código corrigido, sem nenhuma explicação."
        finding['action'] = 'REPLACE_LINE'
        finding['vulnerable_code'] = vulnerable_line
        
    elif finding['type'] == 'SECRET':
        prompt = f"**Contexto:** Vazamento de Segredo.\n**Problema:** A ferramenta Gitleaks encontrou um segredo do tipo '{finding['rule']}' no arquivo '{file_path}' na linha {finding['line']}.\n\n**Sua Tarefa:**\nRemova esta linha e, em seu lugar, gere um código de exemplo genérico para a linguagem do arquivo '{file_path}' que carregue esta variável a partir de uma variável de ambiente. Sua resposta deve conter APENAS o código corrigido, sem nenhuma explicação.\nExemplo para Python: `API_KEY = os.getenv(\"API_KEY_SECRET\")`"
        finding['action'] = 'REPLACE_LINE'
        finding['vulnerable_code'] = vulnerable_line
        
    elif finding['type'] == 'SCA':
        prompt = f"**Contexto:** Análise de Dependências (SCA).\n**Problema:** A ferramenta Trivy encontrou que a dependência '{finding['package']}' na versão '{finding['version']}' é vulnerável ({finding['vuln_id']}). O arquivo de dependências é o '{file_path}'.\n\n**Sua Tarefa:**\nQual é a versão estável e segura mais recente para corrigir isso? Responda APENAS com a linha corrigida para o arquivo de dependência, sem nenhuma outra explicação.\nExemplo de resposta para requirements.txt: `{finding['package']}==1.2.3`"
        finding['action'] = 'REPLACE_LINE'
        finding['vulnerable_code'] = f"{finding['package']}=={finding['version']}"

    finding['prompt'] = prompt
    return finding

# ==============================================================================
# FUNÇÃO PRINCIPAL
# ==============================================================================
def main():
    try:
        with open("semgrep-output.json") as f: semgrep_data = json.load(f)
    except: semgrep_data = {}
    try:
        with open("gitleaks-output.json") as f: gitleaks_data = json.load(f)
    except: gitleaks_data = []
    try:
        with open("trivy-output.json") as f: trivy_data = json.load(f)
    except: trivy_data = {}

    all_findings = []
    for r in semgrep_data.get("results", []): all_findings.append({'type': 'SAST', 'rule': r["check_id"], 'severity': r["extra"]["severity"], 'file': r["path"], 'line': r["start"]["line"]})
    for r in gitleaks_data: all_findings.append({'type': 'SECRET', 'rule': r["Description"], 'severity': 'CRITICAL', 'file': r["File"], 'line': r["StartLine"]})
    if trivy_data.get("Results"):
        for res in trivy_data["Results"]:
            if "requirements.txt" in res.get("Target"):
                for v in res.get("Vulnerabilities", []): all_findings.append({'type': 'SCA', 'vuln_id': v.get("VulnerabilityID"), 'package': v.get("PkgName"), 'version': v.get("InstalledVersion"), 'severity': v.get("Severity"), 'file': res.get("Target"), 'line': -1})

    critical_findings = [f for f in all_findings if f.get('severity') in ['CRITICAL', 'HIGH']]
    if not critical_findings:
        print("✅ Nenhuma vulnerabilidade crítica ou alta encontrada. Nenhuma ação necessária.")
        return

    remediation_plan = create_remediation_plan(critical_findings[0])
    suggested_fix = ask_generative_ai(remediation_plan['prompt'])
    if suggested_fix:
        remediation_plan['suggested_fix'] = suggested_fix
        with open("remediation_plan.json", "w") as f: json.dump(remediation_plan, f)
        print("✅ Plano de remediação com sugestão da IA foi salvo em remediation_plan.json")
    else:
        print("❌ A IA não conseguiu gerar uma sugestão de correção.")

if __name__ == "__main__":
    main()
