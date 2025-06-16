import json
import os
import sys
import requests

def ask_generative_ai(prompt):
    """Envia um prompt para a IA e retorna a resposta."""
    print(f"🤖 Enviando prompt para a IA:\n---\n{prompt}\n---")
    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("❌ Chave de API do Gemini não encontrada.")
        return None
    
    chatHistory = [{"role": "user", "parts": [{"text": prompt}]}]
    payload = {"contents": chatHistory}
    apiUrl = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={api_key}"
    
    try:
        response = requests.post(apiUrl, json=payload, headers={'Content-Type': 'application/json'})
        response.raise_for_status()
        result = response.json()
        if result.get("candidates"):
            fix = result["candidates"][0]["content"]["parts"][0]["text"].strip()
            # Limpa a formatação de bloco de código da resposta da IA
            if fix.startswith("```"):
                fix = '\n'.join(fix.split('\n')[1:-1])
            print(f"🧠 IA respondeu:\n---\n{fix}\n---")
            return fix
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao chamar a API da IA: {e}")
    return None

def create_remediation_prompt(finding, file_content):
    """Cria um prompt de engenharia específico para cada tipo de vulnerabilidade."""
    file_path = finding['file']
    prompt = ""
    # Lógica para SAST e Segredos, que precisam do número da linha
    if finding['type'] in ['SAST', 'SECRET']:
        vulnerable_line = file_content.splitlines()[finding['line'] - 1].strip()
        finding['vulnerable_code'] = vulnerable_line
        if finding['type'] == 'SAST':
            prompt = f"Contexto: Análise de Segurança de Código. A ferramenta Semgrep encontrou a vulnerabilidade '{finding['rule']}' no arquivo '{file_path}' na linha {finding['line']}. A linha exata é: `{vulnerable_line}`. Reescreva APENAS a linha de código corrigida, sem explicações."
        else: # SECRET
            prompt = f"Contexto: Vazamento de Segredo. A ferramenta Gitleaks encontrou um segredo do tipo '{finding['rule']}' no arquivo '{file_path}' na linha {finding['line']}. A linha é: `{vulnerable_line}`. Gere um código de exemplo genérico para a linguagem do arquivo '{file_path}' que carregue esta variável a partir de uma variável de ambiente. Responda APENAS com o código corrigido."
    # Lógica para SCA (dependências)
    elif finding['type'] == 'SCA':
        vulnerable_line = next((line for line in file_content.splitlines() if finding['package'].lower() in line.lower()), None)
        if not vulnerable_line: return None # Pula se não encontrar a linha da dependência
        finding['vulnerable_code'] = vulnerable_line.strip()
        prompt = f"Contexto: Análise de Dependências. O arquivo '{file_path}' tem a dependência '{finding['package']}' na versão '{finding['version']}', que é vulnerável. A linha é: `{vulnerable_line.strip()}`. Qual é a versão estável e segura mais recente? Responda APENAS com a linha corrigida para o arquivo de dependência."
    
    finding['prompt'] = prompt
    return finding

def main():
    try:
        with open("semgrep-output.json") as f: semgrep_data = json.load(f)
        with open("gitleaks-output.json") as f: gitleaks_data = json.load(f)
        with open("trivy-output.json") as f: trivy_data = json.load(f)
    except FileNotFoundError as e:
        print(f"Erro: Arquivo de relatório não encontrado - {e}"); return

    all_findings = []
    # Unifica todos os achados em uma única lista
    for r in semgrep_data.get("results", []): all_findings.append({'type': 'SAST', 'rule': r["check_id"], 'severity': r["extra"]["severity"], 'file': r["path"], 'line': r["start"]["line"]})
    for r in gitleaks_data: all_findings.append({'type': 'SECRET', 'rule': r["Description"], 'severity': 'CRITICAL', 'file': r["File"], 'line': r["StartLine"]})
    if trivy_data.get("Results"):
        for res in trivy_data["Results"]:
            file_target = res.get("Target", "")
            if "requirements.txt" in file_target:
                for v in res.get("Vulnerabilities", []): all_findings.append({'type': 'SCA', 'vuln_id': v.get("VulnerabilityID"), 'package': v.get("PkgName"), 'version': v.get("InstalledVersion"), 'severity': v.get("Severity"), 'file': file_target, 'line': -1})

    critical_findings = [f for f in all_findings if f.get('severity') in ['CRITICAL', 'HIGH']]
    if not critical_findings:
        print("✅ Nenhuma vulnerabilidade crítica ou alta encontrada."); return

    print(f"🚀 Encontrados {len(critical_findings)} problemas de alta prioridade. Tentando remediação em lote...")
    
    modified_files = {}
    remediation_log = []

    for finding in critical_findings:
        file_path = finding['file']
        
        if file_path not in modified_files:
            try:
                with open(os.path.join("target_repo", file_path), 'r', encoding='utf-8') as f:
                    modified_files[file_path] = f.read()
            except FileNotFoundError:
                print(f"Aviso: Não foi possível encontrar {file_path}. Pulando."); continue

        plan = create_remediation_prompt(finding, modified_files[file_path])
        if not plan or not plan.get('vulnerable_code'):
             print(f"Aviso: Não foi possível identificar a linha vulnerável para {finding['rule']}. Pulando."); continue

        suggested_fix = ask_generative_ai(plan['prompt'])
        
        if suggested_fix and plan['vulnerable_code'] in modified_files[file_path]:
            modified_files[file_path] = modified_files[file_path].replace(plan['vulnerable_code'], suggested_fix)
            remediation_log.append({
                "file": file_path, "vulnerable_code": plan['vulnerable_code'],
                "suggested_fix": suggested_fix, "rule": plan.get('rule', plan.get('vuln_id'))
            })
            print(f"✅ Correção para '{plan.get('rule', plan.get('vuln_id'))}' aplicada em memória.")
        else:
            print(f"❌ Correção para '{plan.get('rule', plan.get('vuln_id'))}' falhou ou o código já foi alterado.")

    with open("batch_remediation_log.json", "w") as f:
        json.dump(remediation_log, f, indent=2)
    print("✅ Log de remediação em lote salvo em batch_remediation_log.json")

if __name__ == "__main__":
    main()
