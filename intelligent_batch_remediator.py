# intelligent_batch_remediator.py
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
            if fix.startswith("```"):
                fix = '\n'.join(fix.split('\n')[1:-1])
            print(f"🧠 IA respondeu:\n---\n{fix}\n---")
            return fix
    except requests.exceptions.RequestException as e:
        print(f"❌ Erro ao chamar a API da IA: {e}")
    return None

def create_remediation_prompt(finding, file_content):
    """Cria um prompt específico baseado no tipo de vulnerabilidade."""
    file_path = finding['file']
    prompt = ""
    if finding['type'] == 'SAST':
        vulnerable_line = file_content.splitlines()[finding['line'] - 1].strip()
        prompt = f"**Contexto:** Análise de Segurança de Código (SAST).\n**Problema:** A ferramenta Semgrep encontrou a vulnerabilidade '{finding['rule']}' no arquivo '{file_path}' na linha {finding['line']}.\n**Código Vulnerável:**\n```\n{vulnerable_line}\n```\n**Sua Tarefa:**\nReescreva APENAS a linha de código corrigida, sem nenhuma explicação."
        finding['vulnerable_code'] = vulnerable_line
    elif finding['type'] == 'SECRET':
        vulnerable_line = file_content.splitlines()[finding['line'] - 1].strip()
        prompt = f"**Contexto:** Vazamento de Segredo.\n**Problema:** A ferramenta Gitleaks encontrou um segredo do tipo '{finding['rule']}' no arquivo '{file_path}' na linha {finding['line']}.\n\n**Sua Tarefa:**\nGere um código de exemplo genérico para a linguagem do arquivo '{file_path}' que carregue esta variável a partir de uma variável de ambiente. Sua resposta deve conter APENAS o código corrigido."
        finding['vulnerable_code'] = vulnerable_line
    elif finding['type'] == 'SCA':
        vulnerable_line = next((line for line in file_content.splitlines() if finding['package'] in line), None)
        prompt = f"**Contexto:** Análise de Dependências (SCA).\n**Problema:** A ferramenta Trivy encontrou que a dependência '{finding['package']}' na versão '{finding['version']}' é vulnerável. O arquivo de dependências é o '{file_path}'.\n\n**Sua Tarefa:**\nQual é a versão estável e segura mais recente para corrigir isso? Responda APENAS com a linha corrigida para o arquivo de dependência."
        finding['vulnerable_code'] = vulnerable_line

    finding['prompt'] = prompt
    return finding

def main():
    try:
        with open("semgrep-output.json") as f: semgrep_data = json.load(f)
        with open("gitleaks-output.json") as f: gitleaks_data = json.load(f)
        with open("trivy-output.json") as f: trivy_data = json.load(f)
    except FileNotFoundError as e:
        print(f"Erro: Arquivo de relatório não encontrado - {e}")
        return

    all_findings = []
    # Unifica os achados, garantindo que o caminho do arquivo seja relativo ao repositório alvo
    for r in semgrep_data.get("results", []):
        all_findings.append({'type': 'SAST', 'rule': r["check_id"], 'severity': r["extra"]["severity"], 'file': r["path"], 'line': r["start"]["line"]})
    for r in gitleaks_data:
        all_findings.append({'type': 'SECRET', 'rule': r["Description"], 'severity': 'CRITICAL', 'file': r["File"], 'line': r["StartLine"]})
    if trivy_data.get("Results"):
        for res in trivy_data["Results"]:
            if "requirements.txt" in res.get("Target", ""):
                for v in res.get("Vulnerabilities", []):
                    # O arquivo aqui é 'requirements.txt', não o caminho completo
                    all_findings.append({'type': 'SCA', 'vuln_id': v.get("VulnerabilityID"), 'package': v.get("PkgName"), 'version': v.get("InstalledVersion"), 'severity': v.get("Severity"), 'file': 'requirements.txt', 'line': -1})

    critical_findings = [f for f in all_findings if f.get('severity') in ['CRITICAL', 'HIGH']]
    if not critical_findings:
        print("✅ Nenhuma vulnerabilidade crítica ou alta encontrada.")
        return

    print(f"🚀 Encontrados {len(critical_findings)} problemas de alta prioridade. Tentando remediação em lote...")
    
    modified_files = {}
    remediation_log = []

    for finding in critical_findings:
        file_path = finding['file']
        
        if file_path not in modified_files:
            try:
                with open(os.path.join("target_repo", file_path), 'r') as f:
                    modified_files[file_path] = f.read()
            except FileNotFoundError:
                print(f"Aviso: Não foi possível encontrar o arquivo {file_path}. Pulando.")
                continue

        plan = create_remediation_prompt(finding, modified_files[file_path])
        
        if not plan.get('vulnerable_code'):
             print(f"Aviso: Não foi possível identificar a linha vulnerável em {file_path}. Pulando.")
             continue

        suggested_fix = ask_generative_ai(plan['prompt'])
        
        if suggested_fix and plan['vulnerable_code'] in modified_files[file_path]:
            modified_files[file_path] = modified_files[file_path].replace(plan['vulnerable_code'], suggested_fix)
            remediation_log.append({
                "file": file_path,
                "vulnerable_code": plan['vulnerable_code'],
                "suggested_fix": suggested_fix,
                "rule": plan.get('rule', plan.get('vuln_id'))
            })
            print(f"✅ Correção para '{plan.get('rule', plan.get('vuln_id'))}' aplicada em memória.")
        else:
            print(f"❌ A IA não conseguiu gerar uma correção válida para '{plan.get('rule', plan.get('vuln_id'))}' ou o código já foi alterado.")

    with open("batch_remediation_log.json", "w") as f:
        json.dump(remediation_log, f, indent=2)
    print("✅ Log de remediação em lote salvo em batch_remediation_log.json")

if __name__ == "__main__":
    main()
