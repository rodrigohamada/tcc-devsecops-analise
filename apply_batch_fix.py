# apply_batch_fix.py
import json
import os
import subprocess
import sys

def run_command(command):
    """Executa um comando no shell e para o script se houver erro."""
    print(f"Executando: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"❌ Erro ao executar comando: {' '.join(command)}")
        print(f"Saída de Erro (stderr):\n{result.stderr}")
        sys.exit(1)
    print(result.stdout)
    return result.stdout.strip()

def apply_fixes_and_create_pr():
    # Carrega o plano de remediação
    try:
        with open("batch_remediation_log.json", 'r', encoding='utf-8') as f:
            corrections = json.load(f)
    except FileNotFoundError:
        print("✅ Log de remediação não encontrado ou vazio. Nenhuma ação necessária.")
        return

    if not corrections:
        print("✅ Nenhuma correção a ser aplicada.")
        return

    # Pega as informações do ambiente do workflow
    repo_url = os.getenv("REPO_URL")
    gh_pat = os.getenv("GH_PAT")
    run_id = os.getenv("RUN_ID")
    
    repo_owner = repo_url.split('/')[-2]
    repo_name = repo_url.split('/')[-1].replace('.git', '')
    clone_url = f"https://x-access-token:{gh_pat}@github.com/{repo_owner}/{repo_name}.git"

    # Clona o repositório
    run_command(["git", "clone", clone_url, "target_repo_pr"])
    os.chdir("target_repo_pr")

    # Aplica cada correção
    for fix in corrections:
        file_path = fix['file']
        vulnerable_code = fix['vulnerable_code']
        suggested_fix = fix['suggested_fix']
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            new_content = content.replace(vulnerable_code, suggested_fix)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"✅ Correção aplicada ao arquivo: {file_path}")
        except Exception as e:
            print(f"❌ Erro ao aplicar correção em {file_path}: {e}")
            continue

    # Cria a branch, faz o commit e o push
    branch_name = f"fix/ai-batch-remediation-{run_id}"
    run_command(["git", "checkout", "-b", branch_name])
    run_command(["git", "config", "--global", "user.name", "DevSecOps AI Bot 🤖"])
    run_command(["git", "config", "--global", "user.email", "actions@github.com"])
    run_command(["git", "add", "."])
    run_command(["git", "commit", "-m", "fix(security): Correções automáticas em lote por IA"])
    run_command(["git", "push", "origin", branch_name])

    # Cria o corpo do Pull Request
    pr_body = "### 🤖 Remediação Automática em Lote por IA\n\nEste PR contém as seguintes correções sugeridas pela IA:\n\n"
    for fix in corrections:
        pr_body += f"- **{fix['rule']}** no arquivo `{fix['file']}`\n"
    
    pr_body += "\n**Ação Necessária:** Por favor, revise, teste e aprove este Pull Request."

    # Cria o Pull Request
    run_command([
        "gh", "pr", "create",
        "--title", "[BOT] Correção em Lote Sugerida por IA",
        "--body", pr_body,
        "--base", "main",
        "--head", branch_name
    ])

if __name__ == "__main__":
    apply_fixes_and_create_pr()
