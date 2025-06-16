# apply_batch_fix.py
import json
import os
import subprocess
import sys

def run_command(command, working_dir=None):
    """Executa um comando no shell e para o script se houver erro."""
    print(f"Executando: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True, cwd=working_dir)
    if result.returncode != 0:
        print(f"❌ Erro ao executar comando: {' '.join(command)}")
        print(f"Saída de Erro (stderr):\n{result.stderr}")
        sys.exit(1)
    print(result.stdout)
    return result.stdout.strip()

def apply_fixes_and_create_pr():
    try:
        with open("batch_remediation_log.json", 'r', encoding='utf-8') as f:
            corrections = json.load(f)
    except FileNotFoundError:
        print("✅ Log de remediação não encontrado. Nenhuma ação necessária.")
        return
    if not corrections:
        print("✅ Nenhuma correção a ser aplicada.")
        return

    # Pega as informações do ambiente do workflow
    repo_url = os.getenv("REPO_URL")
    gh_pat = os.getenv("GH_PAT")
    run_id = os.getenv("RUN_ID")
    
    # Constrói a URL de clone de forma robusta
    auth_string = f"x-access-token:{gh_pat}@"
    clone_url = repo_url.replace("https://", f"https://{auth_string}")
    
    target_dir = "target_repo_pr"
    run_command(["git", "clone", clone_url, target_dir])

    for fix in corrections:
        file_path = os.path.join(target_dir, fix['file'])
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

    branch_name = f"fix/ai-batch-remediation-{run_id}"
    run_command(["git", "config", "--global", "user.name", "DevSecOps AI Bot 🤖"], working_dir=target_dir)
    run_command(["git", "config", "--global", "user.email", "actions@github.com"], working_dir=target_dir)
    run_command(["git", "checkout", "-b", branch_name], working_dir=target_dir)
    run_command(["git", "add", "."], working_dir=target_dir)
    run_command(["git", "commit", "-m", "fix(security): Correções automáticas em lote por IA"], working_dir=target_dir)
    run_command(["git", "push", "origin", branch_name], working_dir=target_dir)

    pr_body = "### 🤖 Remediação Automática em Lote por IA\n\nEste PR contém as seguintes correções sugeridas pela IA:\n\n"
    for fix in corrections:
        pr_body += f"- **{fix['rule']}** no arquivo `{fix['file']}`\n"
    pr_body += "\n**Ação Necessária:** Por favor, revise, teste e aprove este Pull Request."

    # Salva o corpo do PR no diretório principal
    with open("pr_body.md", "w") as f:
        f.write(pr_body)

    # CORREÇÃO FINAL: Aponta para o caminho correto do arquivo de corpo do PR
    run_command([
        "gh", "pr", "create",
        "--title", "[BOT] Correção em Lote Sugerida por IA",
        "--body-file", "../pr_body.md", # Usa ../ para subir um nível de diretório
        "--base", "main",
        "--head", branch_name
    ], working_dir=target_dir)

if __name__ == "__main__":
    apply_fixes_and_create_pr()
