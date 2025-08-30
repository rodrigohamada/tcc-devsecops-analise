import os
import json
import shutil
import argparse
import datetime
import zipfile
import re
from ruamel.yaml import YAML
import ast
import astor
from packaging import version

# ==============================
# Funções Utilitárias
# ==============================

def load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return default

def save_file(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

def zip_dir(folder, zip_filename):
    with zipfile.ZipFile(zip_filename, "w", zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder):
            for file in files:
                filepath = os.path.join(root, file)
                arcname = os.path.relpath(filepath, folder)
                zipf.write(filepath, arcname)

# ==============================
# Correções
# ==============================

def fix_gitleaks(findings, repo_dir, report_lines):
    for f in findings:
        filepath = os.path.join(repo_dir, f["File"])
        if not os.path.exists(filepath):
            continue
        with open(filepath, "r", encoding="utf-8", errors="ignore") as file:
            lines = file.readlines()
        # Substituir o segredo por um placeholder
        if 0 <= f["StartLine"] - 1 < len(lines):
            lines[f["StartLine"] - 1] = re.sub(
                re.escape(f["Secret"]), "REMOVIDO_SECRET", lines[f["StartLine"] - 1]
            )
        with open(filepath, "w", encoding="utf-8") as file:
            file.writelines(lines)
        report_lines.append(f"[SEGREDO] {filepath}:{f['StartLine']} → segredo removido/substituído")

def fix_trivy(findings, repo_dir, report_lines):
    req_path = os.path.join(repo_dir, "requirements.txt")
    if not os.path.exists(req_path):
        return
    with open(req_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    updated = False
    for f in findings:
        for i, line in enumerate(lines):
            if f["PkgName"] in line:
                # Atualiza versão para a mais segura conhecida (exemplo: ^ ultima patch)
                safe_version = f.get("FixedVersion")
                if safe_version and version.parse(f["InstalledVersion"]) < version.parse(safe_version):
                    lines[i] = f"{f['PkgName']}=={safe_version}\n"
                    updated = True
                    report_lines.append(
                        f"[SCA] {f['PkgName']} atualizado {f['InstalledVersion']} → {safe_version}"
                    )
    if updated:
        with open(req_path, "w", encoding="utf-8") as f:
            f.writelines(lines)

def fix_semgrep(findings, repo_dir, report_lines):
    for f in findings:
        filepath = os.path.join(repo_dir, f["path"])
        if not os.path.exists(filepath) or not filepath.endswith(".py"):
            continue
        try:
            with open(filepath, "r", encoding="utf-8") as file:
                tree = ast.parse(file.read())
        except Exception:
            continue

        class RewriteInsecure(ast.NodeTransformer):
            def visit_Call(self, node):
                # Exemplo: substituir eval() por ast.literal_eval()
                if isinstance(node.func, ast.Name) and node.func.id == "eval":
                    new_node = ast.copy_location(
                        ast.Call(func=ast.Name(id="literal_eval", ctx=ast.Load()), args=node.args, keywords=[]),
                        node,
                    )
                    report_lines.append(f"[SAST] {filepath}:{node.lineno} → uso de eval() substituído por literal_eval()")
                    return ast.fix_missing_locations(new_node)
                return self.generic_visit(node)

        new_tree = RewriteInsecure().visit(tree)
        new_code = astor.to_source(new_tree)
        with open(filepath, "w", encoding="utf-8") as file:
            file.write(new_code)

# ==============================
# Pipeline Principal
# ==============================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", required=True, help="Diretório do repositório clonado")
    parser.add_argument("--report-md", required=True, help="Relatório original em MD")
    parser.add_argument("--semgrep", required=True, help="JSON do semgrep")
    parser.add_argument("--gitleaks", required=True, help="JSON do gitleaks")
    parser.add_argument("--trivy", required=True, help="JSON do trivy")
    parser.add_argument("--zip-out", required=True, help="Arquivo ZIP de saída")
    args = parser.parse_args()

    repo_fixed = args.repo_dir + "_fixed"
    if os.path.exists(repo_fixed):
        shutil.rmtree(repo_fixed)
    shutil.copytree(args.repo_dir, repo_fixed)

    # Carregar findings
    semgrep = load_json(args.semgrep, {}).get("results", [])
    gitleaks = load_json(args.gitleaks, [])
    trivy = load_json(args.trivy, {}).get("Results", [])

    report_lines = []
    report_lines.append(f"# Relatório de Correções Automáticas\n")
    report_lines.append(f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
    report_lines.append("---\n")

    # Aplicar correções
    if gitleaks:
        fix_gitleaks(gitleaks, repo_fixed, report_lines)
    if trivy:
        all_vulns = []
        for res in trivy:
            for v in res.get("Vulnerabilities", []):
                all_vulns.append(v)
        fix_trivy(all_vulns, repo_fixed, report_lines)
    if semgrep:
        fix_semgrep(semgrep, repo_fixed, report_lines)

    # Salvar relatório
    report_path = os.path.join(repo_fixed, "relatorio-fixes.md")
    save_file(report_path, "\n".join(report_lines))

    # Compactar em ZIP
    zip_dir(repo_fixed, args.zip_out)
    print(f"Correções aplicadas e pacote gerado em: {args.zip_out}")

if __name__ == "__main__":
    main()
