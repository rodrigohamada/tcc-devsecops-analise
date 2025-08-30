import os
import json
import shutil
import argparse
import datetime
import zipfile
import re
import ast
import astor
import subprocess
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

        if 0 <= f["StartLine"] - 1 < len(lines):
            original_line = lines[f["StartLine"] - 1].strip()
            fixed_line = re.sub(re.escape(f["Secret"]), "REMOVIDO_SECRET", lines[f["StartLine"] - 1])

            # Inserir comentário com histórico
            lines[f["StartLine"] - 1] = (
                f"# [AI-FIX] Segredo removido automaticamente\n"
                f"# Código original: {original_line}\n"
                f"{fixed_line}"
            )

            report_lines.append(f"[SEGREDO] {filepath}:{f['StartLine']} → segredo removido")

        with open(filepath, "w", encoding="utf-8") as file:
            file.writelines(lines)

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
                safe_version = f.get("FixedVersion")
                if safe_version and version.parse(f["InstalledVersion"]) < version.parse(safe_version):
                    original_line = lines[i].strip()
                    lines[i] = (
                        f"# [AI-FIX] Dependência atualizada automaticamente\n"
                        f"# Versão original: {original_line}\n"
                        f"{f['PkgName']}=={safe_version}\n"
                    )
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
                original_code = file.read()
                tree = ast.parse(original_code)
        except Exception:
            continue

        class RewriteInsecure(ast.NodeTransformer):
            def visit_Call(self, node):
                if isinstance(node.func, ast.Name) and node.func.id == "eval":
                    new_node = ast.copy_location(
                        ast.Call(func=ast.Name(id="literal_eval", ctx=ast.Load()), args=node.args, keywords=[]),
                        node,
                    )
                    report_lines.append(f"[SAST] {filepath}:{node.lineno} → uso de eval() substituído")

                    # Inserir comentário com código original
                    before = astor.to_source(node).strip()
                    after = astor.to_source(new_node).strip()
                    patched = f"# [AI-FIX] Substituição automática de uso inseguro de eval()\n# Código original: {before}\n{after}"
                    return ast.copy_location(ast.parse(patched).body[0].value, node)

                return self.generic_visit(node)

        new_tree = RewriteInsecure().visit(tree)
        new_code = astor.to_source(new_tree)

        with open(filepath, "w", encoding="utf-8") as file:
            file.write(new_code)

# ==============================
# Gerar Relatório Markdown + PDF
# ==============================

def generate_report_pdf(report_lines, output_md, output_pdf):
    md_content = "\n".join(report_lines)

    save_file(output_md, md_content)

    # Converter para PDF
    try:
        subprocess.run(
            [
                "pandoc",
                output_md,
                "-o",
                output_pdf,
                "--pdf-engine=xelatex",
                "-V",
                'geometry:a4paper,margin=1in'
            ],
            check=True,
        )
    except Exception as e:
        print(f"Falha ao gerar PDF: {e}")

# ==============================
# Pipeline Principal
# ==============================

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", required=True, help="Diretório do repositório clonado")
    parser.add_argument("--semgrep", required=True, help="JSON do semgrep")
    parser.add_argument("--gitleaks", required=True, help="JSON do gitleaks")
    parser.add_argument("--trivy", required=True, help="JSON do trivy")
    parser.add_argument("--zip-out", required=True, help="Arquivo ZIP de saída")
    args = parser.parse_args()

    repo_fixed = args.repo_dir + "_fixed"
    if os.path.exists(repo_fixed):
        shutil.rmtree(repo_fixed)
    shutil.copytree(args.repo_dir, repo_fixed)

    semgrep = load_json(args.semgrep, {}).get("results", [])
    gitleaks = load_json(args.gitleaks, [])
    trivy = load_json(args.trivy, {}).get("Results", [])

    report_lines = []
    report_lines.append(f"# Relatório de Correções Automáticas\n")
    report_lines.append(f"Data: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n")
    report_lines.append("---\n")

    # Correções
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

    # Relatório final
    md_report = os.path.join(repo_fixed, "relatorio-fixes.md")
    pdf_report = os.path.join(repo_fixed, "relatorio-fixes.pdf")
    generate_report_pdf(report_lines, md_report, pdf_report)

    # Compactar em ZIP
    zip_dir(repo_fixed, args.zip_out)
    print(f"Correções aplicadas e pacote gerado em: {args.zip_out}")

if __name__ == "__main__":
    main()
