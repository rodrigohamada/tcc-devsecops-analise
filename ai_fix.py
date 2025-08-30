#!/usr/bin/env python3
"""
ai_fix.py - aplica correções automáticas conservadoras e auditáveis.
- Adiciona comentários onde aplica fix (preserva código original comentado).
- Gera relatorio-fixes.md e relatorio-fixes.pdf (usa pandoc).
- Empacota repo_fixed/ + relatórios em ZIP.
- Aceita --report-md (opcional) para incluir no bundle o relatório original do scanner.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import zipfile
import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Dependências: ruamel.yaml, astor, packaging (instale com pip)
try:
    from ruamel.yaml import YAML
except Exception:
    YAML = None

# -----------------------
# Helpers
# -----------------------
def read_text(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore")

def write_text(p: Path, content: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")

def safe_copytree(src: Path, dst: Path):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)

def unified_diff(a: str, b: str, fname: str) -> str:
    import difflib
    a_lines = a.splitlines(keepends=True)
    b_lines = b.splitlines(keepends=True)
    return "".join(difflib.unified_diff(a_lines, b_lines, fromfile=f"{fname} (antes)", tofile=f"{fname} (depois)"))

def zip_dir(src_dir: Path, zip_path: Path):
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(src_dir):
            for f in files:
                full = Path(root) / f
                rel = full.relative_to(src_dir)
                zf.write(full, arcname=str(rel))

# -----------------------
# Regras de substituição conservadoras (texto)
# -----------------------

def ensure_import(file_path: Path, import_line: str):
    """Garante que 'import ast' (ou outro) exista no topo do arquivo."""
    text = read_text(file_path)
    if import_line in text:
        return False
    lines = text.splitlines()
    insert_at = 0
    # preserva shebang e encoding lines
    if lines and lines[0].startswith("#!"):
        insert_at = 1
    # procura primeiro bloco de imports para colocar depois, senão no topo
    for i, line in enumerate(lines[:30], start=0):
        if line.startswith("import ") or line.startswith("from "):
            insert_at = i + 1
    lines.insert(insert_at, import_line)
    write_text(file_path, "\n".join(lines) + "\n")
    return True

def apply_eval_fix(file_path: Path, lineno: int, report_notes: List[str]) -> Tuple[bool, str]:
    """
    Troca eval(...) por ast.literal_eval(...) na linha indicada.
    Insere comentário com código original acima.
    Retorna (changed, diff)
    """
    text = read_text(file_path)
    lines = text.splitlines(keepends=True)
    idx = lineno - 1
    if idx < 0 or idx >= len(lines):
        return False, ""
    orig_line = lines[idx].rstrip("\n")
    if "eval(" not in orig_line:
        return False, ""
    # Gera a linha substituída
    new_line = orig_line.replace("eval(", "ast.literal_eval(")
    commented = (
        f"# [AI-FIX] Substituição automática de eval() por ast.literal_eval()\n"
        f"# Código original: {orig_line}\n"
        f"{new_line}\n"
    )
    lines[idx] = commented
    # Assegura import ast
    ensure_import(file_path, "import ast")
    new_text = "".join(lines)
    write_text(file_path, new_text)
    d = unified_diff(text, new_text, str(file_path))
    report_notes.append(f"[SAST] eval() substituído em {file_path}:{lineno}")
    return True, d

def apply_yaml_safe_load_fix(file_path: Path, report_notes: List[str]) -> Tuple[bool, str]:
    """Substitui yaml.load(...) por yaml.safe_load(...), adicionando comentário."""
    text = read_text(file_path)
    if "yaml.load(" not in text:
        return False, ""
    new_text = text.replace("yaml.load(", "yaml.safe_load(")
    # adiciona comentário acima de cada ocorrência (simples: coloca comentário no topo informando mudança)
    header = "# [AI-FIX] Substituído yaml.load() por yaml.safe_load() onde aplicável\n"
    if header not in new_text:
        new_text = header + new_text
    write_text(file_path, new_text)
    d = unified_diff(text, new_text, str(file_path))
    report_notes.append(f"[SAST] yaml.load -> yaml.safe_load aplicado em {file_path}")
    return True, d

def apply_app_run_debug_fix(file_path: Path, report_notes: List[str]) -> Tuple[bool, str]:
    """Altera app.run(debug=True) -> app.run(debug=False) com comentário."""
    text = read_text(file_path)
    pattern = re.compile(r"(app\.run\([^)]*debug\s*=\s*)True(\s*[^)]*\))")
    if not pattern.search(text):
        return False, ""
    def repl(m):
        before = m.group(0)
        after = m.group(1) + "False" + m.group(2)
        return f"# [AI-FIX] Alterado debug=True para debug=False\n# Código original: {before}\n{after}"
    new_text = pattern.sub(repl, text)
    write_text(file_path, new_text)
    d = unified_diff(text, new_text, str(file_path))
    report_notes.append(f"[SAST] app.run(debug=True) alterado em {file_path}")
    return True, d

def apply_subprocess_shell_fix(file_path: Path, report_notes: List[str]) -> Tuple[bool, str]:
    """
    Troca shell=True por shell=False e, quando possível, tenta converter string -> lista de args.
    Insere comentário com código original.
    """
    import shlex
    text = read_text(file_path)
    changed = False
    new_text = text
    # busca ocorrências simples: subprocess.run("cmd ...", shell=True)
    pattern = re.compile(r"(subprocess\.(run|Popen)\()\s*([\"'])(.+?)\3\s*,\s*shell\s*=\s*True\s*(\))")
    def repl(m):
        nonlocal changed
        call_prefix = m.group(1)
        cmd_str = m.group(4)
        after_paren = m.group(5)
        parts = shlex.split(cmd_str)
        list_repr = "[" + ", ".join([repr(p) for p in parts]) + "]"
        original = m.group(0)
        replacement = (f"# [AI-FIX] Removido shell=True e convertido para lista de args quando possível\n"
                       f"# Código original: {original}\n"
                       f"{call_prefix}{list_repr}, shell=False{after_paren}")
        changed = True
        return replacement
    new_text2 = pattern.sub(repl, new_text)
    if changed:
        write_text(file_path, new_text2)
        d = unified_diff(text, new_text2, str(file_path))
        report_notes.append(f"[SAST] subprocess shell=True tratado em {file_path}")
        return True, d
    return False, ""

# -----------------------
# Gitleaks: remover segredos com comentário e gerar .env.example
# -----------------------
SECRET_PATTERNS = [
    (re.compile(r"\b(ghp_[0-9A-Za-z]{36,})\b"), "GITHUB_TOKEN"),
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "AWS_ACCESS_KEY_ID"),
    (re.compile(r"\b(xox[abprs]-[0-9A-Za-z-]+)\b"), "SLACK_TOKEN"),
    (re.compile(r"\b(sk-[A-Za-z0-9-_]{10,})\b"), "SECRET_KEY")
]

def detect_secret_name(secret: str) -> str:
    # heurística simples
    for pat, name in SECRET_PATTERNS:
        if pat.match(secret):
            return name
    # fallback
    return "SECRET_" + re.sub(r"\W+", "_", secret)[:8]

def apply_gitleaks_fixes(gitleaks_json: List[Dict], repo_fixed: Path,
                         env_placeholders: Dict[str, str],
                         changes: List[Dict]):
    for entry in gitleaks_json:
        file_rel = entry.get("File") or entry.get("file") or entry.get("path")
        if not file_rel:
            continue
        fpath = repo_fixed / file_rel
        if not fpath.exists():
            continue
        secret_value = entry.get("Secret") or ""
        start_line = entry.get("StartLine") or entry.get("start_line") or 1
        env_name = detect_secret_name(secret_value)
        env_placeholders.setdefault(env_name, "<preencha-valor-seguro>")

        text = read_text(fpath)
        lines = text.splitlines(keepends=True)
        idx = max(0, start_line - 1)
        orig_line = lines[idx].rstrip("\n") if idx < len(lines) else ""
        replaced_line = orig_line.replace(secret_value, f"${{{env_name}}}")
        new_block = (
            f"# [AI-FIX] Segredo removido automaticamente e substituído por variável de ambiente\n"
            f"# Código original: {orig_line}\n"
            f"{replaced_line}\n"
        )
        if idx < len(lines):
            lines[idx] = new_block
        else:
            lines.append(new_block)
        new_text = "".join(lines)
        write_text(fpath, new_text)
        diff = unified_diff(text, new_text, str(fpath))
        changes.append({
            "path": fpath,
            "diff": diff,
            "notes": [f"Segredo detectado substituído por ${{{env_name}}} (linha {start_line})"]
        })

# -----------------------
# Trivy SCA: atualizar requirements.txt quando houver FixedVersion
# -----------------------
def apply_trivy_fixes(trivy_results: List[Dict], repo_fixed: Path, changes: List[Dict]):
    # consolida vulnerabilidades
    vulns = []
    for res in trivy_results:
        for v in res.get("Vulnerabilities", []) if res else []:
            vulns.append(v)
    if not vulns:
        return
    req_file = repo_fixed / "requirements.txt"
    if not req_file.exists():
        return
    text = read_text(req_file)
    lines = text.splitlines(keepends=True)
    changed = False
    for i, line in enumerate(lines):
        for v in vulns:
            pkg = v.get("PkgName") or v.get("PackageName") or ""
            installed = v.get("InstalledVersion") or ""
            fixed = v.get("FixedVersion") or v.get("FixedVersion", "")
            if pkg and pkg in line and fixed:
                orig_line = lines[i].rstrip("\n")
                new_line = (f"# [AI-FIX] Dependência atualizada automaticamente\n"
                            f"# Versão original: {orig_line}\n"
                            f"{pkg}=={fixed}\n")
                lines[i] = new_line
                changed = True
    if changed:
        new_text = "".join(lines)
        write_text(req_file, new_text)
        diff = unified_diff(text, new_text, str(req_file))
        changes.append({"path": req_file, "diff": diff, "notes": ["Dependências atualizadas (SCA)"]})

# -----------------------
# Aplica fixes SAST simples baseados em heurísticas e semgrep results
# -----------------------
def apply_semgrep_fixes(semgrep_json: List[Dict], repo_fixed: Path, changes: List[Dict], report_lines: List[str]):
    # Processa achados e aplica fixes apenas quando seguro (eval, yaml.load, app.run debug, subprocess shell)
    for r in semgrep_json:
        path = r.get("path") or r.get("file") or r.get("File") or r.get("path")
        if not path:
            continue
        file_path = repo_fixed / path
        if not file_path.exists():
            continue
        start_line = (r.get("start") or {}).get("line") if isinstance(r.get("start"), dict) else r.get("StartLine") or r.get("start") or 1
        notes_local = []
        # eval
        try:
            changed, diff = apply_eval_fix(file_path, int(start_line), notes_local)
            if changed:
                changes.append({"path": file_path, "diff": diff, "notes": notes_local.copy()})
                report_lines.append(f"- [SAST] eval() tratado em {path}:{start_line}")
                continue
        except Exception:
            pass
        # yaml.load
        try:
            changed, diff = apply_yaml_safe_load_fix(file_path, notes_local)
            if changed:
                changes.append({"path": file_path, "diff": diff, "notes": notes_local.copy()})
                report_lines.append(f"- [SAST] yaml.load -> yaml.safe_load aplicado em {path}")
                continue
        except Exception:
            pass
        # app.run(debug=True)
        try:
            changed, diff = apply_app_run_debug_fix(file_path, notes_local)
            if changed:
                changes.append({"path": file_path, "diff": diff, "notes": notes_local.copy()})
                report_lines.append(f"- [SAST] app.run(debug=True) ajustado em {path}")
                continue
        except Exception:
            pass
        # subprocess shell=True
        try:
            changed, diff = apply_subprocess_shell_fix(file_path, notes_local)
            if changed:
                changes.append({"path": file_path, "diff": diff, "notes": notes_local.copy()})
                report_lines.append(f"- [SAST] subprocess shell=True tratado em {path}")
                continue
        except Exception:
            pass

# -----------------------
# Gera relatório markdown e PDF local
# -----------------------
def gen_changes_report_md_pdf(changes: List[Dict], env_placeholders: Dict[str, str],
                              out_md: Path, out_pdf: Path, original_report_md: Optional[Path]):
    lines = []
    lines.append("# Relatório de Correções Automáticas (IA)\n\n")
    lines.append(f"**Data:** {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n---\n\n")

    if original_report_md and original_report_md.exists():
        lines.append("## Relatório original do scanner (anexado abaixo)\n\n")
        orig = read_text(original_report_md)
        lines.append("```\n")
        lines.append(orig + "\n")
        lines.append("```\n\n---\n\n")

    if env_placeholders:
        lines.append("## Variáveis de Ambiente Sugeridas\n\n")
        lines.append("| Variável | Exemplo |\n|---|---|\n")
        for k, v in env_placeholders.items():
            lines.append(f"| {k} | {v} |\n")
        lines.append("\n---\n\n")

    if not changes:
        lines.append("**Nenhuma alteração automática foi aplicada.**\n")
    else:
        lines.append("## Alterações aplicadas (resumo)\n\n")
        for ch in changes:
            rel = str(ch["path"])
            lines.append(f"### Arquivo: `{rel}`\n\n")
            if ch.get("notes"):
                lines.append("**Notas:**\n")
                for n in ch["notes"]:
                    lines.append(f"- {n}\n")
            lines.append("\n**Diff (antes → depois):**\n\n")
            lines.append("```diff\n")
            lines.append(ch.get("diff", "") + "\n")
            lines.append("```\n\n")
            lines.append("---\n\n")

    # Recomendações executivas
    lines.append("## Recomendações\n\n")
    lines.append("- Revisar manualmente as mudanças aplicadas antes de aceitar as alterações.\n")
    lines.append("- Rotacionar chaves/segredos detectados e armazená-las em secrets.\n")
    lines.append("- Executar testes automatizados e análise estática novamente.\n")

    write_text(out_md, "".join(lines))

    # Gerar PDF via pandoc (se disponível)
    try:
        subprocess.run(["pandoc", str(out_md), "-o", str(out_pdf), "--pdf-engine=xelatex",
                        "-V", "geometry:a4paper,margin=1in"], check=True)
    except Exception as e:
        print(f"[aviso] não foi possível gerar PDF (pandoc/xelatex). Erro: {e}")

# -----------------------
# Main
# -----------------------
def main():
    ap = argparse.ArgumentParser(description="Aplica correções automáticas e gera ZIP com repo corrigido.")
    ap.add_argument("--repo-dir", required=True, help="Diretório do repositório clonado (ex: target_repo)")
    ap.add_argument("--report-md", required=False, help="Relatório MD original (opcional) para incluir no bundle")
    ap.add_argument("--semgrep", required=False, help="semgrep-output.json (opcional)")
    ap.add_argument("--gitleaks", required=False, help="gitleaks-output.json (opcional)")
    ap.add_argument("--trivy", required=False, help="trivy-output.json (opcional)")
    ap.add_argument("--zip-out", required=True, help="Caminho do ZIP de saída (ex: fixes-repo.zip)")
    args = ap.parse_args()

    repo_src = Path(args.repo_dir).resolve()
    if not repo_src.exists():
        print(f"[erro] repo-dir não encontrado: {repo_src}")
        raise SystemExit(2)

    # prepare work copy
    repo_fixed = Path.cwd() / (repo_src.name + "_fixed")
    if repo_fixed.exists():
        shutil.rmtree(repo_fixed)
    safe_copytree(repo_src, repo_fixed)

    # load inputs
    semgrep = None
    gitleaks = None
    trivy = None
    if args.semgrep:
        try:
            semgrep = json.loads(read_text(Path(args.semgrep)))
        except Exception:
            semgrep = None
    if args.gitleaks:
        try:
            gitleaks = json.loads(read_text(Path(args.gitleaks)))
        except Exception:
            gitleaks = None
    if args.trivy:
        try:
            trivy = json.loads(read_text(Path(args.trivy)))
        except Exception:
            trivy = None

    changes: List[Dict] = []
    env_placeholders: Dict[str, str] = {}

    # Apply gitleaks fixes first (secrets)
    if gitleaks:
        print("[info] aplicando correções de segredos (gitleaks)...")
        apply_gitleaks_fixes(gitleaks, repo_fixed, env_placeholders, changes)

    # Apply trivy fixes (requirements)
    if trivy:
        print("[info] aplicando correções de dependências (trivy)...")
        apply_trivy_fixes(trivy.get("Results", []) if isinstance(trivy, dict) else (trivy or []), repo_fixed, changes)

    # Apply semgrep-driven fixes
    if semgrep:
        semgrep_results = semgrep.get("results", []) if isinstance(semgrep, dict) else (semgrep or [])
        print("[info] aplicando correções SAST (semgrep heurísticas)...")
        report_lines = []
        apply_semgrep_fixes(semgrep_results, repo_fixed, changes, report_lines)

    # Gera relatório md + pdf no repo_fixed
    md_out = repo_fixed / "relatorio-fixes.md"
    pdf_out = repo_fixed / "relatorio-fixes.pdf"
    original_report_path = Path(args.report_md) if args.report_md else None
    gen_changes_report_md_pdf(changes, env_placeholders, md_out, pdf_out, original_report_path)

    # Se houver report-md original, copiá-lo para bundle (melhor rastreabilidade)
    bundle_dir = Path.cwd() / "bundle_out"
    if bundle_dir.exists():
        shutil.rmtree(bundle_dir)
    bundle_dir.mkdir(parents=True)
    shutil.copytree(repo_fixed, bundle_dir / repo_fixed.name)

    if original_report_path and original_report_path.exists():
        shutil.copy(original_report_path, bundle_dir / original_report_path.name)

    # .env.example
    if env_placeholders:
        env_example = bundle_dir / ".env.example"
        with env_example.open("w", encoding="utf-8") as fh:
            fh.write("# Exemplo de variáveis de ambiente geradas pelo ai_fix\n")
            for k, v in env_placeholders.items():
                fh.write(f"{k}={v}\n")

    # zip
    zip_out = Path(args.zip_out).resolve()
    zip_dir(bundle_dir, zip_out)
    print(f"[ok] ZIP gerado em: {zip_out}")

if __name__ == "__main__":
    main()
