#!/usr/bin/env python3
"""
ai_fix.py
- Lê semgrep/gitleaks/trivy outputs
- Aplica correções automáticas conservadoras (sem sobrescrever o repo original)
- Para cada arquivo alterado: grava apenas o arquivo alterado em fixes_out/<caminho_relativo>
  incluindo comentários com o código original (preservado como comentário)
- Gera relatorio-fixes.md (detalhado) e tenta gerar relatorio-fixes.pdf via pandoc
- Empacota fixes_out/ em um ZIP (--zip-out)
"""
import argparse
import json
import re
import shutil
import subprocess
import zipfile
import datetime
import difflib
import ast
import astor
import shlex
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# -------------------------
# Helpers I/O / diff
# -------------------------
def read_text(p: Path) -> str:
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="ignore")

def write_text(p: Path, content: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")

def unified_diff(a: str, b: str, fname: str) -> str:
    return "".join(difflib.unified_diff(a.splitlines(keepends=True),
                                        b.splitlines(keepends=True),
                                        fromfile=f"{fname} (antes)",
                                        tofile=f"{fname} (depois)"))

def zip_dir(src_dir: Path, zip_path: Path):
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(src_dir):
            for f in files:
                full = Path(root) / f
                rel = full.relative_to(src_dir)
                zf.write(full, arcname=str(rel))

def snippet_from_lines(lines: List[str], lineno:int, ctx=3) -> str:
    idx = max(0, lineno-1)
    start = max(0, idx-ctx)
    end = min(len(lines), idx+ctx+1)
    numbered = []
    for i in range(start, end):
        numbered.append(f"{i+1:4d}: {lines[i].rstrip()}")
    return "\n".join(numbered)

# -------------------------
# Fix applicators (conservadores)
# Each returns (changed:bool, new_text:str, notes:List[str])
# -------------------------
def fix_eval_line_by_lineno(text: str, lineno:int) -> Tuple[bool,str,List[str]]:
    """
    Substitui 'eval(' por 'ast.literal_eval(' na linha indicada (quando for seguro),
    e insere comentário com a linha original.
    """
    lines = text.splitlines(keepends=True)
    idx = lineno - 1
    if idx < 0 or idx >= len(lines):
        return False, text, []
    line = lines[idx]
    if "eval(" not in line:
        return False, text, []
    # simples substituição textual (conservadora)
    new_line = line.replace("eval(", "ast.literal_eval(")
    commented = (f"# [AI-FIX] Substituição automática: eval() → ast.literal_eval()\n"
                 f"# Código original: {line.rstrip()}\n"
                 f"{new_line}")
    lines[idx] = commented
    new_text = "".join(lines)
    notes = ["Substituído eval() por ast.literal_eval() (linha {})".format(lineno)]
    return True, new_text, notes

def fix_yaml_load(text: str) -> Tuple[bool,str,List[str]]:
    if "yaml.load(" not in text:
        return False, text, []
    new_text = text.replace("yaml.load(", "yaml.safe_load(")
    header = "# [AI-FIX] Substituído yaml.load() por yaml.safe_load() (mais seguro)\n"
    if header not in new_text:
        new_text = header + new_text
    return True, new_text, ["yaml.load -> yaml.safe_load aplicado"]

def fix_app_run_debug(text:str) -> Tuple[bool,str,List[str]]:
    pattern = re.compile(r"(app\.run\([^)]*debug\s*=\s*)True(\s*[^)]*\))")
    if not pattern.search(text):
        return False, text, []
    def repl(m):
        before = m.group(0)
        after = m.group(1) + "False" + m.group(2)
        return f"# [AI-FIX] debug=True alterado para debug=False\n# Código original: {before}\n{after}"
    new_text = pattern.sub(repl, text)
    return True, new_text, ["app.run(debug=True) -> debug=False"]

def fix_subprocess_shell(text:str) -> Tuple[bool,str,List[str]]:
    # busca calls simples like subprocess.run("cmd ...", shell=True)
    pattern = re.compile(r"(subprocess\.(run|Popen)\()\s*(['\"])(.+?)\3\s*,\s*shell\s*=\s*True\s*(\))", re.DOTALL)
    changed = False
    def repl(m):
        nonlocal changed
        callpre = m.group(1)
        cmd = m.group(4)
        after = m.group(5)
        try:
            parts = shlex.split(cmd)
            list_repr = "[" + ", ".join([repr(p) for p in parts]) + "]"
        except Exception:
            list_repr = None
        if list_repr:
            orig = m.group(0)
            changed = True
            return (f"# [AI-FIX] Removido shell=True e convertido para lista de args quando seguro\n"
                    f"# Código original: {orig}\n"
                    f"{callpre}{list_repr}, shell=False{after}")
        else:
            return m.group(0)
    new_text = pattern.sub(repl, text)
    if changed:
        return True, new_text, ["subprocess(..., shell=True) tratado (convertido para lista de args quando possível)"]
    return False, text, []

def fix_sql_execute_fstring_line(text:str, lineno:int) -> Tuple[bool,str,List[str]]:
    """
    Tenta transformar uma linha com cursor.execute(f"...{var}...") em parametrização:
    cursor.execute("...%s...", (var,))
    Esta transformação é conservadora e só para casos simples de 1 variável.
    """
    lines = text.splitlines(keepends=True)
    idx = lineno - 1
    if idx < 0 or idx >= len(lines):
        return False, text, []
    line = lines[idx]
    # procura pattern cursor.execute(f"...{var}...")
    m = re.search(r"(\w+\.execute\()\s*f([\"'])(.+)\2\s*\)", line)
    if not m:
        # tenta detectar f-string em qualquer .execute(
        if "execute(" not in line or "f\"" not in line and "f'" not in line:
            return False, text, []
        # fallback: cannot safely parse
        return False, text, []
    # extrai inner f-string: content = m.group(3)
    content = m.group(3)
    # procura primeiro {var} simples
    var_match = re.search(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", content)
    if not var_match:
        return False, text, []
    varname = var_match.group(1)
    # constrói new string with %s
    new_query = re.sub(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}", "%s", content)
    new_line = re.sub(r"f([\"'])(.+)\1", f"\"{new_query}\"", line)
    # add params tuple
    if new_line.strip().endswith(")"):
        new_line = new_line.rstrip().rstrip(")") + f", ({varname},))\n"
    else:
        new_line = new_line + f", ({varname},))\n"
    commented = (f"# [AI-FIX] Parametrização básica aplicada para reduzir risco de SQL injection\n"
                 f"# Código original: {line.rstrip()}\n"
                 f"{new_line}")
    lines[idx] = commented
    new_text = "".join(lines)
    return True, new_text, [f"SQL execute parametrizado (linha {lineno})"]

# -------------------------
# Specific entry-level handlers
# -------------------------
def handle_gitleaks_entry(entry:Dict, repo_root:Path, out_dir:Path, envs:Dict[str,str], changes:List[Dict]):
    file_rel = entry.get("File") or entry.get("file") or entry.get("path")
    if not file_rel:
        return
    src = repo_root / file_rel
    if not src.exists():
        return
    secret = entry.get("Secret","")
    start_line = entry.get("StartLine",1)
    text = read_text(src)
    lines = text.splitlines(keepends=True)
    idx = max(0, start_line-1)
    orig_line = lines[idx].rstrip("\n") if idx < len(lines) else ""
    # heurística de nome de env
    env_name = detect_secret_name(secret)
    envs.setdefault(env_name, "<preencha-valor-seguro>")
    new_line = orig_line.replace(secret, "${%s}"%env_name)
    block = (f"# [AI-FIX] Segredo removido automaticamente e substituído por variável de ambiente\n"
             f"# Código original: {orig_line}\n"
             f"{new_line}\n")
    if idx < len(lines):
        lines[idx] = block
    else:
        lines.append(block)
    new_text = "".join(lines)
    # grava somente arquivo alterado para bundle
    rel = Path(file_rel)
    dest = out_dir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    write_text(dest, new_text)
    changes.append({
        "type":"SEGREDO",
        "file": str(rel),
        "lineno": start_line,
        "diff": unified_diff(text,new_text,str(rel)),
        "notes":[f"Segredo substituído por ${{{env_name}}}"]
    })

def detect_secret_name(secret:str)->str:
    # heurística
    if secret.startswith("ghp_"): return "GITHUB_TOKEN"
    if secret.startswith("AKIA"): return "AWS_ACCESS_KEY_ID"
    if secret.startswith("xox"): return "SLACK_TOKEN"
    if secret.startswith("sk-"): return "SECRET_KEY"
    # fallback
    cleaned = re.sub(r"\W+","_", secret)[:8].upper()
    return f"SECRET_{cleaned}"

def handle_trivy_results(trivy_json:Dict, repo_root:Path, out_dir:Path, changes:List[Dict]):
    # trivy.results -> iterate Vulnerabilities
    results = trivy_json.get("Results", []) if isinstance(trivy_json, dict) else []
    # target only requirements.txt updates
    req_file = repo_root / "requirements.txt"
    if not req_file.exists():
        return
    orig_text = read_text(req_file)
    lines = orig_text.splitlines(keepends=True)
    modified = False
    for res in results:
        target = res.get("Target","")
        if "requirements.txt" not in target:
            continue
        for v in res.get("Vulnerabilities",[]):
            pkg = v.get("PkgName") or v.get("PackageName")
            fixed = v.get("FixedVersion") or v.get("FixedVersion") or v.get("FixedVersion", "")
            installed = v.get("InstalledVersion") or ""
            if not pkg or not fixed:
                continue
            # find line with package name
            for i,l in enumerate(lines):
                if pkg in l:
                    orig_line = lines[i].rstrip("\n")
                    new_line = (f"# [AI-FIX] Dependência atualizada automaticamente\n"
                                f"# Versão original: {orig_line}\n"
                                f"{pkg}=={fixed}\n")
                    lines[i] = new_line
                    modified = True
                    changes.append({
                        "type":"SCA",
                        "file":"requirements.txt",
                        "lineno": i+1,
                        "diff": unified_diff(orig_text, "".join(lines), "requirements.txt"),
                        "notes":[f"{pkg} {installed} -> {fixed}"]
                    })
    if modified:
        dest = out_dir / "requirements.txt"
        dest.parent.mkdir(parents=True, exist_ok=True)
        write_text(dest, "".join(lines))

def handle_semgrep_results(semgrep_json:Dict, repo_root:Path, out_dir:Path, changes:List[Dict]):
    results = semgrep_json.get("results", []) if isinstance(semgrep_json, dict) else []
    for r in results:
        path = r.get("path") or r.get("file") or r.get("File")
        if not path:
            continue
        src = repo_root / path
        if not src.exists():
            continue
        start = (r.get("start") or {}).get("line") if isinstance(r.get("start"), dict) else r.get("StartLine") or r.get("start") or 1
        lineno = int(start)
        orig_text = read_text(src)
        applied = False
        # try eval fix
        changed, new_text, notes = fix_eval_line_by_lineno(orig_text, lineno)
        if changed:
            applied = True
        else:
            # yaml.load global
            changed, new_text, notes = fix_yaml_load(orig_text)
            if changed:
                applied = True
            else:
                # app.run debug
                changed, new_text, notes = fix_app_run_debug(orig_text)
                if changed:
                    applied = True
                else:
                    # subprocess shell
                    changed, new_text, notes = fix_subprocess_shell(orig_text)
                    if changed:
                        applied = True
                    else:
                        # SQL f-string param
                        changed, new_text, notes = fix_sql_execute_fstring_line(orig_text, lineno)
                        if changed:
                            applied = True
        if applied:
            rel = Path(path)
            dest = out_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            write_text(dest, new_text)
            changes.append({
                "type":"SAST",
                "file": str(rel),
                "lineno": lineno,
                "rule": r.get("check_id"),
                "message": (r.get("extra") or {}).get("message") if isinstance(r.get("extra"), dict) else None,
                "diff": unified_diff(orig_text,new_text,str(rel)),
                "notes": notes
            })

# -------------------------
# Report generator (MD + PDF)
# -------------------------
def gen_detailed_report(repo_name:str, changes:List[Dict], envs:Dict[str,str], orig_report:Optional[Path], out_md:Path, out_pdf:Path):
    lines = []
    lines.append(f"# Relatório de Correções Automáticas (IA)\n\n")
    lines.append(f"**Repositório:** `{repo_name}`\n")
    lines.append(f"**Data do processamento:** {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n---\n\n")

    # summary
    totals = {"SAST":0,"SCA":0,"SEGREDO":0}
    for ch in changes:
        if ch["type"]=="SAST": totals["SAST"] += 1
        elif ch["type"]=="SCA": totals["SCA"] += 1
        elif ch["type"]=="SEGREDO" or ch["type"]=="SEGREDO": totals["SEGREDO"] += 1
    lines.append("## Resumo Executivo\n\n")
    lines.append(f"- Arquivos / trechos alterados: **{len(changes)}**\n")
    lines.append(f"- SAST corrigidos (trechos): **{totals['SAST']}**\n")
    lines.append(f"- SCA (dependências) alteradas: **{totals['SCA']}**\n")
    lines.append(f"- Segredos substituídos: **{totals['SEGREDO']}**\n\n---\n\n")

    if envs:
        lines.append("## Variáveis de Ambiente sugeridas (substituições de segredos)\n\n")
        lines.append("| Variável | Exemplo |\n|---|---|\n")
        for k,v in envs.items():
            lines.append(f"| {k} | {v} |\n")
        lines.append("\n---\n\n")

    # detalhamento por alteração
    if not changes:
        lines.append("Não foram aplicadas alterações automáticas.\n")
    else:
        lines.append("## Detalhamento das Alterações\n\n")
        for ch in changes:
            lines.append(f"### Arquivo: `{ch['file']}`\n\n")
            lines.append(f"- **Tipo:** {ch.get('type','-')}\n")
            if ch.get("rule"): lines.append(f"- **Regra (SAST):** `{ch.get('rule')}`\n")
            if ch.get("lineno"): lines.append(f"- **Linha aproximada:** {ch.get('lineno')}\n")
            if ch.get("notes"):
                lines.append("- **Notas do fix:**\n")
                for n in ch.get("notes",[]): lines.append(f"  - {n}\n")
            lines.append("\n**Diff (antes → depois):**\n\n")
            lines.append("```diff\n")
            lines.append(ch.get("diff","") + "\n")
            lines.append("```\n\n")
            # explain rationale per type
            rationale = ""
            if ch.get("type")=="SEGREDO":
                rationale = ("Segredos no repositório deixam credenciais e chaves expostas. Substituímos por variáveis de ambiente "
                             "para evitar exposição acidental; troque os valores nas variáveis de ambiente e rotacione as chaves.")
            elif ch.get("type")=="SCA":
                rationale = ("Atualização de dependência para versão corrigida indicada pelo scanner (Trivy). "
                             "Testes e validação são necessários após atualização.")
            else: # SAST
                # heurísticas para mensagem
                msg = ch.get("message") or ""
                if "eval" in ch.get("diff","") or "eval(" in (msg or ""):
                    rationale = ("Uso de eval() permite execução de código arbitrário — substituído por ast.literal_eval() "
                                 "quando aplicável (só avalia literais).")
                elif "yaml.load" in ch.get("diff","") or "yaml.load" in (msg or ""):
                    rationale = ("yaml.load() pode executar código; yaml.safe_load() é seguro para dados não confiáveis.")
                elif "debug=True" in ch.get("diff","") or "app.run" in (msg or ""):
                    rationale = ("app.run(debug=True) habilita o depurador interativo e pode vazar dados sensíveis; desabilitado em produção.")
                elif "subprocess" in ch.get("notes","") or "shell=True" in ch.get("diff",""):
                    rationale = ("Uso de shell=True aumenta risco de injeção de comandos; conversão para lista de args e shell=False reduz o risco.")
                elif "SQL" in ch.get("notes",[]) or "execute" in ch.get("file",""):
                    rationale = ("Parametrização de queries evita SQL Injection; aplicado parametrização básica para casos simples.")
                else:
                    rationale = "Correção aplicada para reduzir risco detectado pelo scanner. Verificar manualmente."

            lines.append("**Motivação / Por que foi alterado:**\n\n")
            lines.append(rationale + "\n\n")
            lines.append("---\n\n")

    # anexar relatório original se houver
    if orig_report and orig_report.exists():
        lines.append("\n## Relatório original (anexado)\n\n")
        orig_text = read_text(orig_report)
        lines.append("```markdown\n")
        lines.append(orig_text + "\n")
        lines.append("```\n")

    # recomendações finais
    lines.append("\n## Recomendações Finais\n\n")
    lines.append("- Revisar cada alteração e executar testes.  \n")
    lines.append("- Rotacionar chaves e segredos que foram encontrados.  \n")
    lines.append("- Rodar novamente os scanners (semgrep/gitleaks/trivy).  \n")
    lines.append("- Considerar integração com revisão manual antes de merge.\n")

    # salvar md
    write_text(out_md, "".join(lines))
    # tentar gerar pdf via pandoc
    try:
        subprocess.run(["pandoc", str(out_md), "-o", str(out_pdf),
                        "--pdf-engine=xelatex", "-V", "geometry:a4paper,margin=1in"], check=True)
    except Exception as e:
        print(f"[aviso] não foi possível gerar PDF (pandoc/xelatex): {e}")

# -------------------------
# Main
# -------------------------
def main():
    ap = argparse.ArgumentParser(description="AI-based automated fixes (conservador)")
    ap.add_argument("--repo-dir", required=True, help="diretório do repositório clonado (ex: target_repo)")
    ap.add_argument("--report-md", required=False, help="relatório original gerado pelo report.py (opcional)")
    ap.add_argument("--semgrep", required=False, help="semgrep-output.json (opcional)")
    ap.add_argument("--gitleaks", required=False, help="gitleaks-output.json (opcional)")
    ap.add_argument("--trivy", required=False, help="trivy-output.json (opcional)")
    ap.add_argument("--zip-out", required=True, help="zip de saída (ex: fixes-repo.zip)")
    ap.add_argument("--repo-name", required=False, default="desconhecido")
    args = ap.parse_args()

    repo_root = Path(args.repo_dir).resolve()
    if not repo_root.exists():
        print(f"[erro] repo não encontrado: {repo_root}")
        raise SystemExit(2)

    out_dir = Path.cwd() / "fixes_out"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir()

    changes = []
    envs = {}

    # Gitleaks first (secrets)
    if args.gitleaks:
        try:
            g = json.loads(read_text(Path(args.gitleaks)))
        except Exception:
            g = []
        # gitleaks can be a list or dict
        if isinstance(g, dict):
            # sometimes Gitleaks returns dict with 'Findings' etc. but most often a list
            entries = g.get("Findings") or g.get("results") or []
            if not entries:
                # try treat as list-like in dict (fallback)
                entries = [g]
        else:
            entries = g
        for e in entries:
            try:
                handle_gitleaks_entry(e, repo_root, out_dir, envs, changes)
            except Exception as exc:
                print(f"[aviso] erro tratando gitleaks entry: {exc}")

    # Trivy
    if args.trivy:
        try:
            t = json.loads(read_text(Path(args.trivy)))
        except Exception:
            t = {}
        try:
            handle_trivy_results(t, repo_root, out_dir, changes)
        except Exception as exc:
            print(f"[aviso] erro tratando trivy: {exc}")

    # Semgrep
    if args.semgrep:
        try:
            s = json.loads(read_text(Path(args.semgrep)))
        except Exception:
            s = {}
        try:
            handle_semgrep_results(s, repo_root, out_dir, changes)
        except Exception as exc:
            print(f"[aviso] erro tratando semgrep: {exc}")

    # gerar relatório detalhado (MD + PDF) na pasta out_dir
    repo_name = args.repo_name or repo_root.name
    md_path = out_dir / "relatorio-fixes.md"
    pdf_path = out_dir / "relatorio-fixes.pdf"
    orig_report = Path(args.report_md) if args.report_md else None
    gen_detailed_report(repo_name, changes, envs, orig_report, md_path, pdf_path)

    # incluir relatorio original no bundle se passado
    if orig_report and orig_report.exists():
        shutil.copy2(orig_report, out_dir / orig_report.name)

    # .env.example se existirem segredos substituidos
    if envs:
        envfile = out_dir / ".env.example"
        with envfile.open("w", encoding="utf-8") as fh:
            fh.write("# Variáveis de ambiente sugeridas (preencha com valores reais e seguros)\n")
            for k,v in envs.items():
                fh.write(f"{k}={v}\n")

    # criar ZIP
    zip_out = Path(args.zip_out).resolve()
    zip_dir(out_dir, zip_out)
    print(f"[ok] ZIP gerado em: {zip_out}")
    print(f"[ok] arquivos alterados exportados para: {out_dir}")

if __name__ == "__main__":
    main()
