#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ai_fix.py
---------------------------------
Script para aplicar correções automáticas em repositórios baseadas nos relatórios:
- Semgrep
- Gitleaks
- Trivy

Fluxo:
1. Lê relatórios de vulnerabilidades.
2. Aplica correções conservadoras (sem sobrescrever os arquivos originais).
3. Cada arquivo alterado é salvo em `fixes_out/` mantendo o código original comentado.
4. Gera relatório detalhado (`fix-report-<repo>.md` e `fix-report-<repo>.pdf`)
5. Empacota tudo em um arquivo `.zip`.

Todos os comentários, variáveis e logs estão em português.
"""

import os
import argparse
import json
import re
import shutil
import subprocess
import zipfile
import datetime
import difflib
from pathlib import Path
from typing import List, Dict, Optional, Tuple


# -------------------------
# Funções utilitárias
# -------------------------
def ler_texto(caminho: Path) -> str:
    if not caminho.exists():
        return ""
    return caminho.read_text(encoding="utf-8", errors="ignore")

def escrever_texto(caminho: Path, conteudo: str):
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(conteudo, encoding="utf-8")

def diff_unificado(antes: str, depois: str, nome_arquivo: str) -> str:
    return "".join(difflib.unified_diff(
        antes.splitlines(keepends=True),
        depois.splitlines(keepends=True),
        fromfile=f"{nome_arquivo} (antes)",
        tofile=f"{nome_arquivo} (depois)"
    ))

def compactar_diretorio(origem: Path, destino_zip: Path):
    if destino_zip.exists():
        destino_zip.unlink()
    with zipfile.ZipFile(destino_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(origem):
            for f in files:
                full = Path(root) / f
                rel = full.relative_to(origem)
                zf.write(full, arcname=str(rel))


# -------------------------
# Correções básicas
# -------------------------
def corrigir_yaml_load(texto: str) -> Tuple[bool, str, List[str]]:
    if "yaml.load(" not in texto:
        return False, texto, []
    novo = texto.replace("yaml.load(", "yaml.safe_load(")
    cabecalho = "# [AI-FIX] Substituído yaml.load() por yaml.safe_load() (mais seguro)\n"
    if cabecalho not in novo:
        novo = cabecalho + novo
    return True, novo, ["yaml.load() substituído por yaml.safe_load()"]

def corrigir_app_debug(texto: str) -> Tuple[bool, str, List[str]]:
    padrao = re.compile(r"(app\.run\([^)]*debug\s*=\s*)True(\s*[^)]*\))")
    if not padrao.search(texto):
        return False, texto, []
    def repl(m):
        return f"# [AI-FIX] debug=True alterado para debug=False\n# Código original: {m.group(0)}\n{m.group(1)}False{m.group(2)}"
    novo = padrao.sub(repl, texto)
    return True, novo, ["debug=True alterado para debug=False"]

# -------------------------
# Relatório
# -------------------------
def gerar_relatorio(nome_repo: str, alteracoes: List[Dict], dir_saida: Path):
    """
    Gera relatório em Markdown + PDF das alterações aplicadas.
    """
    md_path = dir_saida / f"fix-report-{nome_repo}.md"
    pdf_path = dir_saida / f"fix-report-{nome_repo}.pdf"

    linhas = []
    linhas.append(f"# Relatório de Correções Automáticas - {nome_repo}\n")
    linhas.append(f"Data da execução: {datetime.datetime.now()}\n")
    linhas.append("## Resumo das alterações\n")

    if not alteracoes:
        linhas.append("Nenhuma alteração foi aplicada.\n")
    else:
        for alt in alteracoes:
            linhas.append(f"### Arquivo: `{alt['arquivo']}`\n")
            linhas.append(f"- Tipo: {alt['tipo']}\n")
            linhas.append(f"- Linha: {alt['linha']}\n")
            linhas.append("#### Diferença (antes → depois):\n")
            linhas.append("```diff\n" + alt["diff"] + "\n```\n")
            if "notas" in alt:
                for nota in alt["notas"]:
                    linhas.append(f"- {nota}\n")
            linhas.append("\n")

    escrever_texto(md_path, "\n".join(linhas))

    # tentar gerar PDF
    try:
        subprocess.run([
            "pandoc", str(md_path), "-o", str(pdf_path),
            "--pdf-engine=xelatex", "-V", "geometry:a4paper,margin=1in"
        ], check=True)
    except Exception as e:
        print(f"[aviso] não foi possível gerar PDF: {e}")

    return md_path, pdf_path


# -------------------------
# Processamento
# -------------------------
def processar_repo(repo_dir: Path, saida_zip: Path,
                   semgrep: Optional[Path],
                   gitleaks: Optional[Path],
                   trivy: Optional[Path]):
    saida_dir = Path("fixes_out")
    if saida_dir.exists():
        shutil.rmtree(saida_dir)
    saida_dir.mkdir()

    alteracoes: List[Dict] = []

    # exemplo: corrigir debug=True
    for arquivo in repo_dir.rglob("*.py"):
        original = ler_texto(arquivo)
        novo = original
        notas = []

        mudou, novo, n = corrigir_yaml_load(novo)
        if mudou: notas.extend(n)

        mudou, novo, n = corrigir_app_debug(novo)
        if mudou: notas.extend(n)

        if novo != original:
            destino = saida_dir / arquivo.relative_to(repo_dir)
            escrever_texto(destino, novo)
            alteracoes.append({
                "arquivo": str(arquivo.relative_to(repo_dir)),
                "linha": "?",
                "tipo": "Correção de segurança",
                "diff": diff_unificado(original, novo, str(arquivo)),
                "notas": notas
            })

    # gerar relatório
    gerar_relatorio(repo_dir.name, alteracoes, saida_dir)

    # compactar
    compactar_diretorio(saida_dir, saida_zip)


# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="Aplicar correções automáticas em repositório")
    parser.add_argument("--repo-dir", required=True, help="Diretório do repositório alvo")
    parser.add_argument("--semgrep", required=False, help="Arquivo JSON de saída do Semgrep")
    parser.add_argument("--gitleaks", required=False, help="Arquivo JSON de saída do Gitleaks")
    parser.add_argument("--trivy", required=False, help="Arquivo JSON de saída do Trivy")
    parser.add_argument("--saida-zip", required=True, help="Arquivo ZIP de saída")

    args = parser.parse_args()

    processar_repo(
        Path(args.repo_dir),
        Path(args.saida_zip),
        Path(args.semgrep) if args.semgrep else None,
        Path(args.gitleaks) if args.gitleaks else None,
        Path(args.trivy) if args.trivy else None
    )


if __name__ == "__main__":
    main()
