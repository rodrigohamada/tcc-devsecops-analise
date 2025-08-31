#!/usr/bin/env python3
import os
"""
ai_fix.py
----------------------------------
Script de Correção Automática de Vulnerabilidades
----------------------------------
- Lê resultados de Semgrep, Gitleaks e Trivy.
- Aplica correções automáticas conservadoras (sem sobrescrever o repositório original).
- Para cada arquivo alterado, grava em `correcoes/<caminho_relativo>`
  incluindo comentários com o código original (mantido como comentário).
- Gera relatório em Markdown e tenta converter para PDF via Pandoc.
- Empacota tudo em um ZIP (--saida-zip).
"""
import argparse
import json
import re
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
# Funções de Utilidade
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
        for raiz, _, arquivos in os.walk(origem):
            for arq in arquivos:
                caminho_completo = Path(raiz) / arq
                rel = caminho_completo.relative_to(origem)
                zf.write(caminho_completo, arcname=str(rel))

# -------------------------
# Correções Automáticas
# -------------------------
def corrigir_eval(codigo: str, linha:int) -> Tuple[bool,str,List[str]]:
    linhas = codigo.splitlines(keepends=True)
    idx = linha - 1
    if idx < 0 or idx >= len(linhas):
        return False, codigo, []
    if "eval(" not in linhas[idx]:
        return False, codigo, []
    nova_linha = linhas[idx].replace("eval(", "ast.literal_eval(")
    linhas[idx] = (f"# [AI-FIX] Substituição automática de eval() → ast.literal_eval()\n"
                   f"# Código original: {linhas[idx].rstrip()}\n"
                   f"{nova_linha}")
    return True, "".join(linhas), [f"Substituído eval() na linha {linha}"]

def corrigir_yaml_load(codigo: str) -> Tuple[bool,str,List[str]]:
    if "yaml.load(" not in codigo:
        return False, codigo, []
    novo = codigo.replace("yaml.load(", "yaml.safe_load(")
    cabecalho = "# [AI-FIX] Substituído yaml.load() por yaml.safe_load() (mais seguro)\n"
    if cabecalho not in novo:
        novo = cabecalho + novo
    return True, novo, ["yaml.load → yaml.safe_load aplicado"]

def corrigir_debug_flask(codigo:str) -> Tuple[bool,str,List[str]]:
    padrao = re.compile(r"(app\.run\([^)]*debug\s*=\s*)True(\s*[^)]*\))")
    if not padrao.search(codigo):
        return False, codigo, []
    novo = padrao.sub(
        lambda m: (f"# [AI-FIX] Alterado debug=True para debug=False\n"
                   f"# Código original: {m.group(0)}\n"
                   f"{m.group(1)}False{m.group(2)}"),
        codigo
    )
    return True, novo, ["app.run(debug=True) → debug=False"]

def corrigir_subprocess_shell(codigo:str) -> Tuple[bool,str,List[str]]:
    padrao = re.compile(r"(subprocess\.(run|Popen)\()\s*(['\"])(.+?)\3\s*,\s*shell\s*=\s*True\s*(\))", re.DOTALL)
    alterado = False
    def repl(m):
        nonlocal alterado
        comando = m.group(4)
        try:
            partes = shlex.split(comando)
            lista = "[" + ", ".join([repr(p) for p in partes]) + "]"
        except Exception:
            lista = None
        if lista:
            alterado = True
            return (f"# [AI-FIX] shell=True removido e convertido para lista de argumentos\n"
                    f"# Código original: {m.group(0)}\n"
                    f"{m.group(1)}{lista}, shell=False{m.group(5)}")
        return m.group(0)
    novo = padrao.sub(repl, codigo)
    if alterado:
        return True, novo, ["subprocess shell=True tratado"]
    return False, codigo, []

def corrigir_sql_fstring(codigo:str, linha:int) -> Tuple[bool,str,List[str]]:
    linhas = codigo.splitlines(keepends=True)
    idx = linha - 1
    if idx < 0 or idx >= len(linhas):
        return False, codigo, []
    m = re.search(r"(\w+\.execute\()\s*f([\"'])(.+)\2\s*\)", linhas[idx])
    if not m:
        return False, codigo, []
    conteudo = m.group(3)
    var = re.search(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", conteudo)
    if not var:
        return False, codigo, []
    nome_var = var.group(1)
    nova_query = re.sub(r"\{[a-zA-Z_][a-zA-Z0-9_]*\}", "%s", conteudo)
    nova_linha = linhas[idx].replace(f"f\"{conteudo}\"", f"\"{nova_query}\"")
    nova_linha = nova_linha.rstrip(")") + f", ({nome_var},))\n"
    linhas[idx] = (f"# [AI-FIX] Parametrização de SQL para evitar injection\n"
                   f"# Código original: {linhas[idx].rstrip()}\n"
                   f"{nova_linha}")
    return True, "".join(linhas), [f"SQL parametrizado na linha {linha}"]

# -------------------------
# Relatório
# -------------------------
def gerar_relatorio(repo:str, alteracoes:List[Dict], variaveis_env:Dict[str,str], rel_md:Path, rel_pdf:Path):
    linhas = []
    linhas.append(f"# Relatório de Correções Automáticas\n")
    linhas.append(f"Repositório: **{repo}**\n")
    linhas.append(f"Data: {datetime.datetime.now()}\n\n")

    for alt in alteracoes:
        linhas.append(f"## Arquivo: {alt['arquivo']}\n")
        linhas.append(f"- Tipo: {alt['tipo']}\n")
        linhas.append(f"- Linha: {alt['linha']}\n")
        for nota in alt["notas"]:
            linhas.append(f"- {nota}\n")
        linhas.append("\n```diff\n")
        linhas.append(alt["diff"])
        linhas.append("\n```\n")

    escrever_texto(rel_md, "".join(linhas))

    # Geração PDF
    try:
        subprocess.run([
            "pandoc", str(rel_md), "-o", str(rel_pdf),
            "--pdf-engine=xelatex", "-V", "geometry:a4paper,margin=1in"
        ], check=True)
    except Exception:
        try:
            subprocess.run([
                "pandoc", str(rel_md), "-o", str(rel_pdf),
                "--pdf-engine=pdflatex", "-V", "geometry:a4paper,margin=1in"
            ], check=True)
        except Exception as e:
            print(f"[Aviso] Não foi possível gerar PDF: {e}")

# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser(description="AI Fix - Correção Automática de Vulnerabilidades")
    parser.add_argument("--repo-dir", required=True, help="Diretório do repositório alvo")
    parser.add_argument("--saida-zip", required=True, help="Arquivo ZIP de saída")
    args = parser.parse_args()

    repo = Path(args.repo_dir)
    saida = Path("correcoes")
    saida.mkdir(exist_ok=True)

    alteracoes = []
    variaveis_env = {}

    rel_md = saida / "relatorio-correcoes.md"
    rel_pdf = saida / "relatorio-correcoes.pdf"

    gerar_relatorio(repo.name, alteracoes, variaveis_env, rel_md, rel_pdf)
    compactar_diretorio(saida, Path(args.saida_zip))

if __name__ == "__main__":
    main()
