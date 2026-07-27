"""
Descobre um Directly-Follows Graph (DFG) a partir de um log de eventos de
seguranca (login -> acesso a arquivo sensivel -> logout).

Conceito: no DFG, cada atividade e um no e uma aresta A -> B e criada sempre
que a atividade B ocorre imediatamente apos A dentro do mesmo caso (case_id).
O peso da aresta e o numero de vezes que essa sequencia se repete no log.

Uso:
    python3 gerar_dfg.py
    python3 gerar_dfg.py --dataset outro_log.csv
    python3 gerar_dfg.py --dataset outro_log.csv --saida resultados/
    python3 gerar_dfg.py --usuario usuario_10   # DFG apenas dos casos desse usuario
"""

import argparse
import shutil
import subprocess
from collections import Counter
from pathlib import Path

import pandas as pd

LOG_PATH_PADRAO = Path(__file__).parent / "event_log_seguranca.csv"


def carregar_log(caminho: Path) -> pd.DataFrame:
    df = pd.read_csv(caminho, parse_dates=["timestamp"])
    return df.sort_values(["case_id", "timestamp"]).reset_index(drop=True)


def descobrir_dfg(df: pd.DataFrame):
    """Retorna (arestas, atividades_iniciais, atividades_finais) do log."""
    arestas = Counter()
    inicios = Counter()
    fins = Counter()

    for _, caso in df.groupby("case_id", sort=False):
        atividades = caso["activity"].tolist()
        inicios[atividades[0]] += 1
        fins[atividades[-1]] += 1
        for anterior, atual in zip(atividades, atividades[1:]):
            arestas[(anterior, atual)] += 1

    return arestas, inicios, fins


def detectar_alertas(df: pd.DataFrame):
    """Sinaliza casos que desviam do fluxo esperado Login -> Acesso -> Logout."""
    alertas = []
    for case_id, caso in df.groupby("case_id", sort=False):
        atividades = caso["activity"].tolist()
        usuario = caso["usuario"].iloc[0]
        if atividades[0] == "Acesso_Arquivo_Sensivel":
            alertas.append(f"[{case_id}] usuario '{usuario}' acessou arquivo sensivel sem Login previo registrado")
        if atividades[-1] != "Logout":
            alertas.append(f"[{case_id}] usuario '{usuario}' encerrou sessao sem Logout (ultima atividade: {atividades[-1]})")
    return alertas


def gerar_dot(arestas: Counter, inicios: Counter, fins: Counter) -> str:
    linhas = [
        "digraph DFG {",
        "  rankdir=LR;",
        "  node [shape=box, style=rounded, fontname=Helvetica];",
        '  "START" [shape=circle, style=filled, fillcolor=lightgreen];',
        '  "END" [shape=circle, style=filled, fillcolor=lightcoral];',
    ]

    for atividade, freq in inicios.items():
        linhas.append(f'  "START" -> "{atividade}" [label="{freq}"];')
    for atividade, freq in fins.items():
        linhas.append(f'  "{atividade}" -> "END" [label="{freq}"];')
    for (origem, destino), freq in arestas.items():
        cor = "red" if "Falha" in origem or "Falha" in destino else "black"
        linhas.append(f'  "{origem}" -> "{destino}" [label="{freq}", color={cor}];')

    linhas.append("}")
    return "\n".join(linhas)


def parse_args():
    parser = argparse.ArgumentParser(description="Descobre um DFG a partir de um log de eventos.")
    parser.add_argument(
        "--dataset",
        type=Path,
        default=LOG_PATH_PADRAO,
        help=f"Caminho do CSV de entrada (padrao: {LOG_PATH_PADRAO.name})",
    )
    parser.add_argument(
        "--saida",
        type=Path,
        default=None,
        help="Diretorio onde salvar o .dot e o .png (padrao: mesma pasta do dataset)",
    )
    parser.add_argument(
        "--usuario",
        type=str,
        default=None,
        help="Filtra o log para um unico usuario e gera o DFG so com os casos dele",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    log_path = args.dataset
    saida_dir = args.saida or log_path.parent
    saida_dir.mkdir(parents=True, exist_ok=True)

    df = carregar_log(log_path)

    sufixo = ""
    if args.usuario:
        df = df[df["usuario"] == args.usuario].reset_index(drop=True)
        if df.empty:
            print(f"Nenhum evento encontrado para o usuario '{args.usuario}'.")
            return
        sufixo = f"_{args.usuario}"
        print(f"Filtrando log para o usuario '{args.usuario}' ({df['case_id'].nunique()} caso(s))\n")

    dot_path = saida_dir / f"{log_path.stem}_dfg{sufixo}.dot"
    png_path = saida_dir / f"{log_path.stem}_dfg{sufixo}.png"

    arestas, inicios, fins = descobrir_dfg(df)

    print("=== Atividades iniciais (primeira atividade de cada caso) ===")
    for atividade, freq in inicios.most_common():
        print(f"  {atividade}: {freq}")

    print("\n=== Atividades finais (ultima atividade de cada caso) ===")
    for atividade, freq in fins.most_common():
        print(f"  {atividade}: {freq}")

    print("\n=== Arestas do DFG (A -> B : frequencia) ===")
    for (origem, destino), freq in arestas.most_common():
        print(f"  {origem} -> {destino} : {freq}")

    alertas = detectar_alertas(df)
    print("\n=== Alertas de seguranca (desvios do fluxo Login -> Acesso -> Logout) ===")
    if alertas:
        for alerta in alertas:
            print(f"  ALERTA: {alerta}")
    else:
        print("  Nenhum desvio encontrado.")

    dot_source = gerar_dot(arestas, inicios, fins)
    dot_path.write_text(dot_source, encoding="utf-8")
    print(f"\nArquivo DOT salvo em: {dot_path}")

    if shutil.which("dot"):
        subprocess.run(["dot", "-Tpng", str(dot_path), "-o", str(png_path)], check=True)
        print(f"Imagem do DFG salva em: {png_path}")
    else:
        print(
            "Graphviz ('dot') nao encontrado no PATH. Instale com 'brew install graphviz' "
            "(ou 'apt install graphviz') e depois rode:\n"
            f"  dot -Tpng {dot_path.name} -o {png_path.name}"
        )


if __name__ == "__main__":
    main()
