"""
Apoio ao Exercicio 2 (Dia 3) — explorando o dataset mapeado ao MITRE ATT&CK.

O `gerar_dfg.py` agrega TODOS os casos num unico grafo, entao ele junta os dois
ataques e usa so a coluna `activity`. Este script vai alem e resolve as tres
tarefas do exercicio usando tambem as colunas `tactic`, `technique_id` e `host`:

  1) MATRIZ ATT&CK    : agrupa as atividades por tatica (reconstroi a matriz do log)
  2) ISOLAR CADEIA    : filtra os casos de UMA tecnica e gera o DFG so deles
  3) LATERAL POR HOST : detecta movimentacao lateral pela regra "o host muda dentro
                        do mesmo caso logo apos Conexao_WinRM"

Reaproveita as funcoes de descoberta do dia 1 (embutidas aqui para rodar sozinho).

Uso:
    python3 explorar_attack.py --dataset dia3_attack_mapeado.csv
    python3 explorar_attack.py --dataset dia3_attack_mapeado.csv --tecnica T1021.006
    python3 explorar_attack.py --dataset dia3_attack_mapeado.csv --saida figuras/
"""

import argparse
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

# atividade-gatilho da movimentacao lateral (T1021.006)
ATIVIDADE_LATERAL = "Conexao_WinRM"


# ===========================================================================
# Descoberta do DFG (embutida do gerar_dfg.py — dia 1)
# ===========================================================================
def carregar_log(caminho: Path) -> pd.DataFrame:
    df = pd.read_csv(caminho, parse_dates=["timestamp"])
    return df.sort_values(["case_id", "timestamp"]).reset_index(drop=True)


def descobrir_dfg(df: pd.DataFrame):
    arestas, inicios, fins = Counter(), Counter(), Counter()
    for _, caso in df.groupby("case_id", sort=False):
        atividades = caso["activity"].tolist()
        inicios[atividades[0]] += 1
        fins[atividades[-1]] += 1
        for a, b in zip(atividades, atividades[1:]):
            arestas[(a, b)] += 1
    return arestas, inicios, fins


def gerar_dot(df, arestas, inicios, fins, titulo):
    """DFG colorido por tatica ATT&CK (le a coluna tactic/technique_id do log)."""
    COR = {
        "Benigno": "#E0E0E0", "Initial Access": "#FFE0B2", "Discovery": "#B3E5FC",
        "Credential Access": "#F8BBD0", "Lateral Movement": "#FF7043",
        "Execution": "#FFF176", "Persistence": "#CE93D8", "Collection": "#A5D6A7",
        "Exfiltration": "#EF5350",
    }
    # mapa atividade -> (tatica, technique_id)
    meta = {r.activity: (r.tactic, r.technique_id)
            for r in df[["activity", "tactic", "technique_id"]].drop_duplicates().itertuples()}
    L = ["digraph G {", '  rankdir=LR; bgcolor="white";',
         '  node [shape=box, style="rounded,filled", fontname=Helvetica, fontsize=10];',
         f'  labelloc="t"; label="{titulo}"; fontsize=15;',
         '  "START" [shape=circle, fillcolor=lightgreen, label="inicio"];',
         '  "END"   [shape=circle, fillcolor=lightcoral, label="fim"];']
    for atividade in {a for aresta in arestas for a in aresta}:
        tatica, tid = meta.get(atividade, ("Benigno", "-"))
        cor = COR.get(tatica, "#E0E0E0")
        rotulo = atividade if tid == "-" else f"{atividade}\\n[{tid}]"
        L.append(f'  "{atividade}" [fillcolor="{cor}", label="{rotulo}"];')
    for a, f in inicios.items():
        L.append(f'  "START" -> "{a}" [label="{f}"];')
    for a, f in fins.items():
        L.append(f'  "{a}" -> "END" [label="{f}"];')
    mx = max(arestas.values()) if arestas else 1
    for (o, d), f in arestas.items():
        L.append(f'  "{o}" -> "{d}" [label="{f}", penwidth={0.6 + (f/mx)*4:.1f}];')
    L.append("}")
    return "\n".join(L)


def salvar_dfg(df, saida_dir, stem, titulo):
    arestas, ini, fim = descobrir_dfg(df)
    dot_path = saida_dir / f"{stem}.dot"
    png_path = saida_dir / f"{stem}.png"
    dot_path.write_text(gerar_dot(df, arestas, ini, fim, titulo), encoding="utf-8")
    if shutil.which("dot"):
        subprocess.run(["dot", "-Tpng", str(dot_path), "-o", str(png_path)], check=True)
        print(f"    figura: {png_path}")
    else:
        print(f"    DOT salvo em {dot_path} (Graphviz ausente — rode 'dot -Tpng' manualmente)")


# ===========================================================================
# Tarefa 1 — Matriz ATT&CK (atividade por tatica)
# ===========================================================================
def tarefa_matriz(df):
    print("\n" + "=" * 70)
    print(" [1] MATRIZ ATT&CK — atividades agrupadas por tatica")
    print("=" * 70)
    # ordem tatica-fase para leitura tipo kill chain
    ordem = ["Initial Access", "Discovery", "Credential Access", "Lateral Movement",
             "Execution", "Persistence", "Collection", "Exfiltration", "Benigno"]
    por_tatica = defaultdict(list)
    for r in df[["activity", "tactic", "technique_id"]].drop_duplicates().itertuples():
        por_tatica[r.tactic].append((r.activity, r.technique_id))
    for tatica in sorted(por_tatica, key=lambda t: ordem.index(t) if t in ordem else 99):
        print(f"\n  {tatica}")
        for atividade, tid in sorted(por_tatica[tatica]):
            n = int((df["activity"] == atividade).sum())
            print(f"     - {atividade:22s} {tid:11s} ({n} eventos)")


# ===========================================================================
# Tarefa 2 — Isolar uma cadeia filtrando por technique_id
# ===========================================================================
def tarefa_isolar(df, tecnica, saida_dir):
    print("\n" + "=" * 70)
    print(f" [2] ISOLAR A CADEIA da tecnica {tecnica}")
    print("=" * 70)
    # casos que CONTEM a tecnica-alvo
    ids = [c for c, g in df.groupby("case_id") if tecnica in set(g["technique_id"])]
    if not ids:
        print(f"  Nenhum caso contem a tecnica {tecnica}. Tecnicas disponiveis:")
        print("   ", ", ".join(sorted(df["technique_id"].unique())))
        return
    sub = df[df["case_id"].isin(ids)].reset_index(drop=True)
    print(f"  {len(ids)} caso(s) contem {tecnica}. Historia de um deles ({ids[0]}):")
    g = sub[sub["case_id"] == ids[0]]
    for r in g.itertuples():
        seta = "  ->" if r.Index != g.index[0] else "    "
        print(f"   {seta} {r.activity:22s} {r.technique_id:11s} [{r.tactic}]  @ {r.host}")
    stem = f"cadeia_{tecnica.replace('.', '_')}"
    salvar_dfg(sub, saida_dir, stem, f"Cadeia isolada: {tecnica}")


# ===========================================================================
# Tarefa 3 — Detectar lateral pela troca de host apos Conexao_WinRM
# ===========================================================================
def tarefa_lateral(df):
    print("\n" + "=" * 70)
    print(" [3] MOVIMENTACAO LATERAL — regra: host muda apos Conexao_WinRM")
    print("=" * 70)
    achados = []
    for case_id, g in df.groupby("case_id", sort=False):
        atividades = g["activity"].tolist()
        hosts = g["host"].tolist()
        usuario = g["usuario"].iloc[0]
        for i, a in enumerate(atividades):
            if a == ATIVIDADE_LATERAL and i > 0 and hosts[i] != hosts[i - 1]:
                achados.append((case_id, usuario, hosts[i - 1], hosts[i]))
                break
    if not achados:
        print("  Nenhuma movimentacao lateral detectada.")
        return
    print(f"  {len(achados)} caso(s) com salto de host no WinRM:\n")
    print(f"   {'caso':10s} {'usuario':12s} origem -> destino")
    for case_id, usuario, origem, destino in achados:
        print(f"   {case_id:10s} {usuario:12s} {origem} -> {destino}")


def parse_args():
    ap = argparse.ArgumentParser(description="Apoio ao Exercicio 2 — explorar o dataset ATT&CK.")
    ap.add_argument("--dataset", type=Path, required=True)
    ap.add_argument("--tecnica", type=str, default="T1021.006",
                    help="technique_id para isolar na tarefa 2 (padrao: T1021.006).")
    ap.add_argument("--saida", type=Path, default=Path("figuras_ex2"))
    return ap.parse_args()


def main():
    args = parse_args()
    args.saida.mkdir(parents=True, exist_ok=True)
    df = carregar_log(args.dataset)

    tarefa_matriz(df)
    tarefa_isolar(df, args.tecnica, args.saida)
    tarefa_lateral(df)

    print("\n" + "=" * 70)
    print(f" Figuras isoladas salvas em: {args.saida}/")
    print("=" * 70)


if __name__ == "__main__":
    main()