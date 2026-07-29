"""
Comparacao de algoritmos de process mining sobre um log ESPAGUETE (Dia 3).

Roda no dataset de extracao real (dia3_extracao_real.csv) e mostra, lado a lado,
por que o DFG cru nao basta e o que os algoritmos mais robustos entregam:

  1. DFG cru            -> o espaguete (baseline do dia 1)
  2. DFG filtrado       -> filtragem por frequencia dobra a legibilidade... mas nao resolve
  3. Heuristics Miner   -> lida com ruido via limiar de dependencia
  4. Inductive Miner    -> modelo formal e estruturado (Petri net + process tree)
  5. Conformance        -> fitness x precision: da nome ao que se fez na mao no dia 2
  6. Foco no ataque     -> isola o comportamento suspeito e descobre o processo do ataque

Requer PM4Py:   pip install pm4py    (e Graphviz para as imagens: apt/brew install graphviz)

Uso:
    python3 comparar_algoritmos.py --dataset dia3_extracao_real.csv
    python3 comparar_algoritmos.py --dataset dia3_extracao_real.csv --corte 15 --dep 0.9 --noise 0.2
    python3 comparar_algoritmos.py --dataset dia3_extracao_real.csv --saida figuras/
"""

import argparse
from collections import Counter
from pathlib import Path

import pandas as pd

try:
    import pm4py
except ImportError:
    raise SystemExit(
        "PM4Py nao encontrado. Instale com:  pip install pm4py\n"
        "(e o Graphviz do sistema para gerar as imagens: 'sudo apt install graphviz' "
        "ou 'brew install graphviz')."
    )

# Atividades que so aparecem em sessao de ataque (recon->coleta->staging->exfil)
ATIVIDADES_EXFIL = {"ArchiveCreate", "ExternalUpload", "UsbCopy"}


# ---------------------------------------------------------------------------
# Carga e formatacao para o PM4Py
# ---------------------------------------------------------------------------
def carregar(caminho: Path):
    df = pd.read_csv(caminho, parse_dates=["timestamp"])
    df = df.sort_values(["case_id", "timestamp"]).reset_index(drop=True)
    # PM4Py espera as colunas padrao (case:concept:name, concept:name, time:timestamp)
    log = pm4py.format_dataframe(
        df, case_id="case_id", activity_key="activity", timestamp_key="timestamp"
    )
    return df, log


def salvar_viz(func, *args, destino: Path, rotulo: str):
    """Tenta salvar uma visualizacao; nao derruba o script se o Graphviz faltar."""
    try:
        func(*args, str(destino))
        print(f"    figura: {destino}")
    except Exception as e:  # graphviz ausente, etc.
        print(f"    (nao foi possivel gerar a figura de {rotulo}: {e})")


# ---------------------------------------------------------------------------
# 1 + 2. DFG cru e DFG filtrado por frequencia
# ---------------------------------------------------------------------------
def bloco_dfg(log, corte, saida):
    print("\n[1] DFG CRU (o espaguete — baseline do dia 1)")
    dfg, ini, fim = pm4py.discover_dfg(log)
    print(f"    atividades : {len(set([a for aresta in dfg for a in aresta]))}")
    print(f"    arestas    : {len(dfg)}   <- emaranhado")
    salvar_viz(pm4py.save_vis_dfg, dfg, ini, fim, destino=saida / "1_dfg_cru.png", rotulo="DFG cru")

    print(f"\n[2] DFG FILTRADO (mantendo arestas com frequencia >= {corte})")
    dfg_filt = {aresta: f for aresta, f in dfg.items() if f >= corte}
    print(f"    arestas    : {len(dfg_filt)}  (reducao de {100*(1-len(dfg_filt)/max(len(dfg),1)):.0f}%)")
    print("    -> filtrar melhora a leitura, mas o backbone ainda e complexo:")
    print("       nao captura concorrencia, escolhas nem loops. Dai os miners formais.")
    salvar_viz(pm4py.save_vis_dfg, dfg_filt, ini, fim, destino=saida / "2_dfg_filtrado.png", rotulo="DFG filtrado")


# ---------------------------------------------------------------------------
# 3. Heuristics Miner
# ---------------------------------------------------------------------------
def bloco_heuristics(log, dep, saida):
    print(f"\n[3] HEURISTICS MINER (limiar de dependencia = {dep})")
    print("    Usa frequencia das relacoes para descartar ruido; bom para logs barulhentos.")
    hn = pm4py.discover_heuristics_net(log, dependency_threshold=dep)
    salvar_viz(pm4py.save_vis_heuristics_net, hn, destino=saida / "3_heuristics_net.png", rotulo="Heuristics net")
    return hn


# ---------------------------------------------------------------------------
# 4. Inductive Miner (modelo formal: Petri net + process tree)
# ---------------------------------------------------------------------------
def bloco_inductive(log, noise, saida):
    print(f"\n[4] INDUCTIVE MINER (noise_threshold = {noise})")
    print("    Estrategia dividir-para-conquistar sobre o DFG; produz modelo garantidamente")
    print("    bem-formado (sound). Entrega Petri net + process tree.")
    net, im, fm = pm4py.discover_petri_net_inductive(log, noise_threshold=noise)
    salvar_viz(pm4py.save_vis_petri_net, net, im, fm, destino=saida / "4_inductive_petri.png", rotulo="Petri net")
    try:
        tree = pm4py.discover_process_tree_inductive(log, noise_threshold=noise)
        salvar_viz(pm4py.save_vis_process_tree, tree, destino=saida / "4_process_tree.png", rotulo="process tree")
    except Exception as e:
        print(f"    (process tree nao gerada: {e})")
    return net, im, fm


# ---------------------------------------------------------------------------
# 5. Conformance checking (fitness x precision)
# ---------------------------------------------------------------------------
def bloco_conformance(log, net, im, fm):
    print("\n[5] CONFORMANCE CHECKING (o nome formal do que se fez na mao no dia 2)")
    try:
        fit = pm4py.fitness_token_based_replay(log, net, im, fm)
        prec = pm4py.precision_token_based_replay(log, net, im, fm)
        # fit e um dict; a chave costuma ser 'average_trace_fitness' / 'log_fitness'
        fit_val = fit.get("log_fitness", fit.get("average_trace_fitness"))
        print(f"    fitness  (o modelo cobre o que aconteceu?) : {fit_val:.3f}")
        print(f"    precision(o modelo permite coisas demais?) : {prec:.3f}")
        print("    -> o trade-off classico: fitness alta + precision baixa = modelo 'flor'")
        print("       que aceita quase tudo (o efeito do espaguete). Reduzir ruido sobe a precision.")
    except Exception as e:
        print(f"    (conformance nao calculada: {e})")


# ---------------------------------------------------------------------------
# 6. Foco no ataque — isola o comportamento suspeito e descobre seu processo
# ---------------------------------------------------------------------------
def bloco_ataque(df, saida, noise):
    print("\n[6] FOCO NO ATAQUE (isolar o suspeito do ruido — a ponte com o dia 2)")
    ids = [c for c, g in df.groupby("case_id") if ATIVIDADES_EXFIL & set(g["activity"])]
    print(f"    sessoes com exfiltracao (ArchiveCreate/ExternalUpload/UsbCopy): {len(ids)}")
    if not ids:
        print("    nenhuma encontrada.")
        return
    sub = df[df["case_id"].isin(ids)].reset_index(drop=True)
    log_atk = pm4py.format_dataframe(sub, case_id="case_id", activity_key="activity", timestamp_key="timestamp")
    net, im, fm = pm4py.discover_petri_net_inductive(log_atk, noise_threshold=noise)
    salvar_viz(pm4py.save_vis_petri_net, net, im, fm, destino=saida / "6_modelo_ataque.png", rotulo="modelo do ataque")
    print("    -> escondido no espaguete de 290 sessoes, o processo do ataque emerge limpo")
    print("       quando isolado: recon -> coleta em massa -> compactacao -> exfiltracao.")


def parse_args():
    ap = argparse.ArgumentParser(description="Comparacao de algoritmos de process mining (Dia 3).")
    ap.add_argument("--dataset", type=Path, required=True, help="CSV do log de eventos.")
    ap.add_argument("--saida", type=Path, default=Path("figuras_dia3"), help="Pasta das imagens (padrao: figuras_dia3/).")
    ap.add_argument("--corte", type=int, default=15, help="Freq minima de aresta para o DFG filtrado (padrao: 15).")
    ap.add_argument("--dep", type=float, default=0.9, help="Limiar de dependencia do Heuristics Miner (padrao: 0.9).")
    ap.add_argument("--noise", type=float, default=0.2, help="noise_threshold do Inductive Miner (padrao: 0.2).")
    return ap.parse_args()


def main():
    args = parse_args()
    args.saida.mkdir(parents=True, exist_ok=True)

    df, log = carregar(args.dataset)
    print("=" * 74)
    print(f" COMPARACAO DE ALGORITMOS  ·  {df['case_id'].nunique()} casos, "
          f"{len(df)} eventos, {df['activity'].nunique()} atividades")
    print("=" * 74)

    bloco_dfg(log, args.corte, args.saida)
    bloco_heuristics(log, args.dep, args.saida)
    net, im, fm = bloco_inductive(log, args.noise, args.saida)
    bloco_conformance(log, net, im, fm)
    bloco_ataque(df, args.saida, args.noise)

    print("\n" + "=" * 74)
    print(" RESUMO — do espaguete ao modelo:")
    print("   DFG cru        : ve tudo, entende nada (baseline)")
    print("   DFG filtrado   : mais limpo, ainda sem estrutura")
    print("   Heuristics     : descarta ruido por frequencia")
    print("   Inductive      : modelo formal, sound, com estrutura")
    print("   Conformance    : mede o encaixe (fitness x precision)")
    print("   Foco no ataque : o processo malicioso emerge quando isolado")
    print("=" * 74)
    print(f"\nImagens em: {args.saida}/")


if __name__ == "__main__":
    main()