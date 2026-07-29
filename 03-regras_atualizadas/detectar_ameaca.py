"""
Detecção comportamental de ameaça interna — a evolução do `gerar_dfg.py`.

A ferramenta de descoberta revela o COMPORTAMENTO no grafo, mas suas regras
embutidas (acesso sem login / sessao sem logout) so olham atividades ISOLADAS —
e por isso sao cegas para o insider real, cujas sessoes tem Login e Logout
corretos. Este script fecha a lacuna: le a SEQUENCIA de cada caso e combina
varios sinais fracos num placar de risco. Nenhuma atividade sozinha e um ataque;
e a coreografia — reconhecer -> coletar em massa -> compactar -> exfiltrar,
de madrugada — que denuncia o adversario.

Uso:
    python3 detectar_ameaca.py --dataset dia2_ameaca_interna.csv
    python3 detectar_ameaca.py --dataset dia2_ameaca_interna.csv --limiar 4
    python3 detectar_ameaca.py --dataset dia2_ameaca_interna.csv --modelo    # DFG so dos casos de alto risco
    python3 detectar_ameaca.py --dataset dia2_ameaca_interna.csv --verificar  # teste de aceitacao (purple team)
"""

import argparse
import shutil
import subprocess
from collections import Counter
from datetime import time
from pathlib import Path

import pandas as pd


# ===========================================================================
# Funcoes de descoberta (embutidas do gerar_dfg.py — o dia 1)
# ===========================================================================
def carregar_log(caminho: Path) -> pd.DataFrame:
    df = pd.read_csv(caminho, parse_dates=["timestamp"])
    return df.sort_values(["case_id", "timestamp"]).reset_index(drop=True)


def descobrir_dfg(df: pd.DataFrame):
    """Retorna (arestas, atividades_iniciais, atividades_finais) do log."""
    arestas, inicios, fins = Counter(), Counter(), Counter()
    for _, caso in df.groupby("case_id", sort=False):
        atividades = caso["activity"].tolist()
        inicios[atividades[0]] += 1
        fins[atividades[-1]] += 1
        for anterior, atual in zip(atividades, atividades[1:]):
            arestas[(anterior, atual)] += 1
    return arestas, inicios, fins


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
        perigo = any(k in origem + destino for k in ("Compactar", "Upload", "USB", "Busca", "Negado"))
        cor = "red" if perigo else "black"
        linhas.append(f'  "{origem}" -> "{destino}" [label="{freq}", color={cor}];')
    linhas.append("}")
    return "\n".join(linhas)


# ===========================================================================
# Modelo de risco comportamental (o que a Atividade 3 pede)
# ===========================================================================
EXFIL_EGRESS = {"Upload_Externo", "Copia_Dispositivo_USB"}  # saida de dados do ambiente
INICIO_EXPEDIENTE, FIM_EXPEDIENTE = time(7, 0), time(20, 0)
LIMIAR_PADRAO = 3          # score >= limiar -> ALERTA
COLETA_EM_MASSA = 3        # nº de acessos sensiveis num mesmo caso para virar sinal


def pontuar_risco(caso):
    """
    Recebe o DataFrame de UM caso (ja ordenado por tempo) e devolve (score, motivos).
    Cada regra e um 'sinal fraco'. Somados, separam a exfiltracao do acesso legitimo.
    """
    atividades = caso["activity"].tolist()
    hora_login = caso["timestamp"].iloc[0].time()
    score, motivos = 0, []

    tem_compactar = "Compactar_Arquivos" in atividades
    tem_egress = any(a in EXFIL_EGRESS for a in atividades)

    if tem_compactar and tem_egress:
        score += 5
        motivos.append("compacta e exfiltra dados [Collection->Exfiltration / T1560]")
    elif tem_egress:
        score += 3
        motivos.append("exfiltracao para fora do ambiente [Exfiltration / T1567,T1052]")

    if "Busca_Arquivos" in atividades:
        score += 2
        motivos.append("reconhecimento de arquivos [Discovery / T1083]")

    n_sensivel = atividades.count("Acesso_Arquivo_Sensivel")
    if n_sensivel >= COLETA_EM_MASSA:
        score += 2
        motivos.append(f"coleta em massa: {n_sensivel} arquivos sensiveis [Collection / T1005]")

    if not (INICIO_EXPEDIENTE <= hora_login <= FIM_EXPEDIENTE):
        score += 2
        motivos.append(f"acesso fora de hora ({hora_login:%H:%M})")

    if "Acesso_Negado" in atividades:
        score += 1
        motivos.append("tentativa de acesso negada (sondagem)")

    return score, motivos


def cacar(df, limiar=LIMIAR_PADRAO):
    """Pontua todos os casos e devolve a lista ordenada por risco (maior primeiro)."""
    resultados = []
    for case_id, caso in df.groupby("case_id", sort=False):
        score, motivos = pontuar_risco(caso)
        if score > 0:
            resultados.append({
                "case_id": case_id,
                "usuario": caso["usuario"].iloc[0],
                "hora": caso["timestamp"].iloc[0],
                "score": score,
                "motivos": motivos,
                "alerta": score >= limiar,
                "trace": " -> ".join(caso["activity"].tolist()),
            })
    return sorted(resultados, key=lambda r: r["score"], reverse=True)


def imprimir_relatorio(resultados, limiar):
    alertas = [r for r in resultados if r["alerta"]]
    atencao = [r for r in resultados if not r["alerta"]]

    print("=" * 78)
    print(f" CACA COMPORTAMENTAL  ·  limiar de alerta = {limiar}")
    print("=" * 78)

    print(f"\n### ALERTAS (score >= {limiar}) — {len(alertas)} caso(s) ###")
    if not alertas:
        print("  Nenhum.")
    for r in alertas:
        print(f"\n  [{r['case_id']}] usuario '{r['usuario']}'  ·  score {r['score']}  ·  {r['hora']:%d/%m %H:%M}")
        print(f"     trace: {r['trace']}")
        for m in r["motivos"]:
            print(f"       - {m}")

    print(f"\n### ATENCAO (0 < score < {limiar}) — sinais fracos, nao condenam sozinhos ###")
    if not atencao:
        print("  Nenhum.")
    for r in atencao:
        print(f"  [{r['case_id']}] '{r['usuario']}' (score {r['score']}): {', '.join(r['motivos'])}")

    por_usuario = {}
    for r in alertas:
        por_usuario[r["usuario"]] = por_usuario.get(r["usuario"], 0) + r["score"]
    if por_usuario:
        print("\n### RISCO ACUMULADO POR USUARIO (so alertas) ###")
        for usuario, total in sorted(por_usuario.items(), key=lambda x: -x[1]):
            print(f"  {usuario}: {total}")


def verificar(df, limiar):
    """Teste de aceitacao (o 'purple team' da Atividade 3)."""
    resultados = {r["case_id"]: r for r in cacar(df, limiar)}

    def alertou(cid):
        return cid in resultados and resultados[cid]["alerta"]

    deve_alertar = ["case_019", "case_020", "case_021"]   # o insider (usuario_08)
    nao_pode_alertar = ["case_013", "case_014"]            # variacoes benignas

    print("\n=== TESTE DE ACEITACAO (purple team) ===")
    ok = True
    for cid in deve_alertar:
        passou = alertou(cid)
        ok &= passou
        print(f"  [{'OK ' if passou else 'FALHOU'}] {cid} deve alertar        -> {'alertou' if alertou(cid) else 'passou batido'}")
    for cid in nao_pode_alertar:
        passou = not alertou(cid)
        ok &= passou
        print(f"  [{'OK ' if passou else 'FALHOU'}] {cid} NAO pode alertar     -> {'nao alertou' if not alertou(cid) else 'FALSO POSITIVO'}")

    print(f"\n  Resultado: {'TODOS OS CRITERIOS PASSARAM' if ok else 'AJUSTE A REGRA — algum criterio falhou'}")
    return ok


def gerar_modelo_ataque(df, resultados, saida_dir, stem):
    """Gera o DFG SO dos casos em alerta — o 'modelo de processo do ataque'."""
    ids_alerta = [r["case_id"] for r in resultados if r["alerta"]]
    if not ids_alerta:
        print("\nNenhum caso em alerta — modelo de ataque nao gerado.")
        return
    sub = df[df["case_id"].isin(ids_alerta)].reset_index(drop=True)
    arestas, inicios, fins = descobrir_dfg(sub)
    dot = gerar_dot(arestas, inicios, fins)
    dot_path = saida_dir / f"{stem}_modelo_ataque.dot"
    png_path = saida_dir / f"{stem}_modelo_ataque.png"
    dot_path.write_text(dot, encoding="utf-8")
    print(f"\nModelo de processo do ataque (DFG dos casos em alerta): {dot_path}")
    if shutil.which("dot"):
        subprocess.run(["dot", "-Tpng", str(dot_path), "-o", str(png_path)], check=True)
        print(f"Imagem: {png_path}")
    else:
        print("Graphviz ('dot') nao encontrado — rode:  "
              f"dot -Tpng {dot_path.name} -o {png_path.name}")


def parse_args():
    parser = argparse.ArgumentParser(description="Deteccao comportamental de ameaca interna (evolucao do gerar_dfg.py).")
    parser.add_argument("--dataset", type=Path, required=True, help="Caminho do CSV do log de eventos.")
    parser.add_argument("--limiar", type=int, default=LIMIAR_PADRAO, help=f"Score minimo para virar ALERTA (padrao: {LIMIAR_PADRAO}).")
    parser.add_argument("--saida", type=Path, default=None, help="Diretorio de saida do modelo de ataque (padrao: pasta do dataset).")
    parser.add_argument("--modelo", action="store_true", help="Gera o DFG so dos casos em alerta (modelo de processo do ataque).")
    parser.add_argument("--verificar", action="store_true", help="Roda o teste de aceitacao (purple team) da Atividade 3.")
    return parser.parse_args()


def main():
    args = parse_args()
    df = carregar_log(args.dataset)

    resultados = cacar(df, args.limiar)
    imprimir_relatorio(resultados, args.limiar)

    if args.verificar:
        verificar(df, args.limiar)

    if args.modelo:
        saida_dir = args.saida or args.dataset.parent
        saida_dir.mkdir(parents=True, exist_ok=True)
        gerar_modelo_ataque(df, resultados, saida_dir, args.dataset.stem)


if __name__ == "__main__":
    main()