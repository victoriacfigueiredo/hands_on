# Hands-on — Process Mining aplicado a Segurança

Repositório do hands-on de **process mining para detecção de ameaças**: a
partir de logs de eventos de segurança, descobrimos processos (DFG),
detectamos desvios de comportamento e mapeamos ataques a técnicas do
**MITRE ATT&CK**.

## Estrutura

| Pasta | Conteúdo |
|---|---|
| [`01-configuracao_ambiente`](01-configuracao_ambiente/readme.md) | Setup do ambiente (Python, pandas, Graphviz) |
| [`02-process_discovery`](02-process_discovery/readme.md) | Descoberta de processo com Directly-Follows Graph (DFG) a partir de um log de login/acesso/logout |
| `03-regras_atualizadas` | Evolução do DFG para detecção comportamental de ameaça interna (`detectar_ameaca.py`), combinando sinais fracos num placar de risco |
| `04-Apresentacoes` | Slides das aulas |
| `05-Algoritmos` | Scripts do Dia 3: exploração de ataque mapeado ao MITRE ATT&CK (`explorar_ataque.py`) e comparação de algoritmos de process mining — DFG, Heuristics Miner, Inductive Miner, conformance checking (`compara.py`) |

## Por onde começar

1. Configure o ambiente: [`01-configuracao_ambiente/readme.md`](01-configuracao_ambiente/readme.md).
2. Rode a descoberta de processo básica: [`02-process_discovery/readme.md`](02-process_discovery/readme.md).
3. Avance para a detecção comportamental em `03-regras_atualizadas` e a
   análise de ataques mapeados ao ATT&CK em `05-Algoritmos` (veja o
   [README](05-Algoritmos/README.md) da pasta).

## Pré-requisitos gerais

- Python 3.9+
- `pandas` (e `pm4py` para os scripts de comparação de algoritmos em `05-Algoritmos`)
- Graphviz (`dot`), para renderizar os grafos em `.png`

Detalhes completos de instalação por sistema operacional em
[`01-configuracao_ambiente/readme.md`](01-configuracao_ambiente/readme.md).
