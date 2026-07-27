# Process Discovery — Descobrindo o DFG

Este módulo mostra a técnica mais fundamental de **descoberta de processo**
(process discovery): o **Directly-Follows Graph (DFG)**. A partir de um log
de eventos de segurança, o script `gerar_dfg.py` calcula quais atividades
acontecem imediatamente após quais outras, gera o grafo e sinaliza casos que
desviam do fluxo esperado.

Pré-requisitos: Python + `pandas` + Graphviz instalados — veja
[`01-configuracao_ambiente/readme.md`](../01-configuracao_ambiente/readme.md).

## Arquivos

| Arquivo | Descrição |
|---|---|
| `gerar_dfg.py` | Script principal: lê o log, descobre o DFG, detecta anomalias e gera o `.dot`/`.png` |
| `event_log_seguranca.csv` | Dataset de exemplo: 18 casos simulando `Login → Acesso_Arquivo_Sensivel → Logout`, com variações e anomalias |

### Formato esperado do dataset (CSV)

| Coluna | Descrição |
|---|---|
| `case_id` | Identificador do caso (uma sessão/trace) |
| `timestamp` | Data/hora do evento (`YYYY-MM-DD HH:MM:SS`) |
| `activity` | Nome da atividade (ex.: `Login`, `Acesso_Arquivo_Sensivel`, `Logout`) |
| `usuario` | Usuário responsável pelo evento |
| `recurso` | Recurso acessado (arquivo), quando aplicável |

Qualquer CSV com pelo menos `case_id`, `timestamp` e `activity` funciona com o script.

## Como rodar

### Uso básico (usa o dataset padrão do próprio diretório)

```bash
python3 gerar_dfg.py
```

Isso gera, na mesma pasta do dataset:
- `event_log_seguranca_dfg.dot` — código-fonte do grafo (Graphviz)
- `event_log_seguranca_dfg.png` — imagem renderizada do DFG

E imprime no terminal:
- atividades iniciais e finais de cada caso (com frequência)
- todas as arestas do DFG (`A -> B : frequência`)
- alertas de segurança para casos que fogem do fluxo `Login -> Acesso -> Logout`
  (ex.: acesso sem login prévio, sessão sem logout)

### Usando outro dataset

```bash
python3 gerar_dfg.py --dataset caminho/para/outro_log.csv
```

### Escolhendo a pasta de saída do .dot/.png

```bash
python3 gerar_dfg.py --dataset outro_log.csv --saida resultados/
```

### Gerando o DFG de um único usuário

Filtra o log para os casos de um usuário específico e gera um grafo isolado —
útil para investigar o comportamento de alguém em particular:

```bash
python3 gerar_dfg.py --usuario usuario_10
```

Gera `event_log_seguranca_dfg_usuario_10.dot` / `.png`, contendo só as
atividades daquele usuário.

### Ver todas as opções

```bash
python3 gerar_dfg.py --help
```

## Interpretando o resultado

- **Nó verde (`START`) e vermelho (`END`)**: início e fim do processo.
- **Espessura/rótulo das arestas**: quantas vezes aquela transição ocorreu no log.
- **Arestas em vermelho**: transições envolvendo `Login_Falha` — já vêm destacadas
  no grafo padrão como sinal de tentativa de login mal-sucedida.
- **Alertas no terminal**: qualquer caso que comece com `Acesso_Arquivo_Sensivel`
  (sem `Login` antes) ou termine sem `Logout` é reportado como desvio do
  fluxo esperado — o análogo simplificado de *conformance checking*.

## Exercício sugerido

1. Rode `python3 gerar_dfg.py` e identifique visualmente o caminho mais frequente.
2. Rode `python3 gerar_dfg.py --usuario <algum_usuario_com_alerta>` e compare o
   grafo individual com o agregado.
3. Adicione novos casos ao CSV (incluindo pelo menos uma anomalia nova) e
   rode o script de novo — observe como o grafo e os alertas mudam.
