# Scripts de Process Mining — Dia 3

Este diretório contém dois scripts de apoio ao Exercício 2 do Dia 3, que exploram
um log de eventos mapeado ao MITRE ATT&CK.

Datasets disponíveis no diretório:
- `dia3_ataque_mapeado.csv`
- `dia3_extracao_completa.csv`

## Pré-requisitos

```bash
pip install pandas
```

Para gerar as figuras (`.png`) é necessário o Graphviz instalado no sistema:

```bash
brew install graphviz      # macOS
sudo apt install graphviz  # Debian/Ubuntu
```

Sem o Graphviz, os scripts continuam funcionando e salvam os arquivos `.dot`
correspondentes (podem ser convertidos manualmente com `dot -Tpng`).

`compara.py` também requer o PM4Py:

```bash
pip install pm4py
```

---

## `explorar_ataque.py`

Vai além do DFG agregado do dia 1 e resolve três tarefas usando as colunas
`tactic`, `technique_id` e `host` do log:

1. **Matriz ATT&CK** — agrupa as atividades por tática, reconstruindo a matriz do log.
2. **Isolar cadeia** — filtra os casos de UMA técnica (`--tecnica`) e gera o DFG só deles.
3. **Lateral por host** — detecta movimentação lateral pela regra "o host muda dentro
   do mesmo caso logo após `Conexao_WinRM`".

### Uso

```bash
python3 explorar_ataque.py --dataset dia3_ataque_mapeado.csv
```

Isolando uma técnica específica:

```bash
python3 explorar_ataque.py --dataset dia3_ataque_mapeado.csv --tecnica T1021.006
```

Escolhendo a pasta de saída das figuras (padrão: `figuras_ex2/`):

```bash
python3 explorar_ataque.py --dataset dia3_ataque_mapeado.csv --saida figuras/
```

### Argumentos

| Argumento    | Obrigatório | Padrão         | Descrição                                              |
|--------------|:-----------:|----------------|---------------------------------------------------------|
| `--dataset`  | sim         | —              | Caminho do CSV do log de eventos                        |
| `--tecnica`  | não         | `T1021.006`    | `technique_id` a isolar na tarefa 2                      |
| `--saida`    | não         | `figuras_ex2/` | Pasta onde salvar as figuras (`.dot`/`.png`) da cadeia   |

---

## `compara.py`

Compara lado a lado diferentes algoritmos de process mining sobre um log
espaguete, mostrando por que o DFG cru não basta e o que os algoritmos mais
robustos entregam:

1. **DFG cru** — o espaguete (baseline do dia 1).
2. **DFG filtrado** — filtragem por frequência de arestas (`--corte`).
3. **Heuristics Miner** — lida com ruído via limiar de dependência (`--dep`).
4. **Inductive Miner** — modelo formal e estruturado, Petri net + process tree (`--noise`).
5. **Conformance checking** — fitness x precision do modelo gerado pelo Inductive Miner.
6. **Foco no ataque** — isola as sessões com exfiltração (`ArchiveCreate`,
   `ExternalUpload`, `UsbCopy`) e descobre o processo do ataque isoladamente.

### Uso

```bash
python3 compara.py --dataset dia3_extracao_completa.csv
```

Ajustando os parâmetros dos algoritmos:

```bash
python3 compara.py --dataset dia3_extracao_completa.csv --corte 15 --dep 0.9 --noise 0.2
```

Escolhendo a pasta de saída das figuras (padrão: `figuras_dia3/`):

```bash
python3 compara.py --dataset dia3_extracao_completa.csv --saida figuras/
```

### Argumentos

| Argumento    | Obrigatório | Padrão          | Descrição                                                    |
|--------------|:-----------:|-----------------|----------------------------------------------------------------|
| `--dataset`  | sim         | —               | Caminho do CSV do log de eventos                                |
| `--saida`    | não         | `figuras_dia3/` | Pasta onde salvar as imagens geradas                             |
| `--corte`    | não         | `15`            | Frequência mínima de aresta para o DFG filtrado                 |
| `--dep`      | não         | `0.9`           | Limiar de dependência do Heuristics Miner                       |
| `--noise`    | não         | `0.2`           | `noise_threshold` do Inductive Miner                             |
