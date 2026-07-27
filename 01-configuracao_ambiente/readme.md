# Instalação das dependências

Este hands-on precisa de duas coisas:

1. **Python 3.9+** com o pacote `pandas` (biblioteca usada pelo script para ler o CSV e montar o DFG).
2. **Graphviz** (o comando `dot`), usado para renderizar o `.dot` gerado pelo script em uma imagem `.png`.

Sem o Graphviz o script ainda funciona e mostra os resultados no terminal, mas avisa que não conseguiu gerar a imagem.

## macOS

```bash
# Python (pule se já tiver o Python 3 instalado)
brew install python

# Graphviz
brew install graphviz

# Dependências Python do projeto
pip3 install -r requirements.txt
```

## Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install python3 python3-pip graphviz

pip3 install -r requirements.txt
```

## Linux (Fedora/RHEL)

```bash
sudo dnf install python3 python3-pip graphviz

pip3 install -r requirements.txt
```

## Windows

1. Instale o Python em https://www.python.org/downloads/ (marque a opção **"Add python.exe to PATH"** durante a instalação).
2. Instale o Graphviz em https://graphviz.org/download/ (versão para Windows).
   - Após instalar, adicione a pasta `bin` do Graphviz (ex.: `C:\Program Files\Graphviz\bin`) à variável de ambiente `PATH`, caso o instalador não faça isso automaticamente.
3. Instale as dependências Python (PowerShell ou Prompt de Comando):

```powershell
pip install -r requirements.txt
```

## Verificando a instalação

Rode os comandos abaixo (em qualquer sistema) para confirmar que tudo está no lugar:

```bash
python3 --version
dot -V
pip3 show pandas
```

Se os três comandos retornarem uma versão sem erro, está tudo pronto para rodar:

```bash
python3 gerar_dfg.py
```
