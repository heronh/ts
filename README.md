# TS Lab

Analisador MPEG-TS para Linux, em esqueleto híbrido:

- **UI:** Python / PySide6 (abrir arquivo grande, lista de PIDs, dump hexadecimal, pesquisa, remap)
- **Núcleo:** C++ com `mmap` (scan, busca, reescrita de PID, PAT/PMT em seção de um pacote)
- **Opcional:** [TSDuck](https://tsduck.io/) (`tsp`) para remap com atualização completa de PSI/SI

Arquivos grandes não são carregados com `read()` integral: o C++ mapeia o TS e percorre pacotes de 188 (ou 204) bytes. A reescrita **sempre gera um arquivo novo**.

## Layout

```
native/                 núcleo C++ (mmap, PSI, remap, wrapper tsp)
src/tslab/              pacote Python
  ui/                   janela PySide6
  _core*.so             extensão pybind11 (gerada no build)
tests/                  scan / busca / remap + smoke da UI
```

## Dependências

- Linux x86_64/aarch64, GCC/Clang com C++17
- Python 3.10+, CMake 3.16+, Ninja (opcional)
- `python3-dev` (headers para pybind11)
- PySide6 (instalado via pip)
- TSDuck opcional: `tsp` no `PATH`

```bash
sudo apt install build-essential cmake ninja-build python3-dev python3-venv libegl1
# opcional, para o backend TSDuck:
# siga https://tsduck.io/ e instale o pacote tsp
```

## Build

```bash
chmod +x scripts/build.sh
./scripts/build.sh
source .venv/bin/activate
```

Ou manualmente:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Uso

Interface gráfica:

```bash
tslab
tslab caminho/arquivo.ts
```

CLI (útil em arquivos grandes e em scripts):

```bash
tslab scan gravacao.ts
tslab search gravacao.ts --pid 0x100 --payload-hex 000001
tslab remap gravacao.ts saida.ts --map 0x0100=0x0200 0x0101=0x0201
tslab remap gravacao.ts saida.ts --map 0x100=0x200 --tsduck   # se tsp estiver instalado
```

Na UI:

1. **Abrir** um `.ts`
2. Ver PIDs, tipo (PAT/PMT/H.264/AAC/…), erros de continuity e ocupação
3. Clicar num PID para o dump do primeiro pacote
4. Aba **Pesquisa** por PID, `table_id` ou sequência hex no payload
5. **Remapear PIDs** escolhe pares origem→destino, atualiza PAT/PMT no núcleo nativo, ou delega ao TSDuck

## O que o esqueleto já faz

- Detecção de pacote 188/204 e sync `0x47`
- Estatísticas por PID (contagem, PUSI, CC, TEI, scrambled)
- Classificação PAT/PMT/PCR/stream_type
- Busca sem carregar o arquivo inteiro em objetos Python
- Remap nativo do PID no header + PAT/PMT **quando a seção cabe em um pacote**
- Chamada a `tsp -P remap` quando o backend TSDuck está selecionado

## Próximos passos naturais

- Tabelas PSI/SI que atravessam vários pacotes (usar TSDuck ou um packetizer)
- Gráficos de bitrate com PCR
- Troca de *payload* entre PIDs (copy/swap de PES), não só do número do PID
- Indexação persistente para arquivos de dezenas de GB

## Testes

```bash
source .venv/bin/activate
QT_QPA_PLATFORM=offscreen pytest -q
```
