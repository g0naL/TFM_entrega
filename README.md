# TFM - Orquestador multiagente para pentesting en laboratorio

Prototipo academico de orquestacion multiagente para pruebas de seguridad en
laboratorios autorizados. El sistema coordina reconocimiento, planificacion,
generacion de hipotesis, validacion, aprobacion humana, ejecucion controlada,
evaluacion de evidencias y generacion de informes.

El objetivo previsto es un entorno artificial y autorizado, por ejemplo
Metasploitable en una red host-only. No esta disenado para operar contra
terceros, sistemas reales no autorizados ni entornos productivos.

## Frontera de seguridad

- El objetivo debe pertenecer a una allowlist CIDR configurada.
- Las acciones se representan como objetos estructurados, no como texto libre.
- Las propuestas del LLM se validan con Pydantic antes de incorporarse al flujo.
- Las herramientas disponibles se declaran en un registro con dominio, riesgo,
  flags permitidos y necesidad de aprobacion.
- Las acciones atraviesan politica, aprobacion humana si aplica y executor.
- El executor no delega en una shell libre del sistema operativo.
- Las acciones de explotacion o prueba de impacto requieren aprobacion humana.
- Se excluyen acciones fuera de alcance, destructivas o no justificadas por las
  evidencias de la campana.

## Estructura del proyecto

```text
.
|-- README.md
|-- operator_playbook.json
|-- pyproject.toml
|-- code/
|   `-- src/
|       |-- langgraph.json
|       |-- main.py
|       `-- pentest_orchestrator/
|           |-- analysis.py
|           |-- capabilities.py
|           |-- cli.py
|           |-- config.py
|           |-- executor.py
|           |-- graph.py
|           |-- hypotheses.py
|           |-- local_env.py
|           |-- metasploit.py
|           |-- modes.py
|           |-- observability.py
|           |-- pdf.py
|           |-- planning.py
|           |-- playbook.py
|           |-- policy.py
|           |-- prompts.py
|           |-- recon.py
|           |-- recorder.py
|           |-- reporting.py
|           |-- routing.py
|           |-- schemas.py
|           |-- scope.py
|           |-- state.py
|           |-- tools.py
|           |-- validation.py
|           `-- vulnerability_catalog.py
`-- tests/
```

Directorios generados como `runs/`, `__pycache__/`, `.pytest_cache/` y
`*.egg-info/` estan ignorados por Git.

## Componentes principales

- `cli.py`: parsea argumentos, carga `.env.local`, construye configuracion e
  inicia la campana.
- `config.py`: centraliza configuracion del laboratorio, proveedor LLM y
  LangSmith.
- `graph.py`: implementa el grafo LangGraph y los nodos operativos.
- `routing.py`: decide de forma determinista el siguiente nodo segun el estado.
- `state.py`: define la memoria compartida de la campana.
- `schemas.py`: valida propuestas, planes, resultados del juez e hipotesis.
- `tools.py`: registra herramientas permitidas, riesgo y flags admitidos.
- `policy.py`: aplica reglas de alcance, modo, riesgo y aprobacion.
- `executor.py`: ejecuta acciones permitidas mediante invocaciones controladas.
- `metasploit.py`: valida y construye recursos controlados para `msfconsole`.
- `vulnerability_catalog.py`: genera hipotesis a partir de servicios detectados.
- `reporting.py` y `pdf.py`: generan `report.md` y `report.pdf`.
- `recorder.py`: persiste eventos, acciones, evidencias y estado final.

## Flujo de ejecucion

1. `orchestrator`: centraliza el ciclo de vida de la campana.
2. `recon`: valida alcance y ejecuta reconocimiento inicial con Nmap.
3. `planner`: genera un plan estructurado de enumeracion y validacion.
4. `hypothesis_generator`: combina catalogo determinista e hipotesis del modelo.
5. `validation_planner`: convierte hipotesis en tareas de validacion.
6. `specialist`: selecciona o genera el siguiente lote de acciones.
7. `policy`: valida fase, herramienta, objetivo, riesgo y modo de campana.
8. `human_approval`: solicita aprobacion cuando la politica lo requiere.
9. `executor`: ejecuta la accion aprobada y registra evidencia.
10. `judge`: evalua si la evidencia confirma, descarta o deja inconclusa la
    hipotesis.
11. `reporter`: genera artefactos finales e informe.

Los nodos vuelven al orquestador tras cada paso. La comunicacion se produce
mediante `AgentState`, lo que permite auditar la ejecucion completa.

## Requisitos

- Python 3.11 o superior.
- Nmap instalado y disponible en `PATH`.
- Ollama con el modelo configurado, o una API key de OpenAI si se usa proveedor
  remoto.
- Opcional: Metasploit Framework si se quieren usar herramientas
  `metasploit_search`, `metasploit_check` o `metasploit_proof`.
- Opcional: LangSmith para trazas remotas.

Instalacion del paquete y dependencias de desarrollo:

```powershell
python -m pip install -e .[dev]
```

## Configuracion rapida

La aplicacion puede configurarse con variables de entorno, argumentos CLI o un
archivo local `.env.local`. Los argumentos CLI tienen prioridad sobre el entorno.

Ejemplo PowerShell con Ollama:

```powershell
$env:PENTEST_TARGET_HOST="192.168.56.101"
$env:PENTEST_TARGET_PORTS="1-1000"
$env:PENTEST_AUTHORIZED_NETWORKS="192.168.56.0/24"
$env:PENTEST_LLM_PROVIDER="ollama"
$env:PENTEST_LLM_MODEL="qwen2.5:7b"
$env:PENTEST_APPROVAL_MODE="interactive"
```

Ejecucion equivalente por CLI:

```powershell
python code/src/main.py --target-host 192.168.56.101 --target-ports 1-1000 --authorized-networks 192.168.56.0/24 --approval-mode interactive --llm-provider ollama --model qwen2.5:7b
```

Tambien queda disponible el entrypoint instalado:

```powershell
pentest-orchestrator --target-host 192.168.56.101 --authorized-networks 192.168.56.0/24
```

## Opciones CLI principales

```text
--target-host              IP o hostname autorizado.
--target-ports             Rango de puertos para Nmap, por ejemplo 1-1000.
--expand-lab-ports         Escaneo adicional de puertos habituales de laboratorio.
--lab-extra-ports          Puertos extra separados por comas.
--authorized-networks      Allowlist CIDR separada por comas.
--max-tries                Numero maximo de rondas de campana.
--max-actions-per-try      Acciones maximas por ronda.
--max-runtime-s            Tiempo maximo total de campana.
--command-timeout-s        Timeout por accion.
--llm-provider             ollama u openai.
--model                    Modelo comun para todos los roles.
--approval-mode            auto-low, interactive o reject.
--runs-dir                 Directorio de artefactos.
--operator-playbook        Archivo JSON con candidatos del operador.
--mode                     detection, verification o command_execution.
--known-vulnerabilities    Lista inline o ruta para modo verification.
--no-persist               Desactiva escritura de artefactos.
```

## Modos de campana

- `detection`: reconocimiento, analisis y validacion controlada. No usa el
  playbook del operador para acciones de mayor impacto.
- `verification`: contrasta vulnerabilidades conocidas indicadas por el usuario
  mediante `--known-vulnerabilities` o `PENTEST_KNOWN_VULNERABILITIES`.
- `command_execution`: ejecuta primero deteccion y, si existen hallazgos o
  hipotesis, permite considerar acciones de impacto controlado bajo politica y
  aprobacion humana.

Si no se indica modo por CLI ni por `PENTEST_CAMPAIGN_MODE`, el CLI lo pregunta
al iniciar en terminal interactiva.

## Proveedores LLM

### Ollama

```powershell
ollama pull qwen2.5:7b
python code/src/main.py --llm-provider ollama --model qwen2.5:7b
```

Tambien se pueden separar modelos por rol:

```powershell
$env:PENTEST_PLANNER_MODEL="qwen2.5:7b"
$env:PENTEST_SPECIALIST_MODEL="qwen2.5:7b"
$env:PENTEST_JUDGE_MODEL="qwen2.5:7b"
$env:PENTEST_REPORTER_MODEL="qwen2.5:7b"
```

### OpenAI

La API key no debe guardarse en el repositorio. Definirla como variable de
entorno:

```powershell
$env:OPENAI_API_KEY="sk-..."
$env:PENTEST_LLM_PROVIDER="openai"
$env:PENTEST_LLM_MODEL="gpt-4.1-mini"
```

Ejecucion:

```powershell
python code/src/main.py --llm-provider openai --model gpt-4.1-mini --approval-mode interactive
```

Variables adicionales:

```powershell
$env:PENTEST_OPENAI_TIMEOUT_S="120"
$env:PENTEST_OPENAI_MAX_RETRIES="2"
```

## Metasploit

Metasploit es opcional. Si se usa, el sistema no ejecuta modulos libremente:
modela tres herramientas controladas:

- `metasploit_search`: busqueda de modulos sin ejecucion.
- `metasploit_check`: ejecucion de `check` contra un host autorizado y puerto
  descubierto.
- `metasploit_proof`: ejecucion de un exploit con payload controlado
  `cmd/unix/generic` para escribir un archivo de prueba en `/tmp`.

En Windows se recomienda indicar explicitamente la ruta de `msfconsole.bat`:

```powershell
$env:PENTEST_MSFCONSOLE_PATH="C:\metasploit-framework\bin\msfconsole.bat"
```

Si `msfconsole` esta correctamente en `PATH`, tambien puede resolverse sin esa
variable. Para comprobarlo:

```powershell
where.exe msfconsole
```

Las pruebas de impacto con Metasploit requieren modo compatible,
evidencia previa, politica favorable y aprobacion humana.

## Playbook del operador

`operator_playbook.json` permite definir comandos candidatos que el especialista
puede considerar. No se ejecutan automaticamente: pasan por seleccion,
validacion, politica, aprobacion humana y executor.

Formato actual:

```json
{
  "commands": [],
  "candidates": [
    {
      "id": "vsftpd-234-backdoor-check",
      "enabled": true,
      "phase": "vulnerability_scanning",
      "objective": "Verificar de forma controlada la backdoor de vsFTPd 2.3.4 en FTP/21.",
      "command": "vsftpd_backdoor_check {target_host} --ftp-port 21 --backdoor-port 6200 --timeout 5",
      "requires_port": 21,
      "requires_service": "ftp",
      "rationale": "Banner FTP, trigger USER con ':)', PASS y comprobacion del puerto 6200.",
      "risk": "high",
      "requires_human_approval": true,
      "expected_signal": "Puerto 6200 abierto tras el trigger FTP o no confirmado."
    }
  ]
}
```

Placeholders soportados:

- `{target_host}`
- `{target_ports}`
- `{first_open_port}`
- `{http_url}` o `{first_http_url}`
- `{first_http_port}`

## Artefactos generados

Por defecto, cada ejecucion escribe resultados en `runs/<timestamp>/`.

Artefactos habituales:

- `final_state.json`: estado final completo de la campana.
- `events.jsonl`: eventos cronologicos.
- `agent_activations.json`: activaciones de nodos/agentes.
- `actions.json`: ciclo de vida de acciones propuestas y ejecutadas.
- `audit.md`: apendice de auditoria determinista.
- `execution_graph.md`: grafo Mermaid de la ejecucion.
- `execution_graph.mmd`: grafo Mermaid sin bloque Markdown.
- `report.md`: informe final en Markdown.
- `report.pdf`: informe final en PDF.

`runs/` esta ignorado por Git para evitar subir artefactos pesados o sensibles.

## Observabilidad con LangSmith

LangSmith es opcional. Si esta desactivado o falta `LANGSMITH_API_KEY`, la
ejecucion local continua.

```powershell
$env:PENTEST_LANGSMITH_ENABLED="true"
$env:PENTEST_LANGSMITH_PROJECT="tfm-pentest-orchestrator"
$env:LANGSMITH_API_KEY="lsv2_..."
```

Variables adicionales:

- `PENTEST_LANGSMITH_ENDPOINT` o `LANGSMITH_ENDPOINT`.
- `PENTEST_LANGSMITH_WORKSPACE_ID` o `LANGSMITH_WORKSPACE_ID`.
- `PENTEST_LANGSMITH_HIDE_INPUTS=true`.
- `PENTEST_LANGSMITH_HIDE_OUTPUTS=true`.

Tambien puede activarse por CLI:

```powershell
python code/src/main.py --langsmith --langsmith-project tfm-pentest-orchestrator
```

## Semantica de rondas

`max_tries` representa rondas de campana, no comandos individuales. En cada
ronda, el especialista selecciona hasta `max_actions_per_try` tareas pendientes.
Cada tarea atraviesa politica, aprobacion, executor y juez de forma individual.

Una ronda puede interrumpirse si una ejecucion falla. El fallo se registra y el
especialista puede replanificar con ese contexto. La campana termina cuando se
alcanza una condicion de parada: limite de rondas, limite temporal, ausencia de
tareas utiles o generacion del informe final.

## Verificacion

Compilacion:

```powershell
python -m compileall code/src tests
```

Tests:

```powershell
python -m pytest -q
```

Ultima verificacion realizada durante el desarrollo:

```text
107 passed
```

## Ejemplos

Deteccion basica:

```powershell
python code/src/main.py --mode detection --target-host 192.168.56.101 --target-ports 1-1000 --authorized-networks 192.168.56.0/24 --approval-mode auto-low --llm-provider ollama --model qwen2.5:7b
```

Ejecucion con aprobacion humana:

```powershell
python code/src/main.py --mode command_execution --target-host 192.168.56.101 --target-ports 1-1000 --authorized-networks 192.168.56.0/24 --approval-mode interactive --operator-playbook operator_playbook.json --llm-provider ollama --model qwen2.5:7b
```

Verificacion dirigida:

```powershell
python code/src/main.py --mode verification --known-vulnerabilities "CVE-2011-2523;vsFTPd 2.3.4 backdoor" --target-host 192.168.56.101 --authorized-networks 192.168.56.0/24
```

OpenAI:

```powershell
$env:OPENAI_API_KEY="sk-..."
python code/src/main.py --llm-provider openai --model gpt-4.1-mini --approval-mode interactive
```

## Nota de uso responsable

Este repositorio es un prototipo academico. Debe utilizarse solo en laboratorios
propios o explicitamente autorizados. La allowlist de redes, la aprobacion
humana y el registro de herramientas forman parte del diseno del sistema y no
deben deshabilitarse para operar fuera del alcance definido.
