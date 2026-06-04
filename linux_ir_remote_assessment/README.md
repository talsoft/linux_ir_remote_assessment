# linux_ir_remote_assessment

Herramienta profesional de assessment remoto Linux para respuesta a incidentes. Se conecta por SSH a servidores Linux propios o explícitamente autorizados y ejecuta una recolección segura de evidencia, detección de indicadores, investigación de abuso saliente y contención opcional confirmada por operador.

Modo por defecto: `collect-only`.

## Principios de Seguridad

- Uso exclusivo sobre sistemas propios o con autorización explícita.
- Sin explotación, fuerza bruta, evasión, movimiento lateral ni persistencia.
- No modifica el sistema por defecto.
- No almacena passwords, passphrases ni secretos.
- La contención requiere modo `contain` o `full` y confirmación interactiva.
- Prioridad operativa: preservar evidencia, contener, entender causa raíz, remediar.

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r linux_ir_remote_assessment/requirements.txt
```

## Uso

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user root \
  --password \
  --mode collect-only
```

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user root \
  --key-file ~/.ssh/id_ed25519 \
  --mode detect
```

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user admin \
  --password \
  --sudo \
  --mode full \
  --abuse-investigation
```

## Autenticación

Soporta:

- SSH key con RSA, ECDSA o ED25519 mediante Paramiko.
- Passphrase de clave con `--key-passphrase`.
- Password con `--password`, solicitado por `getpass`.
- Fallback a password cuando `--key-file` falla y se usa `--fallback-password`.
- Sudo con detección de disponibilidad y passwordless/password requerido.

## Parámetros

- `--host`: host autorizado.
- `--port`: puerto SSH, default `22`.
- `--user`: usuario SSH.
- `--key-file`: clave privada SSH.
- `--key-passphrase`: solicita passphrase.
- `--password`: solicita password SSH.
- `--fallback-password`: solicita password si falla la clave.
- `--sudo`: usa sudo para comandos privilegiados.
- `--mode`: `collect-only`, `detect`, `contain`, `full`.
- `--output-dir`: directorio base de salida, default `reports`.
- `--non-interactive`: no solicita secretos ni confirmaciones.
- `--abuse-investigation`: fuerza investigación de abuso saliente.

## Modos

- `collect-only`: recolecta evidencia y genera reportes básicos.
- `detect`: recolecta, analiza y genera hallazgos.
- `contain`: recolecta, analiza y permite contención confirmada.
- `full`: recolecta, detecta, contiene y reporta recomendaciones. Las remediaciones destructivas quedan como recomendaciones confirmables, no automáticas.

## Evidencia Recolectada

Incluye inventario de sistema, usuarios, accesos, SSH, procesos, conexiones, cron, systemd, perfiles shell, LD_PRELOAD, rootkit tools si existen, integridad de paquetes si existe, logs auth/syslog/journal y firewall.

Las salidas se guardan en:

```text
<output-dir>/<host>_<timestamp>/
├── commands.log
├── evidence_index.json
├── evidence/
│   └── raw/
└── reports/
    ├── report.md
    ├── report.html
    ├── findings.json
    ├── ioc_report.json
    └── root_cause_analysis.json
```

## Investigación de Abuse Reports

El módulo `abuse_investigation.py` identifica conexiones salientes hacia:

- SSH `22`
- FTP `21`
- Telnet `23`
- SMTP `25`
- SMTPS `465`
- Submission `587`

Correlaciona PID, usuario, ruta del binario, SHA256, comando completo, hora de inicio y conexiones asociadas.

## Contención

Solo en `contain` o `full`, con confirmación exacta:

```text
APPLY-CONTAINMENT
```

Acción aplicada:

- Backup de `iptables-save`, `nft list ruleset` y `ufw status`.
- Reglas `iptables` para bloquear conexiones salientes nuevas a `22,21,23,25,465,587`.

No cambia la policy de `OUTPUT`, no cierra la sesión SSH actual y no elimina procesos automáticamente.

## Limitaciones

Un sistema comprometido puede ocultar procesos, archivos, conexiones o logs. Para incidentes críticos con sospecha de rootkit, usar esta herramienta como apoyo remoto inicial y priorizar análisis forense offline o reconstrucción desde imagen limpia.
