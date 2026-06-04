# linux_ir_remote_assessment

Herramienta profesional de respuesta a incidentes para realizar assessments remotos sobre servidores Linux autorizados mediante SSH.

El objetivo es ayudar a consultores de Talsoft TS a recolectar evidencia, detectar indicadores de compromiso, investigar abuso saliente SSH/FTP/SMTP, identificar persistencia y generar reportes ejecutivos y técnicos sin modificar el sistema por defecto.

Modo por defecto: `collect-only`.

## Uso Autorizado

Esta herramienta debe utilizarse únicamente sobre sistemas propios o con autorización explícita del cliente o propietario del activo.

No incluye funcionalidades ofensivas: no explota vulnerabilidades, no realiza fuerza bruta, no evade controles, no implementa movimiento lateral y no instala persistencia.

## Instalación

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r linux_ir_remote_assessment/requirements.txt
```

## Ejemplos de Uso

Recolección sin modificar el sistema:

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user root \
  --password \
  --mode collect-only
```

Detección usando clave SSH:

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user root \
  --key-file ~/.ssh/id_ed25519 \
  --mode detect
```

Assessment completo con sudo e investigación de abuso saliente:

```bash
python3 linux_ir_remote_assessment/main.py \
  --host 209.126.107.84 \
  --user admin \
  --password \
  --sudo \
  --mode full \
  --abuse-investigation
```

## Modos

- `collect-only`: recolecta evidencia y genera artefactos básicos.
- `detect`: recolecta evidencia, analiza indicadores y genera hallazgos.
- `contain`: recolecta, analiza y permite contención confirmada por operador.
- `full`: recolecta, detecta, contiene y reporta recomendaciones de remediación.

## Funcionalidades Principales

- Inventario de sistema, red, usuarios, procesos y conexiones.
- Revisión de accesos SSH, `authorized_keys`, sudoers y cuentas UID 0.
- Detección de procesos ejecutándose desde `/tmp`, `/var/tmp` y `/dev/shm`.
- Investigación de conexiones salientes hacia puertos `22`, `21`, `23`, `25`, `465` y `587`.
- Detección de cron jobs, servicios systemd, timers, perfiles shell y `LD_PRELOAD` sospechosos.
- Ejecución de `rkhunter`, `chkrootkit`, `clamscan`, `debsums` y `rpm -Va` si ya existen en el sistema.
- Análisis básico de logs de autenticación, sudo, SSH y creación de usuarios.
- Reportes ejecutivos y técnicos en Markdown, HTML y JSON.

## Artefactos Generados

Cada ejecución crea una carpeta con timestamp bajo el directorio de salida:

```text
reports/<host>_<timestamp>/
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

## Contención

La contención solo se ejecuta en modos `contain` o `full`, y requiere confirmación interactiva exacta.

Acciones soportadas:

- Backup de reglas `iptables`, `nftables` y estado `ufw`.
- Bloqueo de conexiones salientes nuevas hacia puertos de abuso comunes.

La herramienta no cambia la policy `OUTPUT`, no cierra la sesión SSH actual y no elimina procesos automáticamente.

## Estructura

```text
linux_ir_remote_assessment/
├── main.py
├── modules/
├── reports/
├── templates/
├── evidence/
├── README.md
└── requirements.txt
```

## Recomendaciones Operativas

- Ejecutar primero en `collect-only` para preservar evidencia.
- Usar `detect` cuando el objetivo sea generar hallazgos automáticos sin cambios.
- Usar `--sudo` cuando el cliente autorice lectura de logs, cron, sudoers y evidencia privilegiada.
- Preservar binarios sospechosos y hashes antes de detener procesos o cuarentenar archivos.
- Si hay sospecha de rootkit o alteración de binarios del sistema, priorizar reconstrucción desde imagen limpia.

## Limitaciones

El análisis remoto depende de la integridad del host examinado. Un sistema comprometido puede ocultar procesos, archivos, conexiones o logs. Para incidentes críticos, usar esta herramienta como evaluación inicial y complementar con análisis forense offline.
