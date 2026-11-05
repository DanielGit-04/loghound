# Historial de cambios

## 0.2.0

### Cadena de custodia
- El manifiesto ahora puede **firmarse con Ed25519** (`keygen`, `analyze --sign-key`, `verify --public-key`). Antes solo llevaba un hash de sí mismo, que cualquiera podía recalcular tras modificarlo.
- El **hash del informe** (y de los logs y las reglas) queda dentro del manifiesto firmado.
- `verify` comprueba hash, firma y ficheros referenciados (`--evidence-dir`), y distingue avisos de fallos.
- El manifiesto ya no guarda rutas absolutas del equipo del examinador, solo nombres de fichero.
- Nuevo formato de manifiesto (`schema_version: 2`); los manifiestos de la 0.1 no son compatibles.

### Reglas
- **R004:** detectaba solo `lsass.exe` exacto; ahora reconoce la ruta completa que registra Sysmon y exige permisos de lectura de memoria (`GrantedAccess`), excluyendo Defender.
- **R003:** ya no salta con `-Encoding`; exige que el proceso sea PowerShell y que haya Base64 largo o `-nop` + ventana oculta.
- **R005 y R001:** ahora exigen valores *distintos* (equipos / servicios), como decía su descripción.
- **R006 (nueva):** borrado del registro de eventos (T1070.001).
- Nuevos operadores: `field_in`, `field_endswith`, `field_regex`, `field_regex_all`, `exclude`, `distinct_field`.
- Las reglas se validan al cargarlas, con mensajes de error claros.
- Cada detección incluye recomendación y enlace a MITRE ATT&CK.

### Parser y CLI
- Fechas con zona horaria mezclada (`Z`, `+02:00`, sin zona) ya no provocan un error; todo se normaliza a UTC. Admite fracciones de segundo de 7 dígitos (Windows).
- Admite JSON Lines y varios ficheros de log (`--logs` repetido).
- `--output report.html` sin carpeta ya no falla.
- Errores de formato con mensaje claro en lugar de volcado de errores.

### Informe
- Nueva **línea de tiempo** (el README de la 0.1 la prometía, pero no existía).
- Estilos de impresión y diseño adaptable; contenido de los logs escapado (probado contra HTML/JS hostil).

### Proyecto
- Tests ampliados de 6 a más de 80, integración continua con GitHub Actions, `pyproject.toml`, datos de ejemplo con actividad legítima parecida a un ataque.

## 0.1.0
- Primera versión: parser, motor de reglas (simple y threshold), informe HTML y manifiesto con hash.
