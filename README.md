# Discovery_OT

Framework modular de descubrimiento, inventario, fingerprinting y evaluación pasiva de seguridad para redes OT/ICS a partir de capturas PCAP o tráfico en vivo.

Discovery_OT identifica activos industriales mediante varios protocolos, combina evidencias de distintas fuentes, genera fingerprints normalizados, detecta operaciones potencialmente peligrosas, calcula niveles de riesgo y correlaciona productos industriales con vulnerabilidades publicadas.

La herramienta mantiene tres niveles de salida:

- Resumen rápido por terminal.
- Inventario técnico completo en JSON.
- Activos físicos correlacionados entre protocolos.

> Discovery_OT realiza análisis pasivo. No envía comandos a PLC, RTU, HMI, brokers ni dispositivos de red.

---

## Características principales

- Análisis pasivo de PCAP y PCAPNG.
- Captura en vivo mediante interfaz de red.
- Arquitectura modular basada en plugins.
- Selección individual o automática de protocolos.
- Inventario independiente por protocolo.
- Fingerprinting de fabricante, modelo, firmware y referencias de producto.
- Correlación de activos por IP, MAC, referencias, hostname, modelo y fabricante.
- Detección de operaciones de escritura y control.
- Motor común de hallazgos de seguridad.
- Cálculo de riesgo por activo.
- Resolución de aliases y nombres comerciales.
- Correlación dinámica con NVD.
- Integración local con CISA ICS Advisories mediante CSV.
- Caché SQLite para reducir consultas repetidas.
- Deduplicación de CVEs entre distintos providers.
- Resumen legible por terminal.
- Salida JSON estructurada para automatización e informes.

---

## Protocolos implementados

### Modbus/TCP

El plugin Modbus/TCP permite detectar:

- Servidores y clientes Modbus.
- Direcciones IP y MAC.
- Unit IDs.
- Function Codes.
- Excepciones Modbus.
- Operaciones de escritura FC05, FC06, FC15 y FC16.
- Clientes que realizan escrituras.
- Device Identification cuando FC43/14 está presente.
- Fabricante, modelo y firmware cuando se observan en el tráfico.

Hallazgos disponibles:

- Modbus/TCP sin autenticación nativa.
- Modbus/TCP sin cifrado.
- Operaciones de escritura observadas.
- Posible exposición a repetición de tráfico.
- Excepciones de protocolo.
- Function Codes inválidos o no reconocidos.

### Siemens S7Comm

El plugin S7Comm permite detectar:

- Servidores S7 sobre TCP/102.
- Reensamblado TPKT/COTP.
- ROSCTR.
- Funciones S7.
- Actividad `read_var` y `write_var`.
- Descargas y subidas de bloques.
- Comandos `plc_stop`.
- S7Comm Plus.
- Longitudes PDU negociadas.
- Strings de identificación observadas en UserData.
- Fabricante Siemens.
- Modelo o módulo.
- Order Number, por ejemplo `6ES7 315-2EH14-0AB0`.
- Versiones o firmware cuando aparecen en el tráfico.

Hallazgos disponibles:

- Protocolo PLC sin autenticación observada.
- Actividad de modificación o programación del PLC.
- Operaciones de escritura.
- Descargas, subidas o parada del PLC.

### PROFINET DCP

El plugin PROFINET DCP permite detectar:

- MAC de origen.
- Nombre de estación.
- Alias.
- Tipo de dispositivo.
- Vendor ID.
- Device ID.
- Roles PROFINET.
- Direcciones IP, máscaras y gateways.
- Resolución de fabricante y modelo mediante catálogos.

### LLDP v2

El plugin LLDP enriquecido permite detectar:

- MAC del emisor.
- System Name.
- System Description.
- Port Description.
- Management Address.
- Fabricante inferido.
- Modelo cuando coincide con patrones conocidos.
- Firmware observado en la descripción.
- Referencias industriales, como números Siemens `6ES7`.
- Información útil para correlacionar dispositivos con S7, Modbus o PROFINET.

Ejemplo de evidencia LLDP:

```text
Siemens, SIMATIC S7, CPU-200 SMART,
6ES7 288-1CR60-0AA0, HW: 3, FW: V.2.0.0
```

### DNP3

El plugin DNP3 permite detectar:

- Outstations y masters.
- TCP y UDP sobre el puerto 20000.
- Direcciones DNP3.
- Funciones de aplicación.
- Object Groups.
- Operaciones `write`, `select`, `operate` y `direct_operate`.
- Reinicios cold y warm cuando aparecen.

### MQTT

El plugin MQTT está preparado para inventariar brokers y actividad MQTT visible sin TLS.

### MQTTS

El plugin MQTTS permite detectar:

- Brokers probables sobre TLS.
- Puerto 8883 y puertos configurados.
- Client Hello y Server Hello.
- Versiones de registros TLS.
- SNI.
- Alertas y Application Data.

El contenido MQTT no se interpreta cuando está cifrado.

---

## Arquitectura

```text
PCAP o captura en vivo
        |
        v
ProtocolRegistry
        |
        v
Plugins de protocolo
        |
        v
Resultados por protocolo
        |
        v
FingerprintBuilder
        |
        +--> SecurityRules
        |        |
        |        v
        |    RiskEngine
        |
        v
AssetCorrelator
        |
        v
Activo físico unificado
        |
        v
AliasResolver
        |
        v
VulnerabilityEngine
        |
        +--> CISA ICS Provider
        +--> NVD Provider
        +--> OpenCVE Provider opcional
        |
        v
VulnerabilityDeduplicator
        |
        v
Terminal + JSON
```

---

## Estructura orientativa de la herrramienta.

```text
ot_discovery/
├── discover_ot.py
├── core/
│   ├── alias_resolver.py
│   ├── asset_correlator.py
│   ├── asset_fingerprint.py
│   ├── base.py
│   ├── cache_manager.py
│   ├── context.py
│   ├── fingerprint_builder.py
│   ├── registry.py
│   ├── risk_engine.py
│   ├── security_rules.py
│   ├── security_summary.py
│   ├── stream_framers.py
│   ├── stream_plugin.py
│   ├── vulnerability_deduplicator.py
│   ├── vulnerability_engine.py
│   └── vulnerability_models.py
├── protocols/
│   ├── dnp3.py
│   ├── lldp.py
│   ├── modbus_tcp.py
│   ├── mqtt.py
│   ├── mqtts.py
│   ├── profinet_dcp.py
│   └── s7comm.py
├── providers/
│   ├── base_provider.py
│   ├── cisa_ics_provider.py
│   ├── nvd_provider.py
│   └── opencve_provider.py
├── data/
│   ├── model_catalog.json
│   ├── product_aliases.json
│   ├── profinet_model_catalog.json
│   ├── profinet_vendor_catalog.json
│   └── cisa_ics/
│       └── CISA_ICS_ADV_Master.csv
├── tools/
│   └── update_cisa_ics.sh
└── vulnerability_cache.db
```

---

## Instalación

### Requisitos

- Python 3.10 o superior.
- `scapy`.
- `psutil`.
- `requests`.
- `tqdm`.
- SQLite, incluido normalmente con Python.
- Permisos de captura cuando se analiza tráfico en vivo.

### Entorno virtual

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Dependencias

```bash
pip install scapy psutil requests tqdm
```

Si el proyecto dispone de `requirements.txt`:

```bash
pip install -r requirements.txt
```

---

## Uso

### Listar protocolos

```bash
python3 discover_ot.py --list-protocols
```

### Analizar un PCAP con todos los protocolos

```bash
python3 discover_ot.py \
  --auto-red \
  --test ../pcap/S7.pcap \
  --quiet
```

### Analizar únicamente S7Comm

```bash
python3 discover_ot.py \
  --auto-red \
  --test ../pcap/snap7_s300_everything.pcapng \
  --quiet \
  --protocol s7comm
```

### Analizar únicamente Modbus/TCP

```bash
python3 discover_ot.py \
  --auto-red \
  --test ../pcap/modbus_test_data.pcap \
  --quiet \
  --protocol modbus_tcp
```

### Analizar varios protocolos

```bash
python3 discover_ot.py \
  --auto-red \
  --test captura.pcapng \
  --protocol lldp \
  --protocol s7comm \
  --protocol modbus_tcp
```

### Captura en vivo

```bash
sudo python3 discover_ot.py \
  --auto-red \
  --interfaz eth0 \
  --tiempo 300
```

### Especificar salida

```bash
python3 discover_ot.py \
  --auto-red \
  --test captura.pcap \
  --salida informe_planta.json
```

---

## Salida por terminal

La terminal muestra un resumen corto por protocolo y una sección de activos correlacionados.

Ejemplo:

```text
========================================
Discovery_OT Security Summary
========================================
Assets discovered : 8

[s7comm]
  192.168.2.10 (MEDIUM/35)
    - [MEDIUM] Unauthenticated PLC protocol
    - [HIGH] PLC modification activity observed

========================================
Correlated Assets
========================================

  asset_192_168_2_10 (MEDIUM/35)
    IPs: 192.168.2.10
    MACs: 00:1c:06:1f:18:6d, 00:1c:06:1f:18:6c
    Protocols: lldp, s7comm
    Asset type: plc
    Fingerprint: Siemens / CPU 200 SMART
    Firmware: V.2.0.0
    Order Number: 6ES7 288-1CR60-0AA0
    Correlation reasons: matching_management_ip
    Unique vulnerabilities: 3
      - CVE-2024-35292 [HIGH] CVSS 8.8
        Sources: nvd, cisa_ics
```

---

## Salida JSON

El JSON conserva dos perspectivas.

### Resultados por protocolo

```json
{
  "protocols": {
    "lldp": {},
    "s7comm": {},
    "modbus_tcp": {}
  }
}
```

Esta sección contiene la evidencia técnica original de cada plugin.

### Activos correlacionados

```json
{
  "correlated_assets": {
    "asset_192_168_2_10": {
      "ips": [
        "192.168.2.10"
      ],
      "macs": [
        "00:1c:06:1f:18:6d",
        "00:1c:06:1f:18:6c"
      ],
      "vendor": "Siemens",
      "model": "CPU 200 SMART",
      "firmware": "V.2.0.0",
      "order_numbers": [
        "6ES7 288-1CR60-0AA0"
      ],
      "protocols": [
        "lldp",
        "s7comm"
      ],
      "correlation_reasons": [
        "matching_management_ip"
      ],
      "risk_level": "MEDIUM"
    }
  }
}
```

---

## Fingerprinting

Todos los protocolos convergen en `AssetFingerprint`.

Campos principales:

```python
AssetFingerprint(
    ip=None,
    vendor=None,
    model=None,
    firmware=None,
    order_numbers=[],
    protocols=[],
    confidence=0,
    metadata={},
)
```

### Fuentes de identidad

- Modbus Device Identification.
- S7 UserData.
- Order Numbers Siemens.
- PROFINET Vendor ID y Device ID.
- LLDP System Description.
- LLDP Management Address.
- SNI y datos TLS en MQTTS.
- Información combinada del activo correlacionado.

### Confianza

La confianza aumenta cuando se observan datos más precisos:

- Fabricante.
- Modelo.
- Firmware.
- Order Number.
- IP y MAC.
- Coincidencia entre varios protocolos.

La confianza no significa que una vulnerabilidad esté confirmada. Indica la calidad de la identificación del activo.

---

## AliasResolver

`AliasResolver` convierte referencias industriales y nombres parciales en identidades canónicas.

Ejemplo de `data/product_aliases.json`:

```json
{
  "6ES7 315-2EH14-0AB0": {
    "vendor": "Siemens",
    "family": "SIMATIC S7-300",
    "model": "CPU 315-2 PN/DP",
    "product_name": "SIMATIC S7-300 CPU 315-2 PN/DP",
    "search_terms": [
      "SIMATIC S7-300",
      "S7-300",
      "CPU 315-2 PN/DP"
    ]
  }
}
```

El resolver mejora la búsqueda en NVD y CISA sin modificar los parsers.

---

## AssetCorrelator

El correlador fusiona evidencias observadas por varios protocolos.

### Evidencias ponderadas

- MAC coincidente.
- IP o Management Address coincidente.
- Order Number coincidente.
- Hostname o Station Name coincidente.
- Modelo compatible.
- Fabricante coincidente.

No se debe fusionar un activo únicamente porque comparta fabricante.

### Resultado

El mismo PLC observado por LLDP y S7Comm se representa una sola vez en `correlated_assets`, conservando la evidencia original de ambos plugins.

---

## SecurityRules

`SecurityRules` genera hallazgos locales basados en la actividad observada.

Ejemplos:

- Modbus/TCP sin autenticación.
- Modbus/TCP sin cifrado.
- Escrituras Modbus observadas.
- Programación o modificación S7 observada.
- Operaciones DNP3 de control.
- Versiones TLS antiguas.
- Exposición de información de inventario LLDP.

Estos hallazgos no dependen de Internet ni de bases de CVEs.

---

## RiskEngine

El motor asigna pesos por severidad:

```text
CRITICAL  40
HIGH      25
MEDIUM    10
LOW        5
INFO       0
```

Niveles usados:

```text
0          UNKNOWN
1-19       LOW
20-49      MEDIUM
50-79      HIGH
80-100     CRITICAL
```


---

## VulnerabilityEngine

El motor recibe un fingerprint normalizado y ejecuta todos los providers configurados.

Providers implementados:

- NVD.
- CISA ICS mediante CSV local.
- OpenCVE opcional.

El motor incluye:

- Caché SQLite.
- Consultas por fabricante, modelo, familia, aliases y Order Number.
- Filtros locales para reducir falsos positivos.
- Conservación de resultados originales por provider.

---

## NVD Provider

NVD se consulta mediante búsquedas progresivas.

Ejemplo:

```text
Siemens CPU 200 SMART
Siemens SIMATIC S7-200 SMART
CPU 200 SMART
SIMATIC S7-200 SMART
6ES7 288-1CR60-0AA0
```

El provider conserva candidatos y filtra los resultados según:

- Modelo.
- Familia.
- Referencia.
- Search terms del AliasResolver.
- Descripciones y configuraciones del CVE.

Una coincidencia textual no implica vulnerabilidad confirmada.

---

## CISA ICS Provider

El provider CISA ICS utiliza un CSV local para funcionar offline.

Ubicación esperada:

```text
data/cisa_ics/CISA_ICS_ADV_Master.csv
```

El motor se puede configurar así:

```python
vulnerability_engine = VulnerabilityEngine(
    providers=[
        CisaIcsProvider(
            csv_file=str(
                base_dir
                / "data"
                / "cisa_ics"
                / "CISA_ICS_ADV_Master.csv"
            )
        ),
        NvdProvider(),
    ],
    cache_db=str(
        base_dir
        / "vulnerability_cache.db"
    ),
)
```

El orden recomendado es:

```text
CISA ICS
NVD
OpenCVE opcional
```

---

## Actualizar CISA ICS

Ejemplo de script `tools/update_cisa_ics.sh`:

```bash
#!/usr/bin/env bash

set -eu

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT_DIR="$BASE_DIR/data/cisa_ics"
OUTPUT_FILE="$OUTPUT_DIR/CISA_ICS_ADV_Master.csv"
TEMP_FILE="$OUTPUT_FILE.tmp"

URL="https://github.com/icsadvprj/ICS-Advisory-Project/raw/refs/heads/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv"

mkdir -p "$OUTPUT_DIR"
curl -fL "$URL" -o "$TEMP_FILE"

if [ ! -s "$TEMP_FILE" ]; then
    echo "Error: CSV vacio."
    rm -f "$TEMP_FILE"
    exit 1
fi

mv "$TEMP_FILE" "$OUTPUT_FILE"

echo "CISA ICS actualizado: $OUTPUT_FILE"
```

Después de actualizar el dataset conviene eliminar la caché:

```bash
rm -f vulnerability_cache.db
```

---

## Caché SQLite

`CacheManager` almacena las respuestas de providers para evitar peticiones repetidas.

Tabla:

```sql
CREATE TABLE IF NOT EXISTS vulnerabilities (
    cache_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL
);
```

Para limpiar la caché:

```bash
rm -f vulnerability_cache.db
```

O:

```bash
sqlite3 vulnerability_cache.db \
  "DELETE FROM vulnerabilities;"
```

Durante desarrollo, una respuesta vacía cacheada puede impedir que una consulta modificada vuelva a ejecutarse. Borra la caché cuando cambies queries, aliases o providers.

---

## Deduplicación de vulnerabilidades

`VulnerabilityDeduplicator` agrupa resultados de NVD, CISA y otros providers por identificador CVE.

Ejemplo:

```json
{
  "cve": "CVE-2024-35292",
  "severity": "HIGH",
  "cvss": 8.8,
  "sources": [
    "nvd",
    "cisa_ics"
  ],
  "advisories": [
    "ICSA-24-..."
  ],
  "status": "product_match",
  "confidence": 85
}
```

La salida original de cada provider se conserva en `raw_sources`.

---

## Estados recomendados para CVEs

Una CVE debe clasificarse con prudencia:

```text
candidate
keyword_candidate
family_match
product_match
exact_model_match
exact_order_match
product_and_firmware_observed
confirmed
not_affected
unknown_version
```

Interpretación:

- `candidate`: resultado amplio pendiente de validar.
- `family_match`: coincide la familia del producto.
- `product_match`: coincide el producto.
- `exact_order_match`: aparece la referencia exacta.
- `product_and_firmware_observed`: se conoce producto y firmware, pero puede faltar validar el rango.
- `confirmed`: producto y versión están incluidos de forma inequívoca en el rango afectado.
- `not_affected`: el firmware observado queda fuera del rango vulnerable.
- `unknown_version`: el producto coincide, pero no hay firmware suficiente.

No se debe etiquetar un activo como vulnerable únicamente porque NVD devuelva un resultado por palabras clave.

---

## Funcionamiento offline

Discovery_OT puede analizar PCAP y aplicar reglas locales sin Internet.

Para búsquedas offline:

- Mantén actualizado el CSV CISA ICS.
- Conserva la caché SQLite.
- Añade una base local de aliases.
- Añade providers locales adicionales si es necesario.

Arquitectura recomendada para redes aisladas:

```text
Equipo con Internet
        ↓
Actualizar CSV y feeds
        ↓
Copiar datos al equipo OT
        ↓
Discovery_OT consulta archivos locales
```

## Funcionamineto online (conectado a la red)

Discovery_OT es capaz de ser conectado a la red y de forma activa analizar la red en la busqueda de los activos industriales. 
No genera trafico en general. Siempre se podrá exportar en un pcap para su posterior análisis offline.


---

## Limitaciones actuales

- El análisis es pasivo y depende del tráfico observado.
- Si el PCAP no contiene identificación, el fabricante o modelo pueden permanecer desconocidos.
- Modbus Device Identification no siempre está presente.
- S7 puede no revelar firmware.
- LLDP puede revelar infraestructura, pero no todos los dispositivos emiten LLDP.
- MQTT sobre TLS no permite interpretar el payload.
- Una MAC aporta fabricante probable, no modelo exacto.
- NVD puede devolver falsos positivos por búsquedas amplias.
- La validación de rangos de firmware aún requiere parsers de versiones específicos por fabricante.
- NAT, gateways, múltiples interfaces y direcciones de gestión pueden complicar la correlación.
- El mismo modelo puede tener variantes de hardware distintas.
- Algunos advisories usan nombres comerciales diferentes a los observados en el tráfico.
- `correlation_confidence` y `fingerprint confidence` no equivalen a confirmación de vulnerabilidad.

---


## Próximas mejoras

- Dashboard HTML autocontenido y offline.
- Filtros por fabricante, protocolo, riesgo y CVE.
- Vista de topología OT.
- Validación automática de rangos de firmware.
- Providers de Siemens ProductCERT, Schneider y Rockwell.
- OUI resolver local.
- Detección de modelos adicionales por LLDP.
- Exportación Markdown y PDF.
- Histórico de análisis.
- Comparación entre inventarios.
- Alertas por activos o vulnerabilidades nuevas.
- Integración con CMDB o inventarios externos.
- Pruebas unitarias para parsers, correlador y providers.

---

## Depuración

### Validar sintaxis

```bash
python3 -m py_compile discover_ot.py
python3 -m py_compile core/security_summary.py
python3 -m py_compile core/asset_correlator.py
python3 -m py_compile providers/nvd_provider.py
```

### Verificar `SecuritySummary.build`

```bash
python3 - <<'PY'
from core.security_summary import SecuritySummary
import inspect

print(hasattr(SecuritySummary, "build"))
print(inspect.signature(SecuritySummary.build))
PY
```

### Consultar activos correlacionados

```bash
jq '.correlated_assets' inventario_ot.json
```

### Consultar vulnerabilidades deduplicadas

```bash
jq '
  .correlated_assets
  | to_entries[]
  | {
      asset: .key,
      vulnerabilities:
        .value.deduplicated_vulnerabilities
    }
' inventario_ot.json
```

### Consultar caché

```bash
sqlite3 vulnerability_cache.db \
  "SELECT cache_key FROM vulnerabilities;"
```

---

## Estado del proyecto

La implementación actual cubre:

```text
Descubrimiento pasivo             Implementado
Plugins OT modulares              Implementado
Fingerprinting                    Implementado
Order Numbers Siemens             Implementado
LLDP enriquecido                  Implementado
Security findings                 Implementado
Risk score                        Implementado
Correlación de activos            Implementado
Aliases de productos              Implementado
NVD Provider                      Implementado
CISA ICS Provider                 Implementado
Caché SQLite                      Implementado
Deduplicación entre providers     Implementado
Resumen de terminal               Implementado
JSON técnico                      Implementado
Dashboard HTML                    Pendiente
Validación exacta de firmware     En evolución
```

Y lo que se ha comprobado:
```text
Descubrimiento pasivo con la busqueda al NVD          Conseguido
Descubrimiento pasivo con busqueda al CISA            Conseguido
Descubrimiento activo en red                          Falta comprobar
Descubrimiento activo con busqueda al NVD             Falta comprobar 
Descubrimiento activo con busqueda al CISA            Falta comprobar
En la busqueda eliminacion de duplicados al 
usar en la busqueda NVD + CISA                        Conseguido 
```

## Aviso

Discovery_OT ayuda a descubrir activos y priorizar posibles riesgos. Los resultados de correlación de CVEs son candidatos técnicos y deben validarse antes de declarar un dispositivo vulnerable.
