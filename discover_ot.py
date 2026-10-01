#!/usr/bin/env python3
import argparse
import ipaddress
import json
import signal
import socket
import sys
import time
from pathlib import Path

import psutil
from scapy.all import IP, TCP, PcapReader, sniff
from tqdm import tqdm

from core.context import DiscoveryContext
from core.registry import ProtocolRegistry
from core.security_summary import SecuritySummary

from core.fingerprint_builder import FingerprintBuilder
from core.security_rules import SecurityRules
from core.risk_engine import RiskEngine
from core.asset_correlator import AssetCorrelator
from core.vulnerability_engine import (VulnerabilityEngine)
from core.vulnerability_deduplicator import VulnerabilityDeduplicator
from providers.nvd_provider import (NvdProvider)
from core.alias_resolver import (AliasResolver)               
from core.asset_correlator import (AssetCorrelator)
from providers.cisa_provider import CisaIcsProvider

RUNNING = True

def get_inventory(protocol_data):

    for key in (
        "inventory",
        "assets",
        "servers",
        "devices",
        "outstations",
        "brokers",
        "emitters",
    ):
        if key in protocol_data:
            return protocol_data[key]

    return {}


def stop_handler(signum, frame):
    global RUNNING
    RUNNING = False
    tqdm.write("Finalizacion solicitada; se guardaran los resultados.")


def has_vulnerability_identity(fingerprint):

    if fingerprint is None:
        return False

    if fingerprint.vendor:
        return True

    if fingerprint.model:
        return True

    if getattr(
        fingerprint,
        "order_numbers",
        [],
    ):
        return True

    metadata = (
        getattr(
            fingerprint,
            "metadata",
            {},
        )
        or {}
    )

    return bool(
        metadata.get("product_name")
        or metadata.get("family")
        or metadata.get("search_terms")
        or metadata.get("system_description")
    )

def build_parser():
    parser = argparse.ArgumentParser(
        description="""
            Framework modular de descubrimiento pasivo OT.

            Analiza tráfico de red industrial para identificar dispositivos,
            protocolos y activos OT sin generar tráfico activo.
            """
    )

    parser.add_argument(
        "red",
        nargs="?",
        default=None,
        help="Red objetivo en formato CIDR (ej: 192.168.1.0/24)."
    )

    parser.add_argument(
        "--auto-red",
        action="store_true",
        help="Detecta automáticamente la red local a monitorizar."
    )

    parser.add_argument(
        "--list-protocols",
        action="store_true",
        help="Muestra la lista de protocolos OT soportados y finaliza."
    )

    parser.add_argument(
        "--protocol",
        action="append",
        dest="protocols",
        help="Protocolo a habilitar. Puede especificarse varias veces. "
             "Ejemplo: --protocol modbus --protocol s7"
    )

    parser.add_argument(
        "--test",
        metavar="PCAP",
        help="Analiza un fichero PCAP en lugar de capturar tráfico en vivo."
    )

    parser.add_argument(
        "-i", "--interfaz",
        help="Interfaz de red desde la que capturar tráfico (ej: eth0)."
    )

    parser.add_argument(
        "-t", "--tiempo",
        type=int,
        default=300,
        help="Duración de la captura en segundos (por defecto: 300)."
    )

    parser.add_argument(
        "-o", "--salida",
        default="inventario_ot.json",
        help="Archivo JSON donde se guardará el inventario generado."
    )

    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Reduce la salida por consola al mínimo."
    )

    parser.add_argument(
        "--model-catalog",
        help="Ruta al catálogo de modelos utilizado para enriquecer activos detectados."
    )

    parser.add_argument(
        "--profinet-vendor-catalog",
        help="Ruta al catálogo de fabricantes PROFINET."
    )

    parser.add_argument(
        "--profinet-model-catalog",
        help="Ruta al catálogo de modelos PROFINET."
    )

    return parser

def validate_args(parser, args):
    if args.list_protocols:
        return None
    if args.red and args.auto_red:
        parser.error("No combines una red manual con --auto-red.")
    if not args.red and not args.auto_red:
        parser.error("Indica una red CIDR o utiliza --auto-red.")
    network = None
    if args.red:
        try:
            network = ipaddress.ip_network(args.red, strict=False)
        except ValueError as error:
            parser.error(f"Red no valida: {error}")
    if bool(args.test) == bool(args.interfaz):
        parser.error("Utiliza exactamente uno: --test o --interfaz.")
    if args.test:
        path = Path(args.test)
        if not path.is_file():
            parser.error(f"PCAP no encontrado: {path}")
        args.test = path
    return network


def list_protocols(registry):
    print("Protocolos disponibles:")
    for plugin_id, plugin_class in registry.available().items():
        meta = plugin_class.metadata()
        print(f"  {plugin_id}: {meta['nombre']} v{meta['version']}")
        print(f"    {meta['descripcion']}")
        print(f"    Filtro BPF: {meta['filtro_bpf'] or 'ninguno'}")


def combined_bpf(plugins):
    filters = sorted({p.bpf_filter for p in plugins if p.bpf_filter})
    if not filters:
        return "ip or ether proto 0x88cc"
    if len(filters) == 1:
        return filters[0]
    return "(" + ") or (".join(filters) + ")"


def count_packets(path):
    total = 0
    with PcapReader(str(path)) as reader:
        for _ in reader:
            total += 1
    return total


def dispatch(packet, plugins, context):
    context.statistics["packets_total"] += 1
    if packet.haslayer(IP):
        context.statistics["packets_ipv4"] += 1
    if packet.haslayer(TCP):
        context.statistics["packets_tcp"] += 1
    for plugin in plugins:
        try:
            plugin.process_packet(packet, context)
        except Exception as error:
            errors = context.statistics.setdefault("plugin_errors", {})
            errors[plugin.plugin_id] = errors.get(plugin.plugin_id, 0) + 1
            if not context.quiet:
                tqdm.write(f"Error en {plugin.plugin_id}: {error}")


def analyze_pcap(path, plugins, context):
    total = count_packets(path)
    print(f"Paquetes encontrados: {total}")
    with PcapReader(str(path)) as reader, tqdm(
        total=total, desc="Analizando PCAP", unit="paquete", dynamic_ncols=True
    ) as bar:
        for packet in reader:
            dispatch(packet, plugins, context)
            bar.update(1)


def capture_live(interface, duration, bpf_filter, plugins, context):
    started = time.monotonic()
    with tqdm(total=duration, desc="Captura en vivo", unit="s", dynamic_ncols=True) as bar:
        while RUNNING:
            remaining = duration - (time.monotonic() - started)
            if remaining <= 0:
                break
            sniff(
                iface=interface,
                filter=bpf_filter,
                prn=lambda packet: dispatch(packet, plugins, context),
                store=False,
                timeout=min(1.0, remaining),
            )
            elapsed = min(time.monotonic() - started, duration)
            bar.update(max(0, elapsed - bar.n))
            bar.set_postfix(packets=context.statistics["packets_total"])


def main():

    signal.signal(
        signal.SIGINT,
        stop_handler,
    )

    signal.signal(
        signal.SIGTERM,
        stop_handler,
    )

    registry = (
        ProtocolRegistry()
        .discover()
    )

    parser = build_parser()

    args = parser.parse_args()

    if args.list_protocols:

        list_protocols(
            registry
        )

        return 0

    network = validate_args(
        parser,
        args,
    )

    base_dir = (
        Path(__file__)
        .resolve()
        .parent
    )

    config = {

        "model_catalog":
            args.model_catalog
            or str(
                base_dir
                / "data"
                / "model_catalog.json"
            ),

        "profinet_vendor_catalog":
            args.profinet_vendor_catalog
            or str(
                base_dir
                / "data"
                / "profinet_vendor_catalog.json"
            ),

        "profinet_model_catalog":
            args.profinet_model_catalog
            or str(
                base_dir
                / "data"
                / "profinet_model_catalog.json"
            ),
    }

    try:

        plugins = registry.create(
            args.protocols,
            config=config,
        )

    except ValueError as error:

        parser.error(
            str(error)
        )

    #
    # Context
    #
    context = DiscoveryContext(
        network=network,
        quiet=args.quiet,
    )

    vulnerability_engine = VulnerabilityEngine(
        providers=[
            CisaIcsProvider(
                csv_file = str(base_dir / "data" /"cisa_ics"/"CISA_ICS_ADV_Master.csv")
            ),
            NvdProvider(),
        ],
        cache_db=str(
            base_dir
            / "vulnerability_cache.db"
        ),
    )

    alias_resolver = AliasResolver(
        str(
            base_dir
            / "data"
            / "product_aliases.json"
        )
    )

    correlator = AssetCorrelator()
    print(
        "Protocolos activos: "
        + ", ".join(
            p.plugin_id
            for p in plugins
        )
    )

    print(
        "Red: "
        + (
            str(network)
            if network
            else "AUTO_DETECTION"
        )
    )

    exit_code = 0

    try:

        if args.test:

            analyze_pcap(
                args.test,
                plugins,
                context,
            )

        else:

            bpf_filter = (
                combined_bpf(
                    plugins
                )
            )

            print(
                f"Filtro BPF: "
                f"{bpf_filter}"
            )

            capture_live(
                args.interfaz,
                args.tiempo,
                bpf_filter,
                plugins,
                context,
            )

    except (
        OSError,
        EOFError,
        PermissionError,
    ) as error:

        print(
            f"Error de captura: "
            f"{error}",
            file=sys.stderr,
        )

        exit_code = 1


    finally:

        #
        # 1. Finalizar todos los plugins
        #
        for plugin in plugins:

            try:
                plugin.finalize(
                    context
                )

            except Exception as error:

                context.protocol_results[
                    plugin.plugin_id
                ] = {
                    "error": str(error),
                    "finalize_failed": True,
                }

                exit_code = 1

        #
        # 2. Enriquecer los activos por protocolo
        #
        # En esta fase se crean fingerprints,
        # security findings y riesgo local.
        #
        # No se buscan CVEs todavía, porque el
        # mismo dispositivo puede aparecer en
        # LLDP, S7Comm y Modbus.
        #
        for (
            protocol_name,
            protocol_data,
        ) in context.protocol_results.items():

            inventory = get_inventory(
                protocol_data
            )

            if not inventory:
                continue

            for (
                asset_id,
                asset,
            ) in inventory.items():

                fingerprint = None

                try:

                    #
                    # Fingerprint por protocolo
                    #
                    fingerprint = (
                        FingerprintBuilder.build(
                            protocol_name,
                            asset,
                        )
                    )

                    if fingerprint:

                        alias = (
                            alias_resolver.resolve(
                                fingerprint
                            )
                        )

                        if alias:

                            fingerprint.metadata.update(
                                alias
                            )

                        asset[
                            "fingerprint"
                        ] = {
                            "ip":
                                fingerprint.ip,

                            "vendor":
                                fingerprint.vendor,

                            "model":
                                fingerprint.model,

                            "firmware":
                                fingerprint.firmware,

                            "order_numbers":
                                getattr(
                                    fingerprint,
                                    "order_numbers",
                                    [],
                                ),

                            "protocols":
                                fingerprint.protocols,

                            "confidence":
                                fingerprint.confidence,

                            "metadata":
                                fingerprint.metadata,
                        }

                    #
                    # Security findings por protocolo
                    #
                    findings = (
                        SecurityRules.evaluate(
                            protocol_name,
                            asset,
                        )
                    )

                    asset[
                        "security_findings"
                    ] = findings

                    #
                    # Riesgo local por protocolo
                    #
                    score, level = (
                        RiskEngine.calculate(
                            findings
                        )
                    )

                    asset[
                        "risk_score"
                    ] = score

                    asset[
                        "risk_level"
                    ] = level

                    #
                    # Las CVEs se calcularán sobre
                    # el activo correlacionado.
                    #
                    asset[
                        "vulnerability_findings"
                    ] = []

                except Exception as error:

                    asset.setdefault(
                        "security_findings",
                        [],
                    )

                    asset.setdefault(
                        "risk_score",
                        0,
                    )

                    asset.setdefault(
                        "risk_level",
                        "UNKNOWN",
                    )

                    asset.setdefault(
                        "vulnerability_findings",
                        [],
                    )

                    asset[
                        "security_processing_error"
                    ] = str(error)

                    if not args.quiet:

                        print(
                            f"[PROCESSING ERROR] "
                            f"{protocol_name}/"
                            f"{asset_id}: "
                            f"{error}"
                        )

        #
        # 3. Fusionar LLDP, S7Comm, Modbus,
        # PROFINET y DNP3
        #
        try:

            context.correlated_assets = (
                correlator.correlate(
                    context.protocol_results
                )
            )

        except Exception as error:

            context.correlated_assets = {}

            context.statistics[
                "correlation_error"
            ] = str(error)

            print(
                f"[CORRELATION ERROR] "
                f"{error}",
                file=sys.stderr,
            )

            exit_code = 1

        #
        # 4. Evaluar cada activo correlacionado
        #
        for (
            correlated_asset_id,
            correlated_asset,
        ) in context.correlated_assets.items():

            unified_fingerprint = None

            try:

                #
                # Fingerprint unificado
                #
                unified_fingerprint = (
                    FingerprintBuilder.build(
                        "correlated_asset",
                        correlated_asset,
                    )
                )

                if unified_fingerprint:

                    alias = (
                        alias_resolver.resolve(
                            unified_fingerprint
                        )
                    )

                    if alias:

                        unified_fingerprint.metadata.update(
                            alias
                        )

                    correlated_asset[
                        "fingerprint"
                    ] = {
                        "ip":
                            unified_fingerprint.ip,

                        "vendor":
                            unified_fingerprint.vendor,

                        "model":
                            unified_fingerprint.model,

                        "firmware":
                            unified_fingerprint.firmware,

                        "order_numbers":
                            getattr(
                                unified_fingerprint,
                                "order_numbers",
                                [],
                            ),

                        "protocols":
                            unified_fingerprint.protocols,

                        "confidence":
                            unified_fingerprint.confidence,

                        "metadata":
                            unified_fingerprint.metadata,
                    }

                #
                # Findings combinados
                #
                unified_findings = (
                    correlated_asset.get(
                        "security_findings",
                        [],
                    )
                    or []
                )

                correlated_asset[
                    "security_findings"
                ] = unified_findings

                #
                # Riesgo unificado
                #
                unified_score, unified_level = (
                    RiskEngine.calculate(
                        unified_findings
                    )
                )

                correlated_asset[
                    "risk_score"
                ] = unified_score

                correlated_asset[
                    "risk_level"
                ] = unified_level

                #
                # CVEs, una única búsqueda por
                # dispositivo físico correlacionado
                #
                if has_vulnerability_identity(
                    unified_fingerprint
                ):

                    provider_findings = (
                        vulnerability_engine.evaluate(
                            unified_fingerprint
                        )
                    )

                    correlated_asset[
                        "vulnerability_findings"
                    ] = provider_findings

                    correlated_asset[
                        "deduplicated_vulnerabilities"
                    ] = (
                        VulnerabilityDeduplicator
                        .deduplicate(
                            provider_findings
                        )
                    )

                else:

                    correlated_asset[
                        "vulnerability_findings"
                    ] = []

                    correlated_asset[
                        "deduplicated_vulnerabilities"
                    ] = []

            except Exception as error:

                correlated_asset.setdefault(
                    "security_findings",
                    [],
                )

                correlated_asset.setdefault(
                    "risk_score",
                    0,
                )

                correlated_asset.setdefault(
                    "risk_level",
                    "UNKNOWN",
                )

                correlated_asset.setdefault(
                    "vulnerability_findings",
                    [],
                )

                correlated_asset[
                    "assessment_error"
                ] = str(error)

                if not args.quiet:

                    print(
                        f"[CORRELATED ASSET ERROR] "
                        f"{correlated_asset_id}: "
                        f"{error}"
                    )

        #
        # 5. Generar salida JSON
        #
        metadata = [
            plugin.metadata()
            for plugin in plugins
        ]

        output = context.as_dict(
            metadata
        )

        #
        # Solo es necesario si context.as_dict()
        # todavía no incluye correlated_assets.
        #
        output[
            "correlated_asset_count"
        ] = len(
            context.correlated_assets
        )

        output[
            "correlated_assets"
        ] = context.correlated_assets

        output_path = Path(
            args.salida
        )

        output_path.write_text(
            json.dumps(
                output,
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

        #
        # 6. Resumen por terminal
        #
        print(
            SecuritySummary.build(
                context.protocol_results,
                context.correlated_assets,
            )
        )

        print(
            f"Resultado guardado en: "
            f"{output_path}"
        )

    return exit_code
        


if __name__ == "__main__":
    raise SystemExit(main())
