import json
from pathlib import Path


MODBUS_OBJECT_NAMES = {
    0x00: "vendor_name",
    0x01: "product_code",
    0x02: "revision",
    0x03: "vendor_url",
    0x04: "product_name",
    0x05: "model_name",
    0x06: "user_application_name",
}


class ModelResolver:
    def __init__(
        self,
        modbus_catalog_path=None,
        profinet_vendor_catalog_path=None,
        profinet_model_catalog_path=None,
    ):
        self.modbus_catalog = self._load_catalog(modbus_catalog_path)
        self.profinet_vendor_catalog = self._load_catalog(
            profinet_vendor_catalog_path
        )
        self.profinet_model_catalog = self._load_catalog(
            profinet_model_catalog_path
        )

    @staticmethod
    def _load_catalog(path_value):
        if not path_value:
            return {}
        path = Path(path_value)
        if not path.is_file():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    @staticmethod
    def clean(value):
        if value is None:
            return None
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        return str(value).strip(" \t\r\n\x00") or None

    @staticmethod
    def normalize_hex_id(value):
        if value is None:
            return None
        if isinstance(value, str):
            try:
                value = int(value, 0)
            except ValueError:
                return None
        try:
            return f"0x{int(value):04X}"
        except (TypeError, ValueError):
            return None

    def resolve_modbus(self, objects, server_id=None):
        objects = objects or {}
        named = {}
        for object_id, value in objects.items():
            name = MODBUS_OBJECT_NAMES.get(
                object_id, f"object_{object_id:02x}"
            )
            clean_value = self.clean(value)
            if clean_value is not None:
                named[name] = clean_value

        vendor = named.get("vendor_name")
        product_code = named.get("product_code")
        product_name = named.get("product_name")
        explicit_model = named.get("model_name")
        clean_server_id = self.clean(server_id)

        if objects:
            source = "modbus_fc43_mei14"
        elif clean_server_id:
            source = "modbus_fc17"
        else:
            source = "modbus_traffic_fingerprint"

        result = {
            "protocol": "modbus_tcp",
            "status": "MODBUS_CONFIRMED",
            "vendor": vendor,
            "product_code": product_code,
            "revision": named.get("revision"),
            "vendor_url": named.get("vendor_url"),
            "product_name": product_name,
            "product_family": None,
            "model": explicit_model,
            "application": named.get("user_application_name"),
            "server_id": clean_server_id,
            "source": source,
            "catalog_match": False,
            "confidence": {
                "protocol": 100,
                "vendor": 100 if vendor else 0,
                "product_family": 0,
                "exact_model": 0,
            },
            "raw_objects": {
                f"0x{object_id:02X}": self.clean(value)
                for object_id, value in sorted(objects.items())
            },
        }

        if explicit_model:
            result["status"] = "IDENTIFIED_EXACT"
            result["confidence"]["product_family"] = 90
            result["confidence"]["exact_model"] = 100
            return result

        match = self._match_modbus_catalog(vendor, product_code)
        if match:
            result["model"] = match.get("model")
            result["product_family"] = match.get("family")
            result["product_name"] = product_name or match.get("product_name")
            result["status"] = "IDENTIFIED_PRODUCT_CODE"
            result["catalog_match"] = True
            result["confidence"]["product_family"] = 95
            if result["model"]:
                result["confidence"]["exact_model"] = 95
        elif product_code:
            result["status"] = "IDENTIFIED_PRODUCT_CODE"
            result["model"] = product_code
            result["confidence"]["product_family"] = 75
            result["confidence"]["exact_model"] = 70
        elif product_name:
            result["status"] = "IDENTIFIED_FAMILY"
            result["product_family"] = product_name
            result["confidence"]["product_family"] = 65
        elif vendor:
            result["status"] = "VENDOR_ONLY"
        elif clean_server_id:
            result["status"] = "SERVER_ID_ONLY"
            result["confidence"]["exact_model"] = 20

        return result

    # Compatibility shim for any older Modbus plugin still calling resolve().
    def resolve(self, objects, server_id=None):
        return self.resolve_modbus(objects=objects, server_id=server_id)

    def _match_modbus_catalog(self, vendor, product_code):
        if not vendor or not product_code:
            return None
        products = self.modbus_catalog.get("products", [])
        vendor_norm = vendor.casefold()
        code_norm = product_code.casefold()
        for product in products:
            if str(product.get("vendor", "")).casefold() != vendor_norm:
                continue
            codes = [
                str(code).casefold()
                for code in product.get("product_codes", [])
            ]
            if code_norm in codes:
                return product
        return None

    def resolve_profinet(
        self,
        vendor_id,
        device_id,
        device_type=None,
        station_name=None,
        alias_name=None,
    ):
        vendor_hex = self.normalize_hex_id(vendor_id)
        device_hex = self.normalize_hex_id(device_id)
        clean_type = self.clean(device_type)

        result = {
            "protocol": "profinet_dcp",
            "status": "PROFINET_CONFIRMED",
            "vendor_id": vendor_hex,
            "device_id": device_hex,
            "vendor": None,
            "product_family": clean_type,
            "model": None,
            "device_type": clean_type,
            "station_name": self.clean(station_name),
            "alias_name": self.clean(alias_name),
            "source": "profinet_dcp",
            "catalog_match": False,
            "confidence": {
                "protocol": 100,
                "vendor": 90 if vendor_id is not None else 0,
                "product_family": 70 if clean_type else 0,
                "exact_model": 0,
            },
        }

        vendor_match = self._match_profinet_vendor(vendor_id)
        if vendor_match:
            result["vendor"] = vendor_match
            result["confidence"]["vendor"] = 100

        model_match = self._match_profinet_model(vendor_id, device_id)
        if model_match:
            result["vendor"] = result["vendor"] or model_match.get("vendor")
            result["product_family"] = (
                model_match.get("family") or result["product_family"]
            )
            result["model"] = model_match.get("model")
            result["catalog_match"] = True
            if result["product_family"]:
                result["confidence"]["product_family"] = 95
            if result["model"]:
                result["status"] = "IDENTIFIED_EXACT"
                result["confidence"]["exact_model"] = 95
            else:
                result["status"] = "IDENTIFIED_PRODUCT_CODE"
        elif vendor_id is not None and device_id is not None:
            result["status"] = "IDENTIFIED_PRODUCT_CODE"
            result["confidence"]["product_family"] = max(
                result["confidence"]["product_family"], 85
            )
        elif result["vendor"]:
            result["status"] = "VENDOR_ONLY"
        elif clean_type:
            result["status"] = "IDENTIFIED_FAMILY"

        return result

    def _match_profinet_vendor(self, vendor_id):
        if vendor_id is None:
            return None
        vendor_hex = self.normalize_hex_id(vendor_id)
        keys = [vendor_hex, vendor_hex.lower(), str(int(vendor_id))]
        for key in keys:
            item = self.profinet_vendor_catalog.get(key)
            if isinstance(item, str):
                return item
            if isinstance(item, dict):
                return item.get("vendor")
        return None

    def _match_profinet_model(self, vendor_id, device_id):
        if vendor_id is None or device_id is None:
            return None
        vendor_hex = self.normalize_hex_id(vendor_id)
        device_hex = self.normalize_hex_id(device_id)
        keys = [
            f"{vendor_hex}:{device_hex}",
            f"{vendor_hex.lower()}:{device_hex.lower()}",
            f"{int(vendor_id)}:{int(device_id)}",
        ]
        for key in keys:
            item = self.profinet_model_catalog.get(key)
            if isinstance(item, dict):
                return item
        return None
