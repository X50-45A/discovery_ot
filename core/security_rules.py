class SecurityRules:

    @staticmethod
    def evaluate(protocol, asset):
        handlers = {
            "modbus_tcp": SecurityRules.modbus,
            "s7comm": SecurityRules.s7,
            "dnp3": SecurityRules.dnp3,
            "mqtts": SecurityRules.mqtts,
            "profinet_dcp": SecurityRules.profinet,
        }

        handler = handlers.get(protocol)
        return handler(asset) if handler else []

    @staticmethod
    def modbus(asset):
        findings = [
            {"severity":"HIGH","title":"Modbus/TCP without authentication"},
            {"severity":"HIGH","title":"Modbus/TCP without encryption"},
        ]

        function_codes = set(asset.get("function_codes", []))

        if any(fc in function_codes for fc in (5,6,15,16)):
            findings.append({
                "severity":"HIGH",
                "title":"Write operations observed"
            })

        return findings

    @staticmethod
    def s7(asset):
        findings = [
            {
                "severity":"MEDIUM",
                "title":"Unauthenticated PLC protocol"
            }
        ]

        functions = asset.get("functions", {})

        dangerous = {
            "write_var",
            "request_download",
            "download_block",
            "plc_stop",
        }

        if any(f in functions for f in dangerous):
            findings.append({
                "severity":"HIGH",
                "title":"PLC modification activity observed"
            })

        return findings

    @staticmethod
    def dnp3(asset):
        findings = []

        functions = asset.get("application_functions", {})

        dangerous = {
            "write",
            "operate",
            "direct_operate",
            "direct_operate_no_ack",
        }

        if any(f in functions for f in dangerous):
            findings.append({
                "severity":"HIGH",
                "title":"DNP3 control operations observed"
            })

        return findings

    @staticmethod
    def mqtts(asset):
        findings = []

        versions = asset.get("tls_record_versions", [])

        if "0x0301" in versions:
            findings.append({
                "severity":"MEDIUM",
                "title":"TLS 1.0 observed"
            })

        return findings

    @staticmethod
    def profinet(asset):
        return [{
            "severity":"LOW",
            "title":"PROFINET discovery information exposed"
        }]
