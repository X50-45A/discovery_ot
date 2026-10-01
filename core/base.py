from abc import ABC, abstractmethod


class ProtocolPlugin(ABC):
    plugin_id = ""
    display_name = ""
    description = ""
    version = "1.0"
    bpf_filter = ""

    def __init__(self, config=None):
        self.config = config or {}

    @abstractmethod
    def process_packet(self, packet, context):
        pass

    def finalize(self, context):
        return None

    @classmethod
    def metadata(cls):
        return {
            "id": cls.plugin_id,
            "nombre": cls.display_name,
            "descripcion": cls.description,
            "version": cls.version,
            "filtro_bpf": cls.bpf_filter,
        }
