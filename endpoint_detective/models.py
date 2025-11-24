from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import List


class EndpointType(Enum):
    PRINTER = auto()
    WINDOWS_SERVER = auto()
    LINUX_SERVER = auto()
    NETWORK_APPLIANCE = auto()
    VIDEO_CAMERA = auto()
    WEB_SERVER = auto()
    UNKNOWN = auto()

    @classmethod
    def label(cls, endpoint_type: "EndpointType") -> str:
        labels = {
            cls.PRINTER: "Printer",
            cls.WINDOWS_SERVER: "Windows Server",
            cls.LINUX_SERVER: "Linux/Unix Server",
            cls.NETWORK_APPLIANCE: "Network Appliance",
            cls.VIDEO_CAMERA: "Video Camera",
            cls.WEB_SERVER: "Web Server",
            cls.UNKNOWN: "Unknown",
        }
        return labels.get(endpoint_type, "Unknown")


@dataclass
class EndpointReportRow:
    ip_address: str
    hostname: str
    protocols: List[str]
    endpoint_type: EndpointType

    def protocol_list(self) -> str:
        return ", ".join(self.protocols)

    def endpoint_label(self) -> str:
        return EndpointType.label(self.endpoint_type)
