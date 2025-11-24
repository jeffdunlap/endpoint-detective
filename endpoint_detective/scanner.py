from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, List, Set

from .models import EndpointReportRow, EndpointType


@dataclass(frozen=True)
class ProtocolProbe:
    name: str
    port: int
    hint: str

    def check(self, ip_address: str, timeout: float) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect((ip_address, self.port))
            except (TimeoutError, OSError):
                return False
            return True


class EndpointScanner:
    def __init__(
        self,
        timeout: float = 0.5,
        max_workers: int = 32,
        probes: Iterable[ProtocolProbe] | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_workers = max_workers
        self.probes = list(probes) if probes is not None else self._default_probes()

    def scan_file(self, path: str) -> List[EndpointReportRow]:
        with open(path, "r", encoding="utf-8") as handle:
            ips = [line.strip() for line in handle.readlines() if line.strip()]
        return self.scan_many(ips)

    def scan_many(self, ips: Iterable[str]) -> List[EndpointReportRow]:
        results: List[EndpointReportRow] = []
        ips_list = list(ips)
        with ThreadPoolExecutor(max_workers=min(self.max_workers, max(len(ips_list), 1))) as executor:
            futures = [executor.submit(self.scan_single, ip) for ip in ips_list]
            for future in futures:
                results.append(future.result())
        return results

    def scan_single(self, ip_address: str) -> EndpointReportRow:
        protocols = self._detect_protocols(ip_address)
        hostname = self._resolve_hostname(ip_address)
        endpoint_type = self._classify_endpoint(protocols)
        return EndpointReportRow(
            ip_address=ip_address,
            hostname=hostname or "(unresolved)",
            protocols=sorted(protocols),
            endpoint_type=endpoint_type,
        )

    def _detect_protocols(self, ip_address: str) -> Set[str]:
        found: Set[str] = set()
        for probe in self.probes:
            if probe.check(ip_address, self.timeout):
                found.add(probe.name)
        return found

    def _resolve_hostname(self, ip_address: str) -> str:
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except (socket.herror, TimeoutError, socket.timeout, OSError):
            return ""

    def _classify_endpoint(self, protocols: Set[str]) -> EndpointType:
        classifiers: List[Callable[[Set[str]], EndpointType | None]] = [
            self._classify_printer,
            self._classify_windows,
            self._classify_camera,
            self._classify_linux,
            self._classify_network_appliance,
            self._classify_web,
        ]
        for classifier in classifiers:
            endpoint = classifier(protocols)
            if endpoint:
                return endpoint
        return EndpointType.UNKNOWN

    @staticmethod
    def _classify_printer(protocols: Set[str]) -> EndpointType | None:
        printer_protocols = {"IPP", "LPD", "RAW_PRINTING"}
        if protocols.intersection(printer_protocols):
            return EndpointType.PRINTER
        return None

    @staticmethod
    def _classify_windows(protocols: Set[str]) -> EndpointType | None:
        windows_protocols = {"SMB", "RDP"}
        if protocols.intersection(windows_protocols):
            return EndpointType.WINDOWS_SERVER
        return None

    @staticmethod
    def _classify_camera(protocols: Set[str]) -> EndpointType | None:
        camera_protocols = {"RTSP", "ONVIF"}
        if protocols.intersection(camera_protocols):
            return EndpointType.VIDEO_CAMERA
        return None

    @staticmethod
    def _classify_linux(protocols: Set[str]) -> EndpointType | None:
        linux_protocols = {"SSH"}
        if linux_protocols.intersection(protocols) and "RDP" not in protocols:
            return EndpointType.LINUX_SERVER
        return None

    @staticmethod
    def _classify_network_appliance(protocols: Set[str]) -> EndpointType | None:
        if "SNMP" in protocols:
            return EndpointType.NETWORK_APPLIANCE
        return None

    @staticmethod
    def _classify_web(protocols: Set[str]) -> EndpointType | None:
        web_protocols = {"HTTP", "HTTPS"}
        if protocols.intersection(web_protocols):
            return EndpointType.WEB_SERVER
        return None

    @staticmethod
    def _default_probes() -> List[ProtocolProbe]:
        return [
            ProtocolProbe(name="SSH", port=22, hint="Remote shell / Linux"),
            ProtocolProbe(name="RDP", port=3389, hint="Remote Desktop / Windows"),
            ProtocolProbe(name="SMB", port=445, hint="File sharing / Windows"),
            ProtocolProbe(name="HTTP", port=80, hint="Web server"),
            ProtocolProbe(name="HTTPS", port=443, hint="Secure web server"),
            ProtocolProbe(name="FTP", port=21, hint="File transfer"),
            ProtocolProbe(name="SMTP", port=25, hint="Mail server"),
            ProtocolProbe(name="IMAP", port=143, hint="Mail access"),
            ProtocolProbe(name="POP3", port=110, hint="Mail access"),
            ProtocolProbe(name="TELNET", port=23, hint="Legacy remote shell"),
            ProtocolProbe(name="SNMP", port=161, hint="Network management"),
            ProtocolProbe(name="IPP", port=631, hint="Printing"),
            ProtocolProbe(name="LPD", port=515, hint="Printing"),
            ProtocolProbe(name="RAW_PRINTING", port=9100, hint="Direct printing"),
            ProtocolProbe(name="RTSP", port=554, hint="Streaming video"),
            ProtocolProbe(name="ONVIF", port=8000, hint="Camera / DVR"),
            ProtocolProbe(name="SIP", port=5060, hint="Voice over IP"),
        ]

