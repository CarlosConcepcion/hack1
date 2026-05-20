from __future__ import annotations
import threading
import logging
from typing import Optional, Callable

from scapy.all import AsyncSniffer, conf

from netaudit.config import NetAuditConfig
from netaudit.models import CaptureResults

logger = logging.getLogger("netaudit.sniffer")


class Sniffer:
    def __init__(self, config: NetAuditConfig, results: CaptureResults):
        self.config = config
        self.results = results
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._callback: Optional[Callable] = None
        self._packets_since_last = 0

    def set_callback(self, callback: Callable):
        self._callback = callback

    def start(self, interface: Optional[str] = None, pcap_file: Optional[str] = None):
        self._running = True
        iface = interface or self.config.interface
        pcap = pcap_file or self.config.pcap_file

        kwargs = {
            "prn": self._packet_callback,
            "store": False,
        }

        if iface:
            kwargs["iface"] = iface
        if pcap:
            kwargs["offline"] = pcap
        if self.config.bpf_filter:
            kwargs["filter"] = self.config.bpf_filter

        if not pcap:
            kwargs["count"] = 0

        logger.info(f"Starting sniffer on {iface or 'default interface'} (pcap: {pcap or 'live'})")

        if pcap and self.config.bpf_filter and not conf.use_pcap:
            logger.warning("BPF filter not supported for PCAP reading without Npcap/libpcap. Ignoring filter.")
            self.config.bpf_filter = None
            kwargs.pop("filter", None)

        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.start()

        if pcap:
            try:
                self._sniffer.join()
            except Exception as e:
                logger.warning(f"Sniffer error: {e}")

    def stop(self):
        self._running = False
        if self._sniffer:
            try:
                if hasattr(self._sniffer, 'running') and self._sniffer.running:
                    logger.info("Stopping sniffer...")
                    self._sniffer.stop()
                    self._sniffer.join(timeout=5)
            except Exception as e:
                logger.debug(f"Sniffer stop: {e}")

    def _packet_callback(self, pkt):
        if not self._running:
            raise StopIteration
        self._packets_since_last += 1
        if self._callback:
            try:
                self._callback(pkt)
            except Exception as e:
                logger.debug(f"Callback error: {e}")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def packets_since_last(self) -> int:
        val = self._packets_since_last
        self._packets_since_last = 0
        return val

    @staticmethod
    def list_interfaces() -> list[dict]:
        interfaces = []
        for iface_name, iface_data in conf.ifaces.items():
            try:
                interfaces.append({
                    "name": iface_name,
                    "description": getattr(iface_data, "description", ""),
                    "ip": getattr(iface_data, "ip", ""),
                    "mac": getattr(iface_data, "mac", ""),
                })
            except Exception:
                pass
        return interfaces
