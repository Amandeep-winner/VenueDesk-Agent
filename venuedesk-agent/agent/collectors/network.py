"""Network adapter and MAC address collectors with graceful degradation."""

import logging
import socket

from agent.identity.fingerprint import is_virtual_or_tether_nic

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None


def collect_nics() -> list[str]:
    """Collect physical network adapter identifiers (e.g. MAC addresses) excluding virtual adapters."""
    nics: list[str] = []
    if not psutil:
        return nics

    try:
        addrs = psutil.net_if_addrs()
        for iface_name, snic_list in addrs.items():
            if is_virtual_or_tether_nic(iface_name):
                continue
            for snic in snic_list:
                # AF_LINK on Windows/BSD/macOS, AF_PACKET on Linux
                is_link = False
                if (
                    hasattr(psutil, "AF_LINK")
                    and snic.family == psutil.AF_LINK
                    or hasattr(socket, "AF_PACKET")
                    and snic.family == socket.AF_PACKET
                ):
                    is_link = True

                if is_link and snic.address:
                    addr = snic.address.strip().lower()
                    # Check for non-empty and non-loopback/all-zero
                    if addr and addr != "00:00:00:00:00:00":
                        nics.append(f"{iface_name}:{addr}")
    except (OSError, AttributeError) as exc:
        logger.debug("Failed collecting NIC addresses via psutil: %s", exc)

    return sorted(set(nics))
