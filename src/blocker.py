#!/usr/bin/env python3
import subprocess, logging, ipaddress
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
CHAIN_NAME = "AUTOSECOPS_BLOCK"

class IPBlocker:
    def __init__(self, whitelist: list[str]):
        self.whitelist = set(whitelist)
        self._ensure_chain_exists()

    def _run_iptables(self, args: list[str]) -> tuple[bool, str]:
        try:
            result = subprocess.run(["sudo", "iptables"] + args, capture_output=True, text=True, timeout=5)
            return result.returncode == 0, result.stderr or result.stdout
        except Exception as e:
            return False, str(e)

    def _ensure_chain_exists(self):
        self._run_iptables(["-N", CHAIN_NAME])
        success, output = self._run_iptables(["-L", "INPUT", "--line-numbers"])
        if success and CHAIN_NAME not in output:
            self._run_iptables(["-I", "INPUT", "1", "-j", CHAIN_NAME])
            logger.info(f"✅ Chain {CHAIN_NAME} added to INPUT")

    def is_whitelisted(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            for entry in self.whitelist:
                if '/' in entry:
                    if ip_obj in ipaddress.ip_network(entry, strict=False):
                        return True
                elif ip == entry:
                    return True
        except ValueError:
            pass
        return False

    def block_ip(self, ip: str) -> bool:
        if self.is_whitelisted(ip):
            logger.warning(f"⚠️ Cannot block whitelisted IP: {ip}")
            return False
        if self.is_blocked(ip):
            return True
        success, _ = self._run_iptables(["-A", CHAIN_NAME, "-s", ip, "-j", "DROP"])
        if success:
            logger.info(f"🚫 BLOCKED: {ip}")
        return success

    def is_blocked(self, ip: str) -> bool:
        success, output = self._run_iptables(["-L", CHAIN_NAME, "-n"])
        return success and ip in output

    def list_blocked(self) -> list[str]:
        success, output = self._run_iptables(["-L", CHAIN_NAME, "-n"])
        if not success: return []
        ips = []
        for line in output.split('\n'):
            if 'DROP' in line and '0.0.0.0/0' not in line:
                for part in line.split():
                    if '.' in part and ':' not in part:
                        ips.append(part.split('/')[0])
        return ips
