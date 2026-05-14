import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SERVER_DIR = ROOT / "server"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))

import asset_discovery


class AssetDiscoveryParserTests(unittest.TestCase):
    def test_get_platform_windows(self):
        with mock.patch("platform.system", return_value="Windows"):
            self.assertEqual(asset_discovery.get_platform(), "windows")

    def test_get_platform_linux(self):
        with mock.patch("platform.system", return_value="Linux"):
            self.assertEqual(asset_discovery.get_platform(), "linux")

    def test_parse_windows_arp(self):
        output = """
Interface: 192.168.1.2 --- 0x7
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
"""
        rows = asset_discovery.parse_windows_arp(output)
        self.assertEqual(rows[0]["ip"], "192.168.1.1")
        self.assertEqual(rows[0]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertTrue(rows[0]["arp_verified"])

    def test_parse_linux_ip_neigh(self):
        output = "192.168.1.10 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE\n"
        rows = asset_discovery.parse_linux_ip_neigh(output)
        self.assertEqual(rows[0]["ip"], "192.168.1.10")
        self.assertEqual(rows[0]["mac"], "00:11:22:33:44:55")
        self.assertEqual(rows[0]["discovery_tool"], "ip_neighbor")

    def test_parse_linux_arp(self):
        output = "Address HWtype HWaddress Flags Mask Iface\n192.168.1.20 ether 66:77:88:99:aa:bb C eth0\n"
        rows = asset_discovery.parse_linux_arp(output)
        self.assertEqual(rows[0]["ip"], "192.168.1.20")
        self.assertEqual(rows[0]["mac"], "66:77:88:99:aa:bb")

    def test_infer_candidate_networks_limits_large_subnet_to_local_24(self):
        context = {
            "local_interfaces": [
                {"interface": "eth0", "ipv4": "10.20.30.40", "cidr": "10.20.0.0/16"},
            ]
        }
        rows = asset_discovery.infer_candidate_networks(context)
        self.assertEqual(rows[0]["cidr"], "10.20.30.0/24")
        self.assertTrue(rows[0]["scan_allowed"])

    def test_infer_candidate_networks_skips_virtual_interfaces_by_default(self):
        context = {
            "local_interfaces": [
                {"interface": "VMware", "ipv4": "192.168.232.1", "cidr": "192.168.232.0/24", "is_virtual": True, "is_up": True},
                {"interface": "WLAN", "ipv4": "192.168.110.178", "cidr": "192.168.110.0/24", "is_virtual": False, "is_up": True},
            ]
        }
        rows = asset_discovery.infer_candidate_networks(context)
        self.assertEqual(rows[0]["cidr"], "192.168.110.0/24")
        vmware = [row for row in rows if row["source_interface"] == "VMware"][0]
        self.assertFalse(vmware["scan_allowed"])
        self.assertEqual(vmware["reason"], "virtual_interface_skipped_by_default")

    def test_infer_candidate_networks_includes_explicit_route_table_subnet(self):
        context = {
            "local_interfaces": [],
            "route_table": [
                {"cidr": "0.0.0.0/0", "gateway": "192.168.110.1", "interface_ip": "192.168.110.178", "is_default": True},
                {"cidr": "10.0.23.0/24", "gateway": "192.168.110.1", "interface_ip": "192.168.110.178", "is_default": False},
            ],
        }
        rows = asset_discovery.infer_candidate_networks(context)
        self.assertTrue(any(row["cidr"] == "10.0.23.0/24" and row["scan_allowed"] for row in rows))
        self.assertFalse(any(row["cidr"] == "0.0.0.0/0" for row in rows))

    def test_infer_candidate_networks_includes_configured_extra_network(self):
        context = {"local_interfaces": [], "extra_networks": [{"cidr": "10.0.23.0/24"}]}
        rows = asset_discovery.infer_candidate_networks(context)
        self.assertEqual(rows[0]["cidr"], "10.0.23.0/24")
        self.assertEqual(rows[0]["reason"], "configured_extra_network")

    def test_nmap_missing_does_not_crash(self):
        with mock.patch("asset_discovery.command_exists", return_value=False):
            result = asset_discovery.nmap_ping_scan("192.168.1.0/24", timeout=1)
        self.assertEqual(result["assets"], [])
        self.assertTrue(result["warnings"])

    def test_ping_sweep_fallback_shape(self):
        with mock.patch("asset_discovery._ping_one", return_value=None):
            result = asset_discovery.ping_sweep("127.0.0.0/30", "linux", timeout=1, concurrency=2)
        self.assertIn("assets", result)
        self.assertIn("warnings", result)

    def test_discover_merges_arp_when_nmap_reports_no_hosts(self):
        context = {
            "platform": "windows",
            "local_interfaces": [
                {"interface": "WLAN", "ipv4": "192.168.110.178", "cidr": "192.168.110.0/24", "is_virtual": False, "is_up": True},
            ],
            "warnings": [],
            "errors": [],
        }
        phone = {
            "ip": "192.168.110.139",
            "mac": "da:8c:06:f3:ca:e4",
            "is_alive": True,
            "discovery_tool": "arp",
            "arp_verified": True,
            "open_ports": [],
        }
        with mock.patch("asset_discovery.get_local_network_context", return_value=context), \
            mock.patch("asset_discovery.command_exists", return_value=True), \
            mock.patch("asset_discovery.nmap_ping_scan", return_value={"assets": [], "warnings": [], "errors": []}), \
            mock.patch("asset_discovery.ping_sweep", return_value={"assets": [], "warnings": [], "errors": []}), \
            mock.patch("asset_discovery.collect_neighbor_table", return_value={"assets": [phone], "warnings": [], "errors": []}), \
            mock.patch("asset_discovery.resolve_hostnames", return_value=[]):
            result = asset_discovery.discover_assets(targets=["192.168.110.139/32"], include_port_scan=False, timeout=2)
        self.assertTrue(any(row["ip"] == "192.168.110.139" for row in result["assets"]))

    def test_discover_uses_custom_ports_for_port_scan(self):
        context = {
            "platform": "windows",
            "local_interfaces": [],
            "warnings": [],
            "errors": [],
        }
        host = {"ip": "192.168.110.139", "is_alive": True, "discovery_tool": "ping_sweep", "open_ports": []}
        captured = {}

        def fake_port_scan(ips, ports, timeout):
            captured["ports"] = ports
            return {"assets": [], "warnings": [], "errors": []}

        with mock.patch("asset_discovery.get_local_network_context", return_value=context), \
            mock.patch("asset_discovery.command_exists", return_value=True), \
            mock.patch("asset_discovery.nmap_ping_scan", return_value={"assets": [host], "warnings": [], "errors": []}), \
            mock.patch("asset_discovery.ping_sweep", return_value={"assets": [], "warnings": [], "errors": []}), \
            mock.patch("asset_discovery.collect_neighbor_table", return_value={"assets": [], "warnings": [], "errors": []}), \
            mock.patch("asset_discovery.nmap_port_scan", side_effect=fake_port_scan), \
            mock.patch("asset_discovery.resolve_hostnames", return_value=[]):
            result = asset_discovery.discover_assets(targets=["192.168.110.139/32"], include_port_scan=True, ports=[443, 22, 22], timeout=2)
        self.assertEqual(captured["ports"], [22, 443])
        self.assertEqual(result["ports"], [22, 443])


class AssetDiscoveryApiTests(unittest.TestCase):
    def _client(self):
        try:
            from fastapi import FastAPI
            from fastapi.testclient import TestClient
        except ModuleNotFoundError as exc:
            self.skipTest(f"FastAPI test dependency is not installed: {exc}")

        import api

        app = FastAPI()
        app.include_router(api.router)
        app.include_router(api.assets_alias_router)
        return TestClient(app), api

    def test_assets_context_endpoint(self):
        client, api = self._client()
        payload = {
            "platform": "windows",
            "local_interfaces": [],
            "candidate_networks": [],
            "warnings": [],
            "errors": [],
        }
        with mock.patch.object(api, "get_asset_network_context", return_value=payload):
            response = client.get("/api/assets/context")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["platform"], "windows")

    def test_assets_discover_endpoint_returns_assets_array(self):
        client, api = self._client()
        payload = {"status": "ok", "assets": [], "count": 0, "warnings": ["timeout"], "errors": []}
        with mock.patch.object(api, "run_asset_discovery", return_value=payload):
            response = client.post("/api/assets/discover", json={"timeout": 1})
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json()["assets"], list)
        self.assertEqual(response.json()["warnings"], ["timeout"])


if __name__ == "__main__":
    unittest.main()
