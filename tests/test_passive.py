import struct
import unittest
from pathlib import Path

from passive import (
    PassiveDiscoveryError,
    parse_dns_message,
    parse_nbns_node_status,
    read_arp_a,
    read_proc_net_arp,
)


class PassiveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.arp_file = Path(__file__).resolve().parent / "workspace" / "proc-net-arp.txt"
        self.arp_file.write_text(
            "IP address HW type Flags HW address Mask Device\n192.168.1.10 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        if self.arp_file.exists():
            self.arp_file.unlink()

    def test_read_cache_formats(self) -> None:
        proc_hosts = read_proc_net_arp(str(self.arp_file))
        arp_hosts = read_arp_a(
            lambda *args, **kwargs: type("Completed", (), {"returncode": 0, "stdout": "  192.168.1.20           aa-bb-cc-dd-ee-11     dynamic\n", "stderr": ""})()
        )
        self.assertEqual(proc_hosts[0].address, "192.168.1.10")
        self.assertEqual(arp_hosts[0].mac, "AA:BB:CC:DD:EE:11")

    def test_parse_dns_and_nbns_packets(self) -> None:
        dns_packet = (
            struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 0, 0)
            + b"\x04test\x05local\x00"
            + struct.pack("!HH", 1, 1)
            + b"\xC0\x0C"
            + struct.pack("!HHIH", 1, 1, 60, 4)
            + bytes([192, 168, 1, 50])
        )
        parsed_dns = parse_dns_message(dns_packet)
        self.assertEqual(parsed_dns["answers"][0]["data"], "192.168.1.50")

        encoded_name = b"\x20" + (b"CK" * 16) + b"\x00"
        rdata = bytes([1]) + b"WORKSTATION    " + b"\x00\x00\x00" + b"\xaa\xbb\xcc\xdd\xee\xff"
        nbns_packet = (
            struct.pack("!HHHHHH", 1, 0x8500, 1, 1, 0, 0)
            + encoded_name
            + struct.pack("!HH", 0x0021, 0x0001)
            + encoded_name
            + struct.pack("!HHIH", 0x0021, 0x0001, 60, len(rdata))
            + rdata
        )
        parsed_nbns = parse_nbns_node_status(nbns_packet)
        self.assertEqual(parsed_nbns["mac"], "AA:BB:CC:DD:EE:FF")

    def test_rejects_truncated_dns_packet(self) -> None:
        with self.assertRaises(PassiveDiscoveryError):
            parse_dns_message(struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + b"\x03ab")


if __name__ == "__main__":
    unittest.main()
