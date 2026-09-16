import unittest
from unittest import mock

from external import parse_nmap_xml
from nuclei import parse_nuclei_jsonl
from subdomains import enumerate_subdomains
from vuln import parse_vulnerability_xml


class ParsingTests(unittest.TestCase):
    def test_parse_nmap_and_vuln_xml(self) -> None:
        xml = """
        <nmaprun version='7.95'>
          <host>
            <status state='up'/>
            <address addr='203.0.113.10' addrtype='ipv4'/>
            <hostnames><hostname name='example.test'/></hostnames>
            <ports>
              <port protocol='tcp' portid='443'>
                <state state='open'/>
                <service name='https' product='Apache' version='2.4.49' extrainfo='TLS'/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
        parsed = parse_nmap_xml(xml, "203.0.113.10")
        self.assertEqual(parsed["hosts"][0]["ports"][0]["service"], "https")

        vuln_xml = """
        <nmaprun>
          <host>
            <status state='up'/>
            <ports>
              <port protocol='tcp' portid='443'>
                <state state='open'/>
                <service name='https' product='Apache' version='2.4.49'/>
                <script id='http-vuln-test' output='State: VULNERABLE\nCVE-2024-0001'/>
              </port>
            </ports>
          </host>
        </nmaprun>
        """
        parsed_vuln = parse_vulnerability_xml(vuln_xml, "203.0.113.10")
        self.assertEqual(parsed_vuln["findings"][0]["cves"], ["CVE-2024-0001"])

    def test_parse_jsonl_integrations(self) -> None:
        rows = parse_nuclei_jsonl('{"template-id":"x","info":{"name":"test","severity":"medium"}}\n')
        self.assertEqual(rows[0]["template-id"], "x")

        runner = mock.Mock(return_value=type("Completed", (), {
            "returncode": 0,
            "stdout": '{"host":"a.example.com"}\n{"host":"b.example.com"}\n',
            "stderr": "",
        })())
        with mock.patch("subdomains.which", return_value="subfinder"):
            result = enumerate_subdomains("example.com", timeout=1.0, runner=runner)
        self.assertEqual(result, ["a.example.com", "b.example.com"])


if __name__ == "__main__":
    unittest.main()
