from scanner import _parse_nmap_xml


def test_parse_nmap_xml_basic():
    xml = """<?xml version='1.0'?>
<nmaprun>
  <host>
    <status state='up'/>
    <address addr='192.168.1.10' addrtype='ipv4'/>
    <address addr='aa:bb:cc:dd:ee:ff' addrtype='mac'/>
    <hostnames><hostname name='pc.local'/></hostnames>
  </host>
</nmaprun>
"""
    devices = _parse_nmap_xml(xml)
    assert len(devices) == 1
    assert devices[0]["ip"] == "192.168.1.10"
    assert devices[0]["mac"] == "AA:BB:CC:DD:EE:FF"
    assert devices[0]["hostname"] == "pc.local"


def test_parse_nmap_xml_missing_fields():
    xml = """<?xml version='1.0'?>
<nmaprun>
  <host>
    <status state='up'/>
    <address addr='192.168.1.20' addrtype='ipv4'/>
  </host>
</nmaprun>
"""
    devices = _parse_nmap_xml(xml)
    assert len(devices) == 1
    assert devices[0]["mac"] == "Inconnue"
    assert devices[0]["hostname"] == "Inconnu"
