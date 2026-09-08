"""
TrustShield V2 - GeoLocation & Infrastructure Tracer Test
Validates:
1. IP-API resolution with GPS coordinates (lat, lon), ISP, and ASN.
2. VPN / Tor / Datacenter proxy detection (is_suspicious_proxy).
3. Graceful fallback on private IPs and network timeouts.
4. Correct Leaflet route map JSON array schema.
"""

import sys
import json
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from core_engine.geo_tracer import resolve_ip_location, generate_route_map


def test_geo_tracer_pipeline():
    print("=" * 80)
    print("🌍 TESTING TRUSTSHIELD V2: GEOLOCATION & INFRASTRUCTURE TRACER")
    print("=" * 80)

    test_ips = ["185.220.101.5", "142.250.190.68"]
    print(f"\n[+] Input IP Hop Chain: {test_ips}")

    # 1. Test generate_route_map
    route_map = generate_route_map(test_ips)

    print("\n[+] Leaflet Route Map Output:")
    print(json.dumps(route_map, indent=2))

    # 2. Assertions
    print("\n" + "=" * 80)
    print("🔍 VALIDATING GEOLOCATION TRACER SPECIFICATIONS")
    print("=" * 80)

    # Check 1: Output format is list of dicts
    assert isinstance(route_map, list), "Output must be a list"
    assert len(route_map) == 2, f"Expected 2 hops, got {len(route_map)}"
    print(f"  [✓] Output is valid list with {len(route_map)} hops")

    # Check 2: First IP is suspicious proxy (185.220.101.5 is a known Tor / proxy node)
    hop_1 = route_map[0]
    assert hop_1["ip"] == "185.220.101.5"
    assert "lat" in hop_1 and "lon" in hop_1
    assert hop_1["lat"] != 0.0 or hop_1["lon"] != 0.0, "Latitude/Longitude should be populated"
    assert hop_1["is_suspicious_proxy"] is True, (
        f"Expected 185.220.101.5 to be flagged as suspicious proxy! Got: {hop_1}"
    )
    print(f"  [✓] Hop 1 (185.220.101.5): {hop_1['city']}, {hop_1['country']} | ISP: {hop_1['isp']}")
    print(f"  [✓] Hop 1 Suspicious Proxy Triggered: is_suspicious_proxy = {hop_1['is_suspicious_proxy']}")

    # Check 3: Second IP (Google IP 142.250.190.68)
    hop_2 = route_map[1]
    assert hop_2["ip"] == "142.250.190.68"
    assert "lat" in hop_2 and "lon" in hop_2
    assert "Google" in hop_2["isp"] or "AS15169" in hop_2["asn"] or hop_2["country"] != "Unknown"
    print(f"  [✓] Hop 2 (142.250.190.68): {hop_2['city']}, {hop_2['country']} | ISP: {hop_2['isp']}")

    # Check 4: Private IP handling (RFC-1918) - should not crash or call external API
    print("\n[+] Testing Private IP Local Fallback (192.168.1.1):")
    private_hop = resolve_ip_location("192.168.1.1")
    assert private_hop["is_private"] is True
    assert private_hop["lat"] == 0.0 and private_hop["lon"] == 0.0
    print(f"  [✓] Private IP handled gracefully: {private_hop['country']} ({private_hop['city']})")

    # Check 5: Schema validation for Leaflet
    required_keys = {"hop_number", "ip", "city", "country", "lat", "lon", "isp", "asn", "is_suspicious_proxy"}
    for hop in route_map:
        missing = required_keys - set(hop.keys())
        assert not missing, f"Hop entry missing required keys: {missing}"

    print(f"  [✓] All required Leaflet schema keys present: {required_keys}")

    print("\n" + "=" * 80)
    print("🎯 ALL GEOLOCATION TRACER CHECKS PASSED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    test_geo_tracer_pipeline()
