---
tags: [config, mihomo, singbox, proxy-groups, dns, cache]
---

# Task 27 locked constraints for proxy_converter.py

- Final MATCH route stays PROXY (not DIRECT).
- Checker URL template: https://checker.surfshield.org/{CC}, HTTP 200 = pass.
- Probe all nodes per country; failed nodes stay in global Auto/PROXY.
- Dashboard UI: Zashboard (external-ui-url zip).
- Cache size: 4096 for both mihomo (cache-size) and sing-box (cache_capacity).
- Keep Load Balance group (interval 60, consistent-hashing).
- Sing-box NTP enabled (time.apple.com).
- Default subscription URL: https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt.
- Country groups: US GB DE NL FR IT JP CA BR; skip empty groups.
- Minimal DNS: mihomo arc cache 4096 + fake-ip; sing-box fakeip + single dns-direct UDP.
- No geo artifacts (geox-url, geo-auto-update removed); no custom DNS resolvers.
