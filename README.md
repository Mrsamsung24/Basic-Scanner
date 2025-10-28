# Basic-Scanner
Performance: scanning 1-65535 is slow. Use --ports 1-1024 or smaller ranges for quick checks. Increase --threads if your network and target can handle it.

Requests: installing requests (pip install requests) improves HTTPS header fetching. If not present, script falls back to raw sockets.

Expand outdated checks: the OUTDATED_PATTERNS list is a starting point. You can add strings like tomcat/7., iis/6., etc., but keep it conservative to avoid false positives.

Nmap integration: for deeper detection, run nmap -sV -oX output.xml and parse XML (I can show code for that).

Reporting: CSV can be converted to HTML, Excel, or PDF for sharing.
