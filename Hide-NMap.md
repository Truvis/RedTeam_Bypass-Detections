Modyfy the following file to remove SNORT/Suricata detections
=> https://raw.githubusercontent.com/nmap/nmap/master/osscan2.cc

## User-Agent
### ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine
User-Agent will be seen in the packet so lets remove the default

SET => 
USER_AGENT = stdnse.get_script_args('http.useragent') or "Mozilla/3.0 (compatible; )"

## TCP Windows
### ET SCAN NMAP -sS window 1024

SET =>
tcp->th_win = htons(9999); /* Who cares */

##  ZMap
### Detect ZMAP scan

SET=>
tcp_header->th_win = htons(65535);
iph->ip_id = htons(54321);
