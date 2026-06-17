import nmap
import datetime

def scan_target(target):
    scanner = nmap.PortScanner()

    print("\n" + "="*50)
    print("Vulnerability Scanner")
    print("Target :", target)
    print("Time   :", datetime.datetime.now())
    print("="*50)

    print("\n[*] Scanning open ports and services...")
    scanner.scan(target, "1-1024", "-sV")

    hosts = scanner.all_hosts()

    if not hosts:
        print("No hosts found.")
        return

    host = hosts[0]
    open_ports = []
    
    if 'tcp' not in scanner[host]:
        print("No open TCP ports found.")
        return

    for port in scanner[host]['tcp']:
        state = scanner[host]['tcp'][port]['state']
        service = scanner[host]['tcp'][port]['name']

        if state == "open":
            open_ports.append(port)
            print(f"[OPEN] Port {port} | Service: {service}")

    print("\n[*] Vulnerability Report:")

    if 21 in open_ports:
        print("⚠️ FTP port open")
    if 22 in open_ports:
        print("⚠️ SSH port open")
    if 23 in open_ports:
        print("🚨 Telnet port open")
    if 80 in open_ports:
        print("⚠️ HTTP port open")
    if 443 in open_ports:
        print("✅ HTTPS port open")

    report_name = "report.txt"

    with open(report_name, "w") as f:
        f.write("Vulnerability Scan Report\n")
        f.write(f"Target: {target}\n")
        f.write(f"Open Ports: {open_ports}\n")

    print(f"\n✅ Report saved as {report_name}")

target = input("Enter target IP or hostname to scan: ")
scan_target(target)
