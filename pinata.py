import sys
import socket
import asyncio
from scapy.layers.inet import IP, TCP, ICMP, sr1
import time

results = ""


#classic map
def is_host_up(host, ports=[21, 22, 23, 25, 53, 80, 443, 8080, 3306, 3389, 445, 5900]):
    icmp_pkt = IP(dst=host) / ICMP()
    icmp_resp = sr1(icmp_pkt, timeout=1, verbose=False)
    if icmp_resp:
        return True

    for port in ports:
        tcp_pkt = IP(dst=host) / TCP(dport=port, flags="S")
        tcp_resp = sr1(tcp_pkt, timeout=2, verbose=False)
        if tcp_resp and tcp_resp.haslayer(TCP):
            if tcp_resp[TCP].flags == 0x12:
                return True

    return False


def check_host(ip):
    if is_host_up(ip):
        return f"{ip} is up"
    else:
        return f"{ip} is down"
#end of classic map

#port scanning
async def scan_port(ip, port, open_ports, semaphore):
    try:
        async with semaphore:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1)
            open_ports.append(port)
            writer.close()
            await writer.wait_closed()
    except:
        pass

async def async_portscan(ip, ports=range(1, 65535), max_concurr=1000):
    open_ports = []
    semaphore = asyncio.Semaphore(max_concurr)
    tasks = [scan_port(ip, port, open_ports, semaphore) for port in ports]
    await asyncio.gather(*tasks)
    return open_ports

def portscan(ip, ports=range(1, 65535)):
    open_ports = asyncio.run(async_portscan(ip, ports))
    if open_ports:
        result = f"Open ports on {ip}: {sorted(open_ports)}"
    else:
        result = f"No open ports found on {ip}."
    return result, open_ports  #

#service version detection
def detect_service_version(ip, target_ports):
    versions = {}

   
    probes = {
        22: b"\r\n",  
        25: b"EHLO generic-address.com\r\n",  
        80: b"HEAD / HTTP/1.1\r\nHost: generic-address.com\r\n\r\n",  #HTTP
        443: b"",  #HTTPS 
        3306: b"\x00",  #MySQL 
        110: b"QUIT\r\n",  #POP3
        143: b"LOGOUT\r\n",  #IMAP
        21: b"QUIT\r\n",  #FTP
    }

    for port in target_ports:
        try:
            sock = socket.socket()
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))

            if result == 0:
                #Send protocol-specific probe
                try:
                    probe = probes.get(port, b"\r\n")
                    if probe:
                        sock.sendall(probe)

                    banner = sock.recv(1024).decode(errors='ignore').strip()

                    if banner:
                        banner_line = banner.split("\n")[0]
                        versions[port] = banner_line
                    else:
                        versions[port] = "Open, no banner received"
                except Exception as e:
                    versions[port] = f"Open, but banner detection failed: {e}"
            else:
                versions[port] = "Closed or filtered"
            sock.close()
        except Exception as e:
            versions[port] = f"Error: {str(e)}"

    return versions

#end of service version detection

#OS detection
def get_ttl(ip):
    # Send a ping packet to the target IP address
    try:
        pkt = IP(dst=ip) / ICMP()
        resp = sr1(pkt, timeout=2, verbose=False)
        if resp and resp.haslayer(IP):
            return resp[IP].ttl
    except Exception as e:
        return f"Error pinging {ip}: {e}"
    return None


def estimated_os_from_ttl(ttl):
    # Map TTL values to OS signatures, possible vulnerability is if number of hops is large ttl might slip into other OS ttl
    if ttl is None:
        return "Unknown"
    elif ttl <= 32:
        return "Windows 98"
    elif ttl <= 60:
        return "Stratus STCP"
    elif ttl <= 64:
        return "Several possible matches with TTL of 64 or less: \nCompa Tru64 v5.0, Foundry, FreeBSD 5, juniper systems, \nLinux 2.0.x kernel, Linux Red Hat 9, \nMacOS/MacTCP X (10.5.6), Netgear FVG318"
    elif ttl <= 128:
        return "Windows 98, 98 SE, Windows NT 4 WRKS SP 3 or SP 6a, \nWindows NT 4 Server SP4, Windows ME, Windows 2000 pro, \nWindows 2000 family, Windows XP, \nWindows Vista, Windows 7, Windows Server 2008, Windows 10"
    elif ttl <= 200:
        return "MPE/IX (HP)"
    elif ttl <= 254:
        return "Cisco/Networking Device"
    elif ttl <= 255:
        return "Several possible matches with TTL of 255: \nAIX 3.2 and 4.1, BSDI BSD/OS 3.1 and 4.0, FreeBSD 3.4 and 4.0, \nHP-UX 10.2, HP-UX 11, Irix 6.5.3 and 6.5.8, \nLinux 2.2.14 kernel, Linux 2.4 kernel, NetBSD, \nOpenBSD 2.6 and 2.7, OpenVMS 07.01.2002, Solaris 2.5.1 and 2.6 and 2.7 and 2.8, \nStratus TCP_OS, SunOS 5.7, Ultrix V4.2 – 4.5"
    else:
        return "Unknown"


def get_window_size(ip, port):
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        rsp = sr1(pkt, timeout=5, verbose=False)
        if rsp and rsp.haslayer(TCP):
            return rsp[TCP].window
    except Exception as e:
        return f"Error: {e}"
    return None


def estimated_os_from_window(window):
    if window is None:
        return "Unknown"

    os_signatures = {
        8192: "Windows XP/2000/NT",
        16384: "Windows 7/8/10",
        65535: "Windows Server or High-Performance Windows",
        5840: "Linux (2.4 - 3.x kernels)",
        64240: "Linux (Modern 4.x kernels)",
        14600: "FreeBSD/macOS",
        32120: "MacOS X (Lion/Mountain Lion)",
        4128: "Cisco Router/Networking Device",
        8760: "Solaris 7/8/9",
        32768: "OpenBSD",
    }

    if window in os_signatures:
        return f"Likely {os_signatures[window]}"

    if 8192 <= window <= 16384:
        return "Possible Windows (XP - 10)"
    elif 5840 <= window <= 64240:
        return "Possible Linux-based OS"
    elif 14600 <= window <= 32120:
        return "Possible macOS/FreeBSD"
    elif window <= 4128:
        return "Possible Cisco/Solaris/Embedded Device"

    return "Unknown OS"

def perform_os_detection(ip, port=80):
    ttl = get_ttl(ip)
    estimated_os = estimated_os_from_ttl(ttl)
    window = get_window_size(ip, port)
    windowsize_os_estimate = estimated_os_from_window(window)
    
    print("\nOS Detection Results:")
    print('Accurately estimating OS based on solely on ttl requires\nknowledge of the number of hops between scanner and target. ')
    print(f"\nTTL: {ttl} OS based on time to live: {estimated_os}")
    print(f"\nWindow Size: {window} OS based on window size: {windowsize_os_estimate}")
    
    return ttl, window, estimated_os, windowsize_os_estimate
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 team10scanner.py <scan_type> <ip> [<port>]")
        sys.exit(1)

    scan_type = sys.argv[1].lower()
    ip = sys.argv[2]
    if len(sys.argv) > 3:
        if "," in sys.argv[3]:
            port = [int(p.strip()) for p in sys.argv[3].split(",")]
        else:
            port = int(sys.argv[3])
    else:
        port = 80

    if scan_type == "map":
        starttime = time.time()
        print("=" * 60)
        print("MAP RESULT")
        print("=" * 60,"\n")
        print(check_host(ip))
        endtime = time.time()
        print("\nScan completed in", endtime - starttime, "seconds")
        

    elif scan_type == "port":
        starttime = time.time()
        print("=" * 60)
        print("PORT SCAN RESULT")
        print("=" * 60,"\n")
        port_result, open_ports = portscan(ip)
        print(port_result)
        endtime = time.time()
        print("\nScan completed in", endtime - starttime, "seconds")

    elif scan_type == "sv":
            starttime = time.time()
            if isinstance(port, list):
                target_ports = port
            else:
                target_ports = [port]

            print("\nRunning Service Version Detection\n")
            services = detect_service_version(ip, target_ports)
            print("=" * 60)
            print("SV DETECTION RESULTS")
            print("=" * 60,"\n")
            for p, svc in services.items():
                print(f"Port {p}: {svc}")
            endtime = time.time()
            print("\nScan completed in", endtime - starttime, "seconds")

    elif scan_type == "os":
        print(f"Scanning Host: {ip}")
        perform_os_detection(ip, port if isinstance(port, int) else port[0])

    elif scan_type == "full":
        print("=" * 60)
        print(f"FULL SCAN REPORT FOR TARGET: {ip}")
        print("=" * 60)
        
        starttime = time.time()
        
        host_status = check_host(ip)
        print("\n[+] Host Discovery:")
        print(host_status)
        
        if "is up" in host_status:
            print("\n[+] Port Scanning:")
            port_result, open_ports = portscan(ip)
            print(port_result)
            
            if open_ports:
                           
                
                print("\n[+] Service Version Detection:")
                services = detect_service_version(ip, open_ports)
                for p, svc in services.items():
                    print(f"  Port {p}: {svc}")
                
                print("\n[+] OS Detection:")
                perform_os_detection(ip, open_ports[0])

        endtime = time.time()
        print("\n" + "=" * 60)
        print(f"Full scan completed in {endtime - starttime} seconds")
        print("=" * 60)

    else:
        print("Unknown scan type. Use one of: map, os, sv. port, full")
