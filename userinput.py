import ipaddress
import subprocess
import time

def user_input():
    while True:
        print("\nWelcome to Team10 Network Scanner\nEnjoy the scan!")
        time.sleep(0.5)
        print("Remember that scanning a target may seem harmless, but can be intrusive. \nRemember to seek prior authorisation when conducting scans \nwith the Team10scanner.\In order for the scanner to run you need to make sure that\n socket, scapy, sys, and asyncio are installed.")
        print("To install the necessary libraries, exit the scanner and type \"pip install \[whatever library you're missing\]\" in the command line interface")
        time.sleep(0.5)
        ip_input = input("Enter the IP address to scan (or type 'exit' to quit): ").strip()
        
        if ip_input.lower() == "exit":
            print("we hope your scan met your expectations, goodbye!")
            break

        try:
            ip = ipaddress.IPv4Address(ip_input)
        except ipaddress.AddressValueError:
            print("Invalid IP address. remember to use IPv4 format (1-255.1-255.1-255.1-255).")
            continue

        scan_type = input('Enter the type of scan (MAP, PORT, SV, OS, FULL) or HELP (or type exit if you want to quit) : ').strip().upper()

        if scan_type == "HELP":
            print("\n Available Scan Types:")
            print("  MAP  : Host discovery (ping & SYN), this will see if a target is online")
            print("  PORT : Port scan, this scan will look for open ports on the target device. It will scan through all 65535 ports ")
            print("  SV   : Service and version scan, this scan will probe the ports you enter, either a single port or a list. The scanner will try to determine which service and version is running on the port")
            print("  OS   : OS detection scan, this scan will try to determine what operating system is installed on the target. The scanner will look at the TTL (time to live) and the window size of the TCP header")
            print("  FULL : All modes, scanner will run scan on all ports, SV will run on all open ports, OS will run on first open port")
            print("  HELP : Typing \"help\" got you here, and will do so the next time as well")
            
            continue  

        if scan_type not in ["SV", "PORT", "OS", "MAP", "FULL"]:
            print(" Unknown scan type. Type 'help' to see options.")
            continue

        port_to_scan = 80  # Default port

        if scan_type == "OS":
            port_input = input("Enter the port to scan (default 80 for OS scan): ").strip()
            if port_input.isdigit():
                port_to_scan = int(port_input)
                if port_to_scan < 1 or port_to_scan > 65535:
                    print("Port out of range. Using default port (80).")
                    port_to_scan = 80
            else:
                print("Invalid port. Using default port (80).")
        if scan_type == "SV":
            port_input = input("Enter the ports to scan (comma-separated, 80,443,8080): ").strip()
            ports = port_input.split(',')
            valid_ports = []
            
            for port in ports:
                if port.strip().isdigit():
                    port_num = int(port.strip())
                    if 1 <= port_num <= 65535:
                        valid_ports.append(port_num)
                    else:
                        print(f"Port {port_num} out of range. Skipping.")
                else:
                    print(f"Invalid port {port}. Skipping.")
            
            if not valid_ports:
                print("No valid ports entered. Using default port (80).")
                port_to_scan = 80
            else:
                port_to_scan = valid_ports
    
        
        cmd = ["sudo", "python3", "team10scanner.py", scan_type, str(ip)]
        if scan_type in ["OS", "SV"]:
            if isinstance(port_to_scan, list):
                port_str = ",".join(str(p) for p in port_to_scan)
                cmd.append(port_str)
            else:
                cmd.append(str(port_to_scan))

        print("\nLaunching scan.\n")
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        print(result.stdout)
        if result.stderr:
            print("Error:", result.stderr)

        input("\nPress Enter to return to the main menu.")


if __name__ == "__main__":
    user_input()
