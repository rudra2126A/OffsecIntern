import socket
import sys
import concurrent.futures

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def format_port_results(results):
    formatted_results = "Port Scan Results:\n"
    formatted_results += "{:<8} {:<15} {:<10}\n".format("Port", "Service", "Status")
    formatted_results += "-" * 85 + "\n"
    for port, service, banner, status in results:
        if status:
            formatted_results += f"{RED}{port:<8} {service:<15} {'Open':<10}{RESET}\n"
            if banner:
                banner_lines = banner.split("\n")
                for line in banner_lines:
                    formatted_results += f"{GREEN}{'':<8}{line}{RESET}\n"
    return formatted_results

def get_banner(sock):
    try:
        sock.settimeout(1)
        banner = sock.recv(1024).decode().strip()
        return banner
    except:
        return None 
def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port,'tcp')
            except:
                service = "Unknown Service"
            banner = get_banner(sock)
            return port, service, banner, True
        else:
            return port, None, None, False
    except Exception as e:
        return port, None, None, False
    finally:
        sock.close()

def port_scanner(target_host, start_port, end_port):
    target_ip = socket.gethostbyname(target_host)
    print(f"Starting scan on host: {target_ip}")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=400) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in range(start_port, end_port + 1)}
        total_ports = end_port - start_port + 1
        for i, futures in enumerate(concurrent.futures.as_completed(futures), start=1):
            port, service, banner, status = futures.result()
            results.append((port, service, banner, status))
            sys.stdout.write(f"\rScanned {i}/{total_ports} ports")
            sys.stdout.flush()

        sys.stdout.write("\n")
        print(format_port_results(results))

if __name__ == "__main__":
    target_host = input("Enter target host (IP or domain):")
    start_port = int(input("Enter the start port:"))
    end_port = int(input("Enter the end port:"))

    port_scanner(target_host, start_port, end_port)