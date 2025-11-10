import requests
import threading

domain = input("Enter the domain to enumerate subdomains for: ")
file_path = input("Enter the file path: ")

with open(file_path, "r") as file:
    subdomains = file.read().splitlines()

discovered_subdomains = []

lock = threading.Lock()

def check_subdomain(subdomain):
    url = f"http://{subdomain}.{domain}"
    try:
        response = requests.get(url, timeout=3)
        if response.status_code == 200:
            with lock:
                discovered_subdomains.append(url)
                print(f"[+] Discovered: {url}")
    except requests.RequestException:
        pass

for subdomain in subdomains:
    thread = threading.Thread(target=check_subdomain, args=(subdomain,))
    thread.start()
    thread.join()

for thread in thread:
    thread.join()

with open("discovered_subdomains.txt", "w") as output_file:
    for subdomain in discovered_subdomains:
        output_file.write(subdomain + "\n")