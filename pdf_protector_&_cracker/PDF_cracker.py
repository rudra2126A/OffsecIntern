import itertools
import pikepdf
from tqdm import tqdm
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

def generate_passwords(chars, min_length, max_length):
    for length in range(min_length, max_length + 1):
        for password in itertools.product(chars, repeat=length):
            yield ''.join(password)

def load_wordlist(file):
    with open(file,'r') as f:
        for line in f:
            yield line.strip()

def try_password(pdf_file, password):
    try:
        with pikepdf.open(pdf_file, password=password) as pdf:
            print("[+] Password found:", password)
            return password
    except pikepdf._core.PasswordError:
        return None
    
def decrypt_pdf(pdf_file, passwords, total_passwords, max_workers=4):
    with tqdm(total=total_passwords, desc="Decrypting PDF", unit="passwords") as  pbar:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_password = {executor.submit(try_password, pdf_file, pwd): pwd for pwd in passwords}
            for future in tqdm(future_to_password, total=total_passwords):
                password = future_to_password[future]
                if future.result():
                    return future.result()
                pbar.update(1)
    print("[-] Password not found.")
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Decrypt a password-protected PDF file.")
    parser.add_argument("pdf_file",help="Path to the password-protected PDF file.")
    parser.add_argument("--wordlist","-w",help="Path to a wordlist file for dictionary attack.")
    parser.add_argument("--generate","-g",action="store_true",help="Generate passwords using brute-force attack.")
    parser.add_argument("--min_length","-min",type=int,default=1,help="Minimum length of generated passwords.")
    parser.add_argument("--max_length","-max",type=int,default=4,help="Maximum length of generated passwords.")
    parser.add_argument("--chars","-c",type=str,default=string.ascii_lowercase + string.digits,help="Characters to use for password generation.")
    parser.add_argument("--workers","-j",type=int,default=4,help="Number of concurrent workers.")
    args = parser.parse_args()
    if args.generate:
        passwords= generate_passwords(args.chars, args.min_length, args.max_length)
        total_passwords = sum(1 for _ in generate_passwords(args.chars, args.min_length, args.max_length))
    elif args.wordlist:
        passwords = load_wordlist(args.wordlist)
        total_passwords = sum(1 for _ in load_wordlist(args.wordlist))
    else:
        print("[-] Please provide either a wordlist or enable password generation.")
        exit(1)
        with open(args.wordlist,'r') as f:
            total_passwords = sum(1 for _ in f)
    decrypt_password = decrypt_pdf(args.pdf_file, passwords, total_passwords, args.workers)

    if decrypt_password:
        print(f"PDF decrypted successfully with password: {decrypt_password}")
    else:
        print("Failed to decrypt the PDF.")
        exit(1)