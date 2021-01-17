import socket
from threading import Thread

def rcv():
    while True:
        print(server.recv(1024).decode("utf-8"))

def send():
    while True:
        msg_send = input()
        server.send(bytes(msg_send,'utf-8'))


def chat():
    SEND_THREAD = Thread(target=send)
    RCV_THREAD = Thread(target=rcv)
    SEND_THREAD.start()
    RCV_THREAD.start()
    

PORT = input('Enter port: ')
ADDR = (socket.gethostname(),int(PORT))

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.connect(ADDR)
print(server.recv(1024).decode("utf-8"))


#LOGIN or SIGNUP
print(server.recv(1024).decode("utf-8"))
sending = input()
server.send(bytes(sending,"utf-8"))

#SIGNUP
def login():
    if int(sending) == 1:
        print(server.recv(1024).decode("utf-8"))
        username = input()
        server.send(bytes(username,'utf-8'))
        print(server.recv(1024).decode("utf-8"))
        password = input()
        server.send(bytes(password,'utf-8'))
        server_response = server.recv(1024).decode("utf-8")
        print(server_response)
    elif int(sending) == 2:
        print(server.recv(1024).decode("utf-8"))
        username = input()
        server.send(bytes(username,'utf-8'))
        print(server.recv(1024).decode("utf-8"))
        password = input()
        server.send(bytes(password,'utf-8'))
        server_response = server.recv(1024).decode("utf-8")
        print(server_response)
    return server_response

server_response = login()
if("Successful" in server_response):
    chat()
    


