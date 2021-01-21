import socket
from threading import Thread

class User:
    def __init__(self, username, password, socket, address):
        self.username = username
        self.password = password
        self.socket = socket
        self.addr = address
        self.groups = []
    
    def add_group(group):
        self.groups.append(group)
    
    def update_socket(self,client, addr):
        self.socket = client
        self.addr = addr


def rcv(client):
    while True:
        msg_rcvd = client.recv(1024).decode("utf-8")
        (recipient, msg) = msg_rcvd.split(maxsplit=1)
        send(client,recipient,msg)

def send(client,recipient,msg):
    to_send = [x.socket for x in Users if recipient == x.username][0]
    sender = [x.username for x in Users if client == x.socket][0]
    print(to_send,sender)
    msg = sender + ' : ' + msg
    to_send.send(bytes(msg,'utf-8'))

def client_chat(client):
    RCV_THREAD = Thread(target=rcv,args=(client,))
    RCV_THREAD.start()

def client_handle(client,addr):
    client.send(bytes('Reply "1" for Sign Up \nReply "2" for login','utf-8'))
    user_response = client.recv(8).decode("utf-8")
    if int(user_response) == 1:
        client.send(bytes('Enter Username','utf-8'))
        username = client.recv(8).decode("utf-8")
        client.send(bytes('Enter Password','utf-8'))
        password = client.recv(8).decode("utf-8")
        Username_and_Passwords[username] = password
        Users.append(User(username, password, client, addr))
        client.send(bytes('Sign Up Successful','utf-8'))
        client_chat(client)
    else:
        client.send(bytes('Enter Username','utf-8'))
        username = client.recv(8).decode("utf-8")
        client.send(bytes('Enter Password','utf-8'))
        password = client.recv(8).decode("utf-8")
        if username in Username_and_Passwords.keys() and Username_and_Passwords[username] == password:
            client.send(bytes('Login Successful','utf-8'))
            Current_user = [x for x in Users if username == x.username][0]
            Current_user.update_socket(client,addr)
            client_chat(client)
        elif username not in Username_and_Passwords.keys():
            client.send(bytes('Username does not exist','utf-8'))
        else:
            client.send(bytes('Password does not match','utf-8'))
        

def wait_for_connection():
    while True:
        client, addr = server.accept()
        client.send(bytes('Connection Established','utf-8'))
        CLIENT_THREAD = Thread(target=client_handle,args=(client,addr,))
        CLIENT_THREAD.start()

#List of users
Users = []

Username_and_Passwords = {}
PORT = 5500
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
ADDR = (socket.gethostname(),PORT)
server.bind(ADDR)

if __name__ == "__main__":
    server.listen()
    print("Waiting for connections....")
    ACCEPT_THREAD = Thread(target=wait_for_connection)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
server.close()