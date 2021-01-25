import socket
from threading import Thread

class User:
    def __init__(self, username, password, port, socket, address):
        self.username = username
        self.password = password
        self.port = port
        self.socket = socket
        self.addr = address
        self.groups = []
    
    def add_group(self, group):
        self.groups.append(group)
    
    def update_socket(self,client, addr, port):
        self.socket = client
        self.addr = addr
        self.port = port


def rcv(client,username):
    while True:
        msg_rcvd = client.recv(1024).decode("utf-8")
        #(recipient, msg1) = msg_rcvd.split(maxsplit=1)
        # print(msg_rcvd)
        send(client,username,msg_rcvd)

def send(client,username,peername):
    to_send = [x.socket for x in Users if username == x.username][0] #socket
    reciever_port = [x.port for x in Users if peername == x.username][0] #port

    m1 = peername + ":" + reciever_port
    to_send.send(bytes(m1,'utf-8'))

def client_chat(client,username):
    RCV_THREAD = Thread(target=rcv,args=(client,username,))
    RCV_THREAD.start()

def client_handle(client,addr):

    user_response = client.recv(4028).decode("utf-8")
    user_response = user_response.replace("', '", " ").strip('[]').strip("''").split(' ')
    username = user_response[1]
    password = user_response[2]
    port = user_response[3]
    if int(user_response[0]) == 1:
        Username_and_Passwords[username] = password
        Username_and_Port[username] = port
        Users.append(User(username, password, port, client, addr))
        client.send(bytes('Sign Up Successful','utf-8'))
        client_chat(client,username)
    else:
        Username_and_Port[username] = port
        if username in Username_and_Passwords.keys() and Username_and_Passwords[username] == password:
            client.send(bytes('Login Successful','utf-8'))
            Current_user = [x for x in Users if username == x.username][0]
            Current_user.update_socket(client,addr,port)
            client_chat(client,username)
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
Username_and_Port = {}
PORT = 5501
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