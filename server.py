import socket
from threading import Thread

Group_lists=[] #key as grp name and value and name of all group members

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

class Groups:
    def __init__(self,group_name,username):
        self.group_name=group_name
        self.members=[]
        self.members.append(username)
        self.key=str(group_name)+"ee"

    def update_group(self,username):
        self.members.append(username)


def rcv(client,username):
    while True:
        msg_rcvd = client.recv(1024).decode("utf-8")
        #(recipient, msg1) = msg_rcvd.split(maxsplit=1)
        #print(msg_rcvd)
        if not(msg_rcvd.startswith("create") or msg_rcvd.startswith("group") or msg_rcvd.startswith("join") or msg_rcvd.startswith("list")):
            send(client,username,msg_rcvd)
        else:
            (command, msg) = msg_rcvd.split(maxsplit=1) 
            if (command=="create"):
                Group_lists.append(Groups(msg,client))
                for obj in Group_lists:
                    if obj.group_name == msg :
                        client.send(bytes(obj.key,'utf-8'))
                for obj in Users:
                    if obj.username==client:
                        obj.groups.append(msg)
                print("***********Group created****************")

            elif(command=="group"): #msg=groupname msg # command=group
                i=0
                (groupname,msg1)=msg.split(maxsplit=1)
                for i in range(len(Group_lists)):
                    if(Group_lists[i].group_name==groupname):
                        if client in Group_lists[i].members:
                            client.send("enter key".encode())
                            kk=client.recv(1024).decode()
                            if(Group_lists[i].key==kk):
                                send1("group",client,groupname,msg) 
                                client.send("Message sent".encode())
                                print("***********Message sent****************")
                            else:
                                clien.send("Wrong key entered, please try again".encode())
                        else:
                            client.send("You are not part of the group".encode())

            elif(command=="join"): #msg=group ka naam
                i=0
                print(Group_lists)
                for i in range(len(Group_lists)):
                    print(Group_lists[i].group_name)
                    print(msg)
                    if(Group_lists[i].group_name==msg):
                        print(client)

                        Group_lists[i].update_group(client)
                        y=str(Group_lists[i].key)
                        client.send(y.encode())
                        print("***************Group joined********************")
                if(i==len(Group_lists)):
                    Group_lists[i].append(Groups(groupname,client))
                    for obj in Group_lists:
                        if obj.group_name == groupname :
                            y=str(obj.key)
                            client.send(y.encode())
                    for obj in Users:
                        if obj.username==client:
                            obj.groups.append(msg)
                
            elif(command=="list"):
                data = {}

                for x in Group_lists:
                    data[x.group_name] = len(x.members)
                #length=int(len(data))
                client.send(str(data).encode())
                


def send(client,username,peername):
    to_send = [x.socket for x in Users if username == x.username][0]
    reciever_port = [x.port for x in Users if peername == x.username][0]
    
    #print(to_send,sender)
    #msg = sender + ' : ' + msg
    m1 = peername + ":" + reciever_port
    to_send.send(bytes(m1,'utf-8'))


def send1(txt,client,groupname,msg):
    if(txt=="group"):
        for obj in Group_lists:
            if obj.group_name==groupname:
                msg = str(groupname) + "[" + str(client) +"] : " + str(msg)
                for mem in obj.members:
                    for x in Users:
                        if x.username == mem:
                            to_send=x.socket  
                            to_send.send(bytes(msg,'utf-8'))
                            

def client_chat(client,username):
    RCV_THREAD = Thread(target=rcv,args=(client,username,))
    RCV_THREAD.start()

def client_handle(client,addr):
    client.send(bytes('Reply "1" for Sign Up \nReply "2" for login','utf-8'))
    user_response = client.recv(8).decode("utf-8")
    if int(user_response) == 1:
        client.send(bytes('Enter Username','utf-8'))
        username = client.recv(8).decode("utf-8")
        client.send(bytes('Enter Password','utf-8'))
        password = client.recv(8).decode("utf-8")
        client.send(bytes('Enter Port','utf-8'))
        port= client.recv(8).decode("utf-8")
        Username_and_Passwords[username] = password
        Username_and_Port[username] = port
        Users.append(User(username, password, port, client, addr))
        client.send(bytes('Sign Up Successful','utf-8'))
        client_chat(client,username)
    else:
        client.send(bytes('Enter Username','utf-8'))
        username = client.recv(8).decode("utf-8")
        client.send(bytes('Enter Password','utf-8'))
        password = client.recv(8).decode("utf-8")
        client.send(bytes('Enter Port','utf-8'))
        port= client.recv(8).decode("utf-8")
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
PORT = 6620
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