import socket
from threading import Thread
import pyDH
from Crypto.Cipher import DES3

def pad(msg):
    while len(msg) != 1024:
        msg += ' '
    return msg 

Group_lists=[] #key as grp name and value and name of all group members
Username_and_Port = {}
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
        self.admin = Username_and_Port[username]

    def update_group(self,username):
        self.members.append(username)


def rcv(client,username):
    while True:
        msg_rcvd = client.recv(1024)
        print(msg_rcvd)
        msg_rcvd=msg_rcvd.decode("utf-8")
        #(recipient, msg1) = msg_rcvd.split(maxsplit=1)
        #print(msg_rcvd)
        if not(msg_rcvd.startswith("create") or msg_rcvd.startswith("group") or msg_rcvd.startswith("join") or msg_rcvd.startswith("list")):
            send(client,username,msg_rcvd)
        else:
            (command, msg) = msg_rcvd.split(maxsplit=1) 
            
            if (command=="create"):
                Group_lists.append(Groups(msg,username))
                """
                for obj in Group_lists:
                    if obj.group_name == msg :
                        client.send(bytes(obj.key,'utf-8'))
                """
                for obj in Users:
                    if obj.username==username:
                        obj.groups.append(msg)
                print("***********Group created****************")
                client.send(bytes("Group creation Successful! Generate a key :",'utf-8'))


            elif(command=="group"): #msg=groupname file filename # command=group
                if "file" in msg:
                    
                    grpname,txt,filename=msg.split(maxsplit=2)
                    
                    filecontent=None
                    newfilename= "new_"+filename
                    filesize = int(client.recv(1024).decode())
                    
                    aa=client.recv(filesize)
                    print(filesize,aa)
                    with open(newfilename,"wb") as F:
                        F.write(aa)
                        

                    i=0
                    #groupname = msg.split(maxsplit=1)[0] 
                    for i in range(len(Group_lists)):
                        if(Group_lists[i].group_name==grpname):
                            if username in Group_lists[i].members:
                                send1("group",username,grpname,filecontent,True,newfilename) 
                                #client.send("Message sent without encryption".encode())
                                print("***********Message sent****************")
                            else:
                                #client.send("You are not part of the group".encode())
                                pass    
                else:    
                    i=0
                    groupname=msg.split(maxsplit=1)[0]
                    msg1 = client.recv(1048576)
                    for i in range(len(Group_lists)):
                        if(Group_lists[i].group_name==groupname):
                            if username in Group_lists[i].members:
                                send1("group",username,groupname,msg1) 
                                #client.send("Message sent!!".encode())
                                print("***********Message sent****************")
                            else:
                                #client.send("You are not part of the group".encode())
                                pass


            elif(command=="join"): #msg=group ka naam
                i=0
                for i in range(len(Group_lists)):
                    if(Group_lists[i].group_name==msg):
                        Group_lists[i].update_group(username)
                        admin_port=str(Group_lists[i].admin)
                        client.send(admin_port.encode())
                        print("***************Group joined********************")
                if(i==len(Group_lists)):
                    # Group_lists.append(Groups(msg,username))
                    client.send(("not").encode())
                    """
                    for obj in Group_lists:
                        if obj.group_name == groupname :
                            y=str(obj.key)
                            client.send(y.encode())
                    """
                    # for obj in Users:
                    #     if obj.username==username:
                    #         obj.groups.append(msg)
                    print("***********Group created****************")

            elif(command=="list"):
                data = {}

                for x in Group_lists:
                    data[x.group_name] = len(x.members)
                #length=int(len(data))
                print(data)
                client.send(str(data).encode())
                


def send(client,username,peername):
    to_send = [x.socket for x in Users if username == x.username][0]
    reciever_port = [x.port for x in Users if peername == x.username][0]
    
    #print(to_send,sender)
    #msg = sender + ' : ' + msg
    m1 = peername + ":" + reciever_port
    to_send.send(bytes(m1,'utf-8'))


def msg_peer1(peer_port,msg):
    
    """
    DH1 = pyDH.DiffieHellman()
    DH1_publickey = DH1.gen_public_key()
    server_peer.send(bytes(str(DH1_publickey),'utf-8'))
    F_publickey = server_peer.recv(1024).decode("utf-8")
    #key for symmetric key encryption
    DH1_secretkey = DH1.gen_shared_key(int(F_publickey))
    #Encrypting Message
    msg = pad(msg)
    cipher = DES3.new(str(DH1_secretkey)[0:24], DES3.MODE_ECB)
    encrypted_msg = cipher.encrypt(msg.encode("utf-8"))
    server_peer.send(encrypted_msg)
    """
    # server_peer.send(msg)
    # server_peer.close()


def send1(txt,client,groupname,msg,isFile=False,filename=" "):    
    if(txt=="group" and isFile==False):
        for obj in Group_lists:
            if obj.group_name==groupname:
                txt="grup"
                msg2 = str(groupname) + " [" + str(client) +"] : "
                msg2 = pad(msg2) 
                for mem in obj.members:    
                    if mem != client:
                        peer_port = Username_and_Port[mem]
                        peer_ip = socket.gethostname()
                        peer_info = (peer_ip,int(peer_port))
                        server_peer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        server_peer.connect(peer_info)
                        server_peer.send(txt.encode())
                        server_peer.send(msg2.encode())
                        server_peer.send(msg)
                        server_peer.close()

    elif(txt=="group" and isFile==True):
        for obj in Group_lists:
            if obj.group_name==groupname:
                txt="gruf"
                msg2 = str(groupname) + " [" + str(client) +"] : 11_" +str(filename)+"*'del"
                msg2 = pad(msg2) 
                for mem in obj.members:    
                    if mem != client:
                        peer_port = Username_and_Port[mem]
                        peer_ip = socket.gethostname()
                        peer_info = (peer_ip,int(peer_port))
                        server_peer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        server_peer.connect(peer_info)
                        server_peer.send(txt.encode())
                        server_peer.send(msg2.encode())
                        with open(filename, "rb") as F:
                            content = F.read(1024)
                            while(content):
                                server_peer.send(content)
                                content = F.read(1024)
                        F.close()
                        server_peer.close()





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

PORT = 5500
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
ADDR = (socket.gethostname(),PORT)

server.bind(ADDR)

if __name__ == "__main__":
    server.listen()
    print("Waiting for connections....")
    ACCEPT_THREAD = Thread(target=wait_for_connection)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
server.close()