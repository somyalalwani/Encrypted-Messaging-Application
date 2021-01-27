import socket
from threading import Thread
import pyDH
from Crypto.Cipher import DES3
import sys
import nacl.secret
import nacl.utils
import nacl.pwhash
import os
# Do not do "import nacl", it won't work
import base64

group_key={}

def keyGen(password,groupname):
    kdf = nacl.pwhash.argon2i.kdf # our key derivation function
    salt_size = nacl.pwhash.argon2i.SALTBYTES # The salt musts have a size of 16 bytes
    print(salt_size)
    salt = nacl.utils.random(salt_size) # can be sth like: b'3\xba\x8f\r]\x1c\xcbOsU\x12\xb6\x9c(\xcb\x94'
    print(salt) # To decrypt the data later, you have to save this salt somewhere.
    password=password.encode("utf-8")
    key = kdf(nacl.secret.SecretBox.KEY_SIZE, password, salt)
    hexed_key = key.hex()
    group_key[groupname] = hexed_key
    

def groupMsgGen(secret_msg,groupname):
    key = group_key[groupname]
    # Encrypt the data:
    box = nacl.secret.SecretBox(bytes.fromhex(key))
    # msgsend =''.join(format(ord(i), 'b') for i in secret_msg)
    encrypted = box.encrypt(bytes(secret_msg.encode('utf-8')))
    return encrypted


def rcv():
    while True:
        print()
        print("-----------")
        print(server.recv(1024).decode("utf-8"))
        print("-----------")
        print()


def pad(msg):
    while len(msg)%8 !=0:
        msg += ' '
    return msg 


def msg_peer(peer_port,msg, isFile):
    peer_ip = socket.gethostname()
    peer_info = (peer_ip,int(peer_port))
    server_peer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server_peer.connect(peer_info)
    

    #key for symmetric key encryption
    
    
    if isFile == False:
        msgtype = "text"
        server_peer.send(msgtype.encode())
        #Encrypting Message
        DH1 = pyDH.DiffieHellman()
        DH1_publickey = DH1.gen_public_key()
        server_peer.send(bytes(str(DH1_publickey),'utf-8'))
        F_publickey = server_peer.recv(1024).decode("utf-8")
        DH1_secretkey = DH1.gen_shared_key(int(F_publickey))
        msg = pad(msg)
        cipher = DES3.new(str(DH1_secretkey)[0:24], DES3.MODE_ECB)
        encrypted_msg = cipher.encrypt(msg.encode("utf-8"))
        server_peer.send(encrypted_msg)
    else:
        msgtype = "file"
        server_peer.send(msgtype.encode())
        server_peer.send(msg)
    # server_peer.send(msg)
    server_peer.close()


def start_server(portno):
    PORT1 = int(portno)
    peer_server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    peer_server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    ADDR = (socket.gethostname(),PORT1)
    peer_server.bind(ADDR)
    peer_server.listen()
    ACCEPT_THREAD = Thread(target=wait_for_connection,args=(peer_server,))
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
        #client1.send(bytes('Connection Established','utf-8'))
        #CLIENT_THREAD = Thread(target=rcv_msg,args=(peer_server,))
        #CLIENT_THREAD.start()

def send(username):
    while True:
        msg_send = input()
        command,msg = msg_send.split(maxsplit=1)
        command = command.lower()
        if (command == 'send'):
            isFile = False
            command, msg = msg.split(maxsplit=1)
            server.send(bytes(command,'utf-8'))
            details = server.recv(1024).decode("utf-8")
            peername , portno = details.split(":")

            if 'file' in msg: #ruchi file a.txt
                isFile = True
                filename = msg.split(' ')[1]
                header = username+ ' file ' + filename+'\n\n' #file a.txt\n\n
                if isFile == True:
                    
                    try:
                        fin = open(filename,"rb")
                        content = fin.read()
                        content = header.encode()+content
                        fin.close()
                        msg_peer(portno,content,isFile)

                    except FileNotFoundError:
                        content = 'unsuccessfull recieve :(\n'
                        msg_peer(portno,content,isFile)
            else:
                message = "\n-----------\n" + username + ':"' + msg + '"\n-----------\n'
                msg_peer(portno,message,isFile)

        elif(command=="create"):
            server.send(bytes(str(command) + " " + str(msg),'utf-8'))
            details = server.recv(1024).decode("utf-8") #key recvd
            if(details=="Group creation Successful! Generate a key :"):
                password = username+msg
                keyGen(password,msg)


            else:
                print("error!")
        elif(command=="list"):
            server.send(bytes(str(command)+" "+ str(msg),'utf-8'))
            details = server.recv(1024).decode("utf-8")
            print()
            print("-----------")
            print(" Group: No. of members")
            print(details)
            print("-----------")
            print()


        elif(command=="join"):
            server.send(bytes(str(command) + " "+ str(msg),'utf-8'))
            admin_port = server.recv(1024).decode()
            print("************:")
            print(admin_port)
            print("************")
            if admin_port != "Group creation Successful! Generate a key :":
                peer_ip = socket.gethostname()
                peer_info = (peer_ip,int(admin_port))
                server_peer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                server_peer.connect(peer_info)
                txt="keyg"
                server_peer.send(txt.encode())
                server_peer.send(msg.encode()) #sending grp name
                details=server_peer.recv(1024).decode() #key
                print()
                print("-----------")
                print("Group joined successfully!!")
                # print("Key recvd : "+ details)
                print("-----------")
                print()
                group_key[msg] = details
                server_peer.close()
                
                
            else:
                print("key generation code ayega yaha bs")

            

        else:
            gname,secret_msg = msg.split(maxsplit=1)
            encrypted = groupMsgGen(secret_msg,gname)
            server.send(bytes(str(command) + " "+ str(gname),'utf-8'))
            server.send(encrypted)
            details = server.recv(1024).decode()
            #print(details)
            

def rcv_msg(client):
    data = client.recv(1024) #when msg is multimedia
    header,content = data.split(b'\n\n',1)
    header = header.decode() # username file a.txt
    # print(header)
    list1 = header.split(' ')
    if 'file' in header:
        uname = list1[1]
        filename = header.split(' ')[2]
        ext = filename.split('.')[1]
        newfilename = filename.split('.')[0] + "(new)."+ext #a(new).txt

        with open(newfilename, "wb") as F:
            while content:
                F.write(content)
                content = client.recv(1024)
            F.close()
            print("\n-----------\n" + uname + ':"' + newfilename+' recieved!' + '"\n-----------\n')
            # print("Your friend has sent " + old_filename + " which has been downloaded on your system as " + filename)
    
    else:
        print(content.decode("utf-8")) 

def chat(username,portno):
    SEND_THREAD = Thread(target=send,args=(username,))
    MSGS_THREAD = Thread(target=start_server,args=(portno,))
    SEND_THREAD.start()
    MSGS_THREAD.start()

def wait_for_connection(peer_server):
    while True:
         client, addr = peer_server.accept()
         filetype = client.recv(4)
         filetype = filetype.decode()
         #print(filetype)
         if filetype == "text":
             DH2 = pyDH.DiffieHellman()
             DH2_publickey = DH2.gen_public_key()
             R_publickey = client.recv(1024).decode("utf-8")
             client.send(bytes(str(DH2_publickey),'utf-8'))
             #key for symmetric key decryption
             shared_key2 = DH2.gen_shared_key(int(R_publickey))
             encrypted_msg = client.recv(1024)
             #decrypting message
             cipher = DES3.new(str(shared_key2)[0:24], DES3.MODE_ECB)
             msg = cipher.decrypt(encrypted_msg)
             print(str(msg.decode("utf-8")))
         elif filetype == "file":
            rcv_msg(client)
         elif filetype=="grup":
            data = (client.recv(1024).decode())
            msg = client.recv(1048576)
            print()
            print("-----------")
            gname = data.split(" [")[0]
            box = nacl.secret.SecretBox(bytes.fromhex(group_key[gname]))
            #encrypted = base64.b64decode(msg)
            secret_msg = box.decrypt(msg)
            temp = data.split(":")[0] + ": " + secret_msg.decode()
            print(temp)
            print("-----------")
            print()

         elif filetype=="keyg":
            grpname = client.recv(1024).decode()
            #print("Enter key to join group" + grpname)
            data=group_key[grpname]
            # print("KEY SENT:",data)
            client.send(str(data).encode())

         else:
             print(filetype)
             print("message type not recognised!!")

PORT = input('Enter server\'s port: ')
ADDR = (socket.gethostname(),int(PORT))

server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.connect(ADDR)
print(server.recv(1024).decode("utf-8")) #will print connection established if established

#LOGIN or SIGNUP
user_Data = []
user_response = input('Reply "1" for Sign Up \nReply "2" for login\n')
if user_response == '1':
    username = input('enter username\n')
    password = input('enter password\n')
    portno = input('enter your own port\n')
    user_Data = [ '1',username, password, portno]
    server.send(bytes(str(user_Data),'utf-8'))
    # server.send(str(userdata).encode())

elif user_response == '2':
    username = input('enter username\n')
    password = input('enter password\n')
    portno = input('enter your own port\n')
    user_Data = ['2',username, password, portno]
    server.send(bytes(str(user_Data),'utf-8'))
else:
    print("invalid response!")
    sys.exit()

server_response = server.recv(1024).decode("utf-8") #server will tell if login/signup is successful or not
print()
print(server_response)

if("Successful" in server_response):
    print("\n***chatroom started! say hii to your friend!***\n")
    chat(username,portno)
    