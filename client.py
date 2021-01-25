import socket
from threading import Thread
import pyDH
from Crypto.Cipher import DES3
import sys

def rcv():
    while True:
        print(server.recv(1024).decode("utf-8"))

def pad(msg):
    while len(msg)%8 !=0:
        msg += ' '
    return msg 


def msg_peer(peer_port,msg, isFile):
    peer_ip = socket.gethostname()
    peer_info = (peer_ip,int(peer_port))
    server_peer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server_peer.connect(peer_info)
    DH1 = pyDH.DiffieHellman()
    DH1_publickey = DH1.gen_public_key()
    server_peer.send(bytes(str(DH1_publickey),'utf-8'))
    F_publickey = server_peer.recv(1024).decode("utf-8")

    #key for symmetric key encryption
    DH1_secretkey = DH1.gen_shared_key(int(F_publickey))
    
    if isFile == False:
        msgtype = "text"
        server_peer.send(msgtype.encode())
        #Encrypting Message
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
        msg_send = input() # anchal hii
        command,msg = msg_send.split(maxsplit=1) #command = username jisko msg bhejna hai
        # server.send(bytes(command,'utf-8'))
        # details = server.recv(1024).decode("utf-8")
        isFile = False
        if 'file' in msg_send: #ruchi file a.txt
            isFile = True
            filename = msg.split(' ')[1]
            header = username+ ' file ' + filename+'\n\n' #file a.txt\n\n

        if(command == "create_group"):
            pass

        else:
            if isFile == True:
                server.send(bytes(command,'utf-8'))
                details = server.recv(1024).decode("utf-8")
                peername , portno = details.split(":")

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
                server.send(bytes(command,'utf-8'))
                details = server.recv(1024).decode("utf-8")
                peername , portno = details.split(":")
                message = "\n-----------\n" + username + ':"' + msg + '"\n-----------\n'
                msg_peer(portno,message,isFile)


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
        DH2 = pyDH.DiffieHellman()
        DH2_publickey = DH2.gen_public_key()
        R_publickey = client.recv(1024).decode("utf-8")
        client.send(bytes(str(DH2_publickey),'utf-8'))

        #key for symmetric key decryption
        shared_key2 = DH2.gen_shared_key(int(R_publickey))
        filetype = client.recv(4)
        filetype = filetype.decode()
        if filetype == "text":
            encrypted_msg = client.recv(1024)
            #decrypting message
            cipher = DES3.new(str(shared_key2)[0:24], DES3.MODE_ECB)
            msg = cipher.decrypt(encrypted_msg)
            print(str(msg.decode("utf-8")))
        elif filetype == "file":
            rcv_msg(client)
        else:
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
    