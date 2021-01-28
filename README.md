# End to End Encrypted Messaging System like WhatsApp

The below functionalities are designed using following commands:
1. **Multiclient chat application** that has a server component and as many no. of clients.
2. The system supports the **signup and sign in** feature.
3. User can send message to other user [p2p message] : **send <USERNAME> <MESSAGE>**
4. Each user can **join multiple chat rooms (groups) at a time**. 
5. Each user can **list all the groups** (show all group and number of participants in each group) : <list groups>
6. Each user can **join a group** using <join group_name>. If the group does not exist then the first create it then joins it.
7. Each user can **create a group** using <create groupname>.
8. If one user sends a message to a group it should be sent to all members of that group.
9. **The message is encrypted using Tripple DES (3DES) and the key will be Diffie–Hellman key type exchanged between clients.**
10. **For each group one key (random nonce) is generated and messages are encrypted through this key and sent to each user.**
11. Message can be any type, for example, text, images, video, and audio.

##### LIST OF COMMANDS:
- Send a message to User: SEND <USERNAME> <MESSAGE>
- Send a multimedia to User: SEND FILE <USERNAME> <MESSAGE>
- Send a message to Group: SEND <GROUPNAME> <MESSAGE>
- Send a multimedia to Group: SEND FILE <GROUPNAME> <MESSAGE>
- Create Group: CREATE <GROUPNAME>
- Join Group: JOIN <GROUPNAME>
- Prints list of all the Group: LIST

##### INSTRUCTIONS TO RUN THE CODE:
- python3 server.py
- python3 client.py

##### EXTERNAL LIBRARIES 
- binascii
- hashlib
- socket
- Thread
- DES3
- nacl.secret
- nacl.utils
- nacl.pwhash
- os
- pyDH
- sys
- base64

#### TEAM MEMBERS
* Anchal Soni - 2020201099
* Param Pujara - 2020202008
* Somya Lalwani - 2020201092
* Utkarsh MK - 2020201027
