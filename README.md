# End to End messaging system like WhatsApp

Design an end to end messaging system like WhatsApp with the below functionalities:.
- Multiclient chat application that has a server component and 4 clients [atleast].
- The system supports the signup and sign in feature. [error message with wrong credentials].
- User can send message to other user [p2p message] [ SEND command] [<SEND> <USERNAME> <MESSAGE>]
- Each user can join multiple chat rooms (groups) at a time.
- Each user can list all the groups. [LIST Command] [show all group and number of participants in each group]
- Each user can join a group [JOIN command]. If the group does not exist then the first create it then joins it.
- Each user can create a group [CREATE command].
- If one user sends a message to a group it should be sent to all members of that group.
- The message is encrypted using Tripple DES (3DES) and the key will be Diffie–Hellman key type exchanged between clients.
- For each group make one key (random nonce).
- Message can be any type, for example, text, images, video, and audio.

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

#### Team Members
* Anchal Soni - 2020201099
* Param Pujara - 2020202008
* Somya Lalwani - 2020201092
* Utkarsh MK - 2020201027
