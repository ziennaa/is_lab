import socket

import hashlib



def sha256_hex(data):

    if isinstance(data, str):

        data = data.encode()

    return hashlib.sha256(data).hexdigest()



filename = input(
    "Enter patient report filename: "
)



with open(filename, "rb") as file:

    data = file.read()



# client calculates original SHA-256

sender_hash = sha256_hex(
    data
)


print(
    "sender hash: ",
    sender_hash
)



# combine file data and hash for sending

message = (
    data
    + b"\n---HASH---\n"
    + sender_hash.encode()
)



client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)



client.connect(
    ("127.0.0.1", 5000)
)



print("connected to server")



# send data + hash

client.sendall(
    message
)



# tell server that sending is finished

client.shutdown(
    socket.SHUT_WR
)



# receive verification result

response = client.recv(
    1024
)


print(
    "server response: ",
    response.decode()
)



client.close()

'''
Create a test file

Make:

patient.txt

with something like:

Patient Name: Manya
Age: 20
Diagnosis: Fever
Blood Group: A+

Then open two terminals.

Terminal 1:

python server.py

You'll see:

server waiting for client...

Then Terminal 2:

python client.py

Enter:

patient.txt

The server will ask:

Do you want to tamper data? y/n:
Test 1: no tampering

Enter:

n

You should get:

sender hash:     abc....
receiver hash:   abc....

integrity: True

Integrity Verified
received file stored successfully

Client gets:

server response: Integrity Verified

And:

received_patient_report.txt

gets created.

Test 2: tampering

Run server and client again and enter:

y

Now:

sender hash:    abc....
receiver hash:  xyz....

integrity: False

Integrity Failed
file not stored because tampering was detected

Client gets:

server response: Integrity Failed
What socket lines actually mean

The server pattern you need to remember is:

server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server.bind(
    ("127.0.0.1", 5000)
)

server.listen(1)

conn, address = server.accept()

data = conn.recv(...)

conn.sendall(...)

Mental story:

socket()
↓
create server

bind()
↓
give server address + port

listen()
↓
wait for client

accept()
↓
client connected

recv()
↓
receive something

sendall()
↓
send something back

Client is even simpler:

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client.connect(
    ("127.0.0.1", 5000)
)

client.sendall(...)

response = client.recv(1024)

So the core template to remember tomorrow is basically:

SERVER:
socket → bind → listen → accept → recv → process → send

CLIENT:
socket → connect → send → recv

Everything else — SHA, AES, RSA, DH — is just what you put in the process part.

client.py
server.py
What the question is asking
Client side
.txt file
↓
read file
↓
SHA-256(file contents)
↓
send:
    file contents
    sender hash
↓
wait for server response
↓
print "Integrity Verified" / "Integrity Failed"
Server side
receive:
    file contents
    sender hash
↓
SHA-256(received contents)
↓
compare with sender hash

same
→ Integrity Verified
→ save file
→ send success to client

different
→ Integrity Failed
→ DON'T save file
→ send failure to client

For the tampering demonstration, we'll simply ask on the server:

Do you want to tamper data? y/n

If y, we'll change one byte before computing the receiver hash.

So:

original data     → sender hash

tampered data     → receiver hash

sender hash != receiver hash
→ Integrity Failed

'''
