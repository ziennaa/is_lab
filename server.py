import socket

import hashlib



def sha256_hex(data):

    if isinstance(data, str):

        data = data.encode()

    return hashlib.sha256(data).hexdigest()



server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)


server.bind(
    ("127.0.0.1", 5000)
)


server.listen(1)


print("server waiting for client...")


conn, address = server.accept()


print("client connected: ", address)



received = b""


while True:

    part = conn.recv(4096)

    if not part:

        break

    received = received + part



# separate file content and sender hash

file_data, sender_hash = received.split(
    b"\n---HASH---\n",
    1
)


sender_hash = sender_hash.decode()


print("sender hash: ", sender_hash)



# ask whether tampering should be demonstrated

tamper = input(
    "Do you want to tamper data? y/n: "
)



if tamper == "y":

    tampered = bytearray(
        file_data
    )


    if len(tampered) > 0:

        tampered[0] = tampered[0] ^ 1


    file_data = bytes(
        tampered
    )


    print("data has been tampered")



# server calculates hash again

receiver_hash = sha256_hex(
    file_data
)


print(
    "receiver hash: ",
    receiver_hash
)



# compare hashes

integrity = (
    sender_hash
    == receiver_hash
)


print(
    "integrity: ",
    integrity
)



if integrity:

    print("Integrity Verified")


    # store file only if integrity passed

    with open(
        "received_patient_report.txt",
        "wb"
    ) as file:

        file.write(
            file_data
        )


    print(
        "received file stored successfully"
    )


    conn.sendall(
        b"Integrity Verified"
    )


else:

    print("Integrity Failed")

    print(
        "file not stored because tampering was detected"
    )


    conn.sendall(
        b"Integrity Failed"
    )



conn.close()

server.close()
