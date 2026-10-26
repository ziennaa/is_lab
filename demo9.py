from Crypto.PublicKey import RSA

def rsa_generate(bits=2048):
    private_key = RSA.generate(bits)
    public_key = private_key.publickey()
    return public_key, private_key

def rsa_textbook_multiply(c1, c2, n):
    return (c1 * c2) % n

rpu, rpr = rsa_generate(2048)
n = rpu.n 
e = rpu.e
d = rpr.d

while True:
    print("\n===== RSA BOX COST SYSTEM =====")  # Display menu heading.
    print("1. Enter inputs and perform encrypted multiplication")  # Option 1.
    print("2. Display RSA parameters")  # Option 2.
    print("3. Exit")  # Option 3.
    cho = input("Enter choice: ")  # Read user's menu choice.
    if cho == "1":  # Perform RSA homomorphic multiplication.
        boxes = int(input("Enter number of boxes: "))  # Read number of boxes.
        cost = int(input("Enter cost of each box: "))  # Read cost of each box.
        c1 = pow(boxes, e, n)  # Encrypt boxes: C1 = boxes^e mod N.
        c2 = pow(cost, e, n)  # Encrypt cost: C2 = cost^e mod N.
        print("Encrypted number of boxes:", c1)  # Display first ciphertext.
        print("Encrypted cost per box:", c2)  # Display second ciphertext.
        encrypted_product = rsa_textbook_multiply(c1, c2, n)  # Calculate (C1 * C2) mod N.
        # Multiply the ciphertexts without decrypting them.
        print("Encrypted product:", encrypted_product)  # Display encrypted multiplication result.
        decrypted_product = pow(encrypted_product, d, n)  # Decrypt: M = C^d mod N.
        expected_product = (boxes * cost) % n  # Calculate expected result modulo N.
        print("Decrypted product:", decrypted_product)  # Display decrypted result.
        print("Expected product modulo N:", expected_product)  # Display expected result.
        if decrypted_product == expected_product:  # Compare decrypted and expected results.
            print("VERIFIED! Products match.")  # Multiplicative property verified.

        else:  # Execute if products do not match.
            print("FAILED! Products do not match.")  # Display verification failure.
    elif cho == "2":  # Display RSA public parameters.

        print("RSA Modulus (n):", n)  # Display modulus N.
        print("Public Exponent (e):", e)  # Display public exponent e.

    elif cho == "3":  # Exit the program.

        print("Exiting...")  # Display exit message.
        break  # Stop the while loop.

    else:  # Handle invalid menu choices.
        print("Invalid choice!")  # Ask user to enter a valid option.

