import base64
import random
import string
import os
import hashlib as hl

import rsa

b64_map = list(string.ascii_uppercase) + list(string.ascii_lowercase) + list(string.digits) + ["+", "/"]
non_b64_map = [c for c in string.printable if c not in b64_map]

def is_b64(s):
    try:
        base64.b64decode(s)
        return True
    except:
        return False

def parse_b64(b64_text):
    padding_last_idx = b64_text.find("=")
    
    content = b64_text[:padding_last_idx] if padding_last_idx != -1 else b64_text[:]
    padding = b64_text[padding_last_idx:] if padding_last_idx != -1 else ""
    
    return content, padding

def abash_encrypt_b64(text):
    plaintext, padding = parse_b64(text)
    
    encrypted = "".join(b64_map[len(b64_map) - b64_map.index(char) - 1] for char in plaintext) 
    return encrypted + padding

def abash_decrypt_b64(text):
    ciphertext, padding = parse_b64(text)
   
    decrypted = "".join(b64_map[len(b64_map) - b64_map.index(char) - 1] for char in ciphertext) 
    return decrypted + padding

def caesar_encrypt_b64(text, rot):
    plaintext, padding = parse_b64(text)
    
    encrypted = "".join(b64_map[(b64_map.index(char) + rot) % len(b64_map)] for char in plaintext) 
    return encrypted + padding

def caesar_decrypt_b64(text, rot):
    ciphertext, padding = parse_b64(text)
    
    decrypted = "".join(b64_map[(b64_map.index(char) - rot) % len(b64_map)] for char in ciphertext) 
    return decrypted + padding

def vigenere_encrypt_b64(text, key_b64):
    plaintext, padding = parse_b64(text) 
    key, _ = parse_b64(key_b64)    
    
    encrypted = "".join(b64_map[(b64_map.index(char) + b64_map.index(key[i % len(key)])) % len(b64_map)] for i, char in enumerate(plaintext)) 
    return encrypted + padding

def vigenere_decrypt_b64(text, key_b64):
    ciphertext, padding = parse_b64(text) 
    key, _ = parse_b64(key_b64)
    
    decrypted = "".join(b64_map[(b64_map.index(char) - b64_map.index(key[i % len(key)])) % len(b64_map)] for i, char in enumerate(ciphertext)) 
    return decrypted + padding

def vernam_encrypt_b64(text):
    plaintext, padding = parse_b64(text)
    otp = [random.randint(0, len(b64_map) - 1) for _ in range(len(plaintext))] 
    
    encrypted = "".join(b64_map[b64_map.index(char) ^ otp[i]] for i, char in enumerate(plaintext))
    otp_b64 = "".join(b64_map[o] for o in otp)
    
    return encrypted + padding, otp_b64

def vernam_decrypt_b64(text, otp_b64):
    ciphertext, padding = parse_b64(text) 
    
    decrypted = "".join(b64_map[b64_map.index(char) ^ b64_map.index(otp_b64[i])] for i, char in enumerate(ciphertext))
    return decrypted + padding

def qtrsa_encrypt(byte_text, rsa_encryption_key, transpo_key, vigenere_key, encoding = "utf-8"):
    chunk_size = rsa_encryption_key.n.bit_length() // 8  - 11 # 8 -> bits in bytes, 11 -> overhead
    chunks = byte_text[:]
    rsa_encrypted = b''
    while True: 
        chunk_text, chunks = chunks[:chunk_size], chunks[chunk_size:]
        rsa_encrypted += rsa.encrypt(chunk_text, rsa_encryption_key)
        

        if len(chunks) == 0:
            break
    
    b64_content = base64.b64encode(rsa_encrypted).decode(encoding)
    plaintext, padding = parse_b64(b64_content)
    
    vigenere_key_b64 = base64.b64encode(vigenere_key.encode(encoding)).decode(encoding)
    caesar_rot = sum(ord(c) for c in transpo_key) % len(b64_map) 
    otps = []
    
    buckets = [""] * len(transpo_key)
    for i, c in enumerate(plaintext):
        buckets[i % len(transpo_key)] += c
    
    for i, part in enumerate(buckets):
        if i % 4 == 0:
            buckets[i] = abash_encrypt_b64(part)
        elif i % 4 == 1:
            buckets[i] = caesar_encrypt_b64(part, caesar_rot)
        elif i % 4 == 2:
            buckets[i] = vigenere_encrypt_b64(part, vigenere_key_b64)
        elif i % 4 == 3:
            buckets[i], otp = vernam_encrypt_b64(part)
            otps.append(otp)

    transpo_sorted = sorted(zip(transpo_key, buckets), key=lambda k : k[0])
    
    max_len_part = max(len(s) for _, s in transpo_sorted)
    transpo_padded = [s + "".join(random.choice(non_b64_map) for _ in range(max_len_part - len(s))) for _, s in transpo_sorted]
    transposed = ["".join(col) for col in zip(*transpo_padded)]
    
    encrypted = "".join(transposed) + padding
    joined_otps = "".join(otps)
    return encrypted.encode(encoding), joined_otps.encode(encoding)

def qtrsa_decrypt(byte_text, rsa_decryption_key, transpo_key, vigenere_key, one_time_pads, encoding = "utf-8"):
    assert is_b64(byte_text), "Encrypted text is malformed, and can't be decrypted." 
    
    text = byte_text.decode(encoding)
    ciphertext, padding = parse_b64(text)
    vigenere_key_b64 = base64.b64encode(vigenere_key.encode(encoding)).decode(encoding)
    otps = one_time_pads.decode(encoding)
    caesar_rot = sum(ord(c) for c in transpo_key) % len(b64_map) 

    transposed_parts = [ciphertext[i - len(transpo_key):i] for i in range(len(transpo_key), len(text), len(transpo_key))]
    reversed_transposition = ["".join(col) for col in zip(*transposed_parts)]
    removed_pads = ["".join(c for c in s if c in b64_map) for s in reversed_transposition]

    reversed_shuffle = sorted(zip(sorted(transpo_key), removed_pads), key=lambda k : transpo_key.index(k[0]))
    buckets = [s for _, s in reversed_shuffle]

    for i, part in enumerate(buckets):
        if i % 4 == 0:
            buckets[i] = abash_decrypt_b64(part)
        elif i % 4 == 1:
            buckets[i] = caesar_decrypt_b64(part, caesar_rot)
        elif i % 4 == 2:
            buckets[i] = vigenere_decrypt_b64(part, vigenere_key_b64)
        elif i % 4 == 3:
            otp, otps = otps[:len(part)], otps[len(part):]
            buckets[i] = vernam_decrypt_b64(part, otp)
    
    plaintext_b64 = ""
    for i in range(sum(len(part) for part in buckets)):
        plaintext_b64 += buckets[i % len(transpo_key)][i // len(transpo_key)]
    rsa_encrypted_text = base64.b64decode((plaintext_b64 + padding).encode(encoding))
    
    chunk_size = rsa_decryption_key.n.bit_length() // 8 # 8 -> bits in bytes
    chunks = rsa_encrypted_text[:]
    plaintext_bytes = b''
    while True: 
        chunk_text, chunks = chunks[:chunk_size], chunks[chunk_size:]
        plaintext_bytes += rsa.decrypt(chunk_text, rsa_decryption_key)

        if len(chunks) == 0:
            break
    
    return plaintext_bytes

def rinput(prompt):
    user_input = None
    while user_input is None:
        user_input = input(prompt).strip()
        if user_input == '':
            print("Value is required.")
            user_input = None

    return user_input

def cinput(prompt, text_on_fail, accept_if_pred):
    user_input = None
    while user_input is None:
        user_input = input(prompt).strip()
        if user_input == '':
            print("Value is required.")
            user_input = None
        elif not accept_if_pred(user_input):
            print(text_on_fail)
            user_input = None

    return user_input

def main():
    print("===== Cryptography =====")
    print("What do you want to do?")
    print("[1] Encrypt")
    print("[2] Decrypt")
    print("[3] Verify Hash")
    print("[4] Exit")
    
    while True:
        num_choice = input("Choice: ")
        if num_choice.isdigit():
            num_choice = int(num_choice)

        os.system("cls")
        if num_choice == 1:
            plaintext_filename = cinput(f"{'Plaintext Filename':<30}: ", text_on_fail="File does not exist.", accept_if_pred=lambda f : os.path.exists(f))
            
            modulus = None
            while modulus is None:
                modulus = int(cinput(f"{'Key Modulus (>= 1024)':<30}: ", text_on_fail="Modulus must be a number", accept_if_pred=lambda n : n.isdigit()))
                if modulus < 1024 or (modulus & (modulus - 1) != 0):
                    print("Modulus must be greater than 1024 bits, and should be a power of 2")
                    modulus = None
            
            vigenere_key = rinput(f"{'Passkey 1':<30}: ")
            transpo_key = cinput(f"{'Passkey 2 (Unique Chars Only)':<30}: ", text_on_fail="Passkey must have each character repeat only once.", accept_if_pred=lambda s : len(set(s)) == len(s))
           
            output_filename = rinput(f"{'Output Filename':<30}: ")
            d_key_output_filename = rinput(f"{'Decryption Key Filename':<30}: ")
            
            print()
            print("===== Progress =====")
            print(f"{'📖':<2} Extracting contents -> {plaintext_filename}...")
            with open(plaintext_filename, "rb") as plaintext_file:
                plaintext = plaintext_file.read()
       
            print(f"{'🛠':<2}  Generating RSA keys...")
            e_key, d_key = rsa.newkeys(modulus)
            
            print(f"{'🛡':<2}  Encrypting Content...")
            ciphertext, otps = qtrsa_encrypt(
                byte_text=plaintext,
                rsa_encryption_key=e_key,
                transpo_key=transpo_key,
                vigenere_key=vigenere_key,
                encoding="utf-8"
            )
            
            print(f"{'📝':<2} Writing Encrypted Content -> {output_filename}...")
            with open(output_filename, "wb") as output_file:
                output_file.write(ciphertext)
            
            print(f"{'📝':<2} Writing Decryption Key -> {d_key_output_filename}...")
            with open(d_key_output_filename, "wb") as output_file:
                output_file.write(d_key.save_pkcs1())

                encoded_otps = "-----BEGIN OTPS-----\n".encode("utf-8")
                encoded_otps += otps
                encoded_otps += "\n-----END OTPS-----".encode("utf-8")
                output_file.write(encoded_otps)
            
            print(f"{'🧬':<2} Generating Hashes...")
            md5_cipher = hl.md5(ciphertext)
            sha1_cipher = hl.sha1(ciphertext)
            md5_plain = hl.md5(plaintext)
            sha1_plain = hl.sha1(plaintext)

            print(f"{'✅':<2} Successful Encryption!")

            print()
            print("===== Results =====")
            print("# File Summary")
            print(f"{'Encrypted File':<26} -> {output_filename}") 
            print(f"{'Decryption Key File':<26} -> {d_key_output_filename}") 
            
            print()
            print("# Hash Summary")
            print(f"{'Plain -> MD5':<18}:", md5_plain.hexdigest())
            print(f"{'Cipher -> MD5':<18}:", md5_cipher.hexdigest())
            print(f"{'Plain -> SHA1':<18}:", sha1_plain.hexdigest())
            print(f"{'Cipher -> SHA1':<18}:", sha1_cipher.hexdigest())

        elif num_choice == 2:
            ciphertext_filename = cinput(f"{'Ciphertext Filename':<30}: ", text_on_fail="File does not exist.", accept_if_pred=lambda f : os.path.exists(f))
            d_key_filename = cinput(f"{'Decryption Key Filename':<30}: ", text_on_fail="File does not exist.", accept_if_pred=lambda f : os.path.exists(f))
            
            vigenere_key = rinput(f"{'Passkey 1':<30}: ")
            transpo_key = rinput(f"{'Passkey 2':<30}: ")
           
            output_filename = rinput(f"{'Output Filename':<30}: ")
            
            print()
            print("===== Progress =====")
            print(f"{'📖':<2} Extracting contents -> {ciphertext_filename}...")
            with open(ciphertext_filename, "rb") as ciphertext_file:
                ciphertext = ciphertext_file.read()
            
            print(f"{'📖':<2} Parsing Decryption Key -> {d_key_filename}...")
            with open(d_key_filename, "r") as d_key_file:
                key_content = d_key_file.read()
                content = key_content.split("-----BEGIN OTPS-----")
                
                d_key = rsa.PrivateKey.load_pkcs1(content[0].encode("utf-8"))
                otps = content[1].split("\n")[1].encode("utf-8")
            
            print(f"{'💌':<2} Decrypting Content...")
            try:
                plaintext = qtrsa_decrypt(
                    byte_text=ciphertext,
                    rsa_decryption_key=d_key,
                    transpo_key=transpo_key,
                    vigenere_key=vigenere_key,
                    one_time_pads=otps,
                    encoding="utf-8"
                )
            except:
                print(f"{'❌':<2} Decryption Failed!")
            else:
                print(f"{'📝':<2} Writing Decrypted Content -> {output_filename}...")
                with open(output_filename, "wb") as output_file:
                    output_file.write(plaintext)
                
                print(f"{'🧬':<2} Generating Hashes...")
                md5_plain = hl.md5(plaintext)
                sha1_plain = hl.sha1(plaintext)
                md5_cipher = hl.md5(ciphertext)
                sha1_cipher = hl.sha1(ciphertext)

                print(f"{'✅':<2} Successful Decryption!")

                print()
                print("===== Results =====")
                print("# File Summary")
                print(f"{'Decrypted File':<26} -> {output_filename}") 
                
                print()
                print("# Hash Summary")
                print(f"{'Cipher -> MD5':<18}:", md5_cipher.hexdigest())
                print(f"{'Plain -> MD5':<18}:", md5_plain.hexdigest())
                print(f"{'Cipher -> SHA1':<18}:", sha1_cipher.hexdigest())
                print(f"{'Plain -> SHA1':<18}:", sha1_plain.hexdigest())
            
        elif num_choice == 3:
            filename_one = cinput(f"{'Filename 1':<30}: ", text_on_fail="File does not exist.", accept_if_pred=lambda f : os.path.exists(f))
            filename_two = cinput(f"{'Filename 2':<30}: ", text_on_fail="File does not exist.", accept_if_pred=lambda f : os.path.exists(f))
            
            print()
            print("===== Progress =====")
            print(f"{'📖':<2} Extracting contents -> {filename_one}...")
            with open(filename_one, "rb") as file_one:
                file_one_contents = file_one.read()
            
            print(f"{'📖':<2} Extracting contents -> {filename_two}...")
            with open(filename_two, "rb") as file_two:
                file_two_contents = file_two.read()

            print(f"{'🧬':<2} Generating Hashes...")
            md5_f1 = hl.md5(file_one_contents)
            md5_f2 = hl.md5(file_two_contents)
            
            sha1_f1 = hl.sha1(file_one_contents)
            sha1_f2 = hl.sha1(file_two_contents)
            
            sha3_f1 = hl.sha3_256(file_one_contents)
            sha3_f2 = hl.sha3_256(file_two_contents)
            
            sha256_f1 = hl.sha256(file_one_contents)
            sha256_f2 = hl.sha256(file_two_contents)

            print(f"{'✅':<2} Successful Hashing!")
            
            print()
            print("===== Results =====")
            print("MD5", f'[{"MATCHED ✅" if md5_f1.digest() == md5_f2.digest() else "MISMATCH ❌"}]')
            print(f"{filename_one:<18}:", md5_f1.hexdigest())
            print(f"{filename_two:<18}:", md5_f2.hexdigest())
            print()
            
            print("SHA1", f'[{"MATCHED ✅" if sha1_f1.digest() == sha1_f2.digest() else "MISMATCH ❌"}]')
            print(f"{filename_one:<18}:", sha1_f1.hexdigest())
            print(f"{filename_two:<18}:", sha1_f2.hexdigest())
            print()
            
            print("SHA3", f'[{"MATCHED ✅" if sha3_f1.digest() == sha3_f2.digest() else "MISMATCH ❌"}]')
            print(f"{filename_one:<18}:", sha3_f1.hexdigest())
            print(f"{filename_two:<18}:", sha3_f2.hexdigest())
            print()
            
            print("SHA256", f'[{"MATCHED ✅" if sha256_f1.digest() == sha256_f2.digest() else "MISMATCH ❌"}]')
            print(f"{filename_one:<18}:", sha256_f1.hexdigest())
            print(f"{filename_two:<18}:", sha256_f2.hexdigest())
            print()
        
        elif num_choice == 4:
            break

        else:
            print("Invalid value.")
        
        print()
        input("Press Enter to Continue...")
        
        os.system("cls")
        print("===== Cryptography =====")
        print("What do you want to do?")
        print("[1] Encrypt")
        print("[2] Decrypt")
        print("[3] Verify Hash")
        print("[4] Exit")

if __name__ == "__main__":
    main()
