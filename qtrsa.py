import os
import base64
import random
import string
import hashlib as hl

import rsa

# ===== CIPHER FUNCTIONS ======
def abash_cipher(text: str, space: list[str] | str):
    """ 
    Flips the characters in a text to their opposite counterparts in a 
    given character space. Characters that are not in the space are ignored.
    """
    return "".join(space[len(space) - space.index(c) - 1] if c in space else c for c in text)

def caesar_cipher(text: str, shift: int, space: list[str] | str, reversed: bool = False):
    """ 
    Shifts the characters by a given number in a given 
    character space. Characters that are not in the space are ignored.
    """
    rot = shift if not reversed else -shift
    return "".join(space[(space.index(c) + rot) % len(space)] if c in space else c for c in text)

def vigenere_cipher(text: str, keyword: str, space: list[str] | str, reversed: bool = False):
    """ 
    Shifts the characters based on the value of a keyword in a 
    character space. Characters that are not in the character space 
    are ignored, and for the keyword it is stripped. 
    """
    key_shifts = [space.index(k) if not reversed else -space.index(k) for k in keyword if k in space]
    if len(key_shifts) == 0:
        return text

    return "".join(space[(space.index(c) + key_shifts[i % len(key_shifts)]) % len(space)] if c in space else c for i, c in enumerate(text))

def generate_otp(size: int, space: list[str] | str):
    """
    Generates a one time pad of a given size from a character space.
    """
    return "".join(random.choices(space, k=size))

def vernam_cipher(text: str, one_time_pad: str, space: list[str] | str):
    """
    XOR-based cipher which XORs a text with a randomly generated 
    one time pad based on their value in a character space. Characters
    that are not in the character space are ignored.
    
    Note: Use this with `generate_otp` function.
    Limitations: Char space must have a length equal to a power of 2, or else an overflow occurs.
    """
    assert len(text) <= len(one_time_pad), "One time pad is smaller than the given text."
    assert len(space) & (len(space) - 1) == 0, "Char space must have a length equal to a power of 2."
    
    return "".join(space[space.index(c) ^ space.index(o)] if c in space and o in space else c for c, o in zip(text, one_time_pad))

# ===== QTRSA FUNCTIONS ======
b64 = list(string.ascii_uppercase) + list(string.ascii_lowercase) + list(string.digits) + ["+", "/"]
non_b64_map = [c for c in string.printable if c not in b64]

def is_b64(s: str):
    try:
        base64.b64decode(s)
        return True
    except:
        return False

def parse_b64(b64_text: str):
    padding_last_idx = b64_text.find("=")
    
    content = b64_text[:padding_last_idx] if padding_last_idx != -1 else b64_text[:]
    padding = b64_text[padding_last_idx:] if padding_last_idx != -1 else ""
    
    return content, padding

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
    caesar_rot = sum(ord(c) for c in transpo_key) % len(b64) 
    otps = []
    
    buckets = [""] * len(transpo_key)
    for i, c in enumerate(plaintext):
        buckets[i % len(transpo_key)] += c
    
    for i, col in enumerate(buckets):
        if i % 4 == 0:
            buckets[i] = abash_cipher(col, b64)
        elif i % 4 == 1:
            buckets[i] = caesar_cipher(col, caesar_rot, b64)
        elif i % 4 == 2:
            buckets[i] = vigenere_cipher(col, vigenere_key_b64, b64)
        elif i % 4 == 3:
            otp = generate_otp(len(col), b64)
            otps.append(otp)

            buckets[i] = vernam_cipher(col, otp, b64)

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
    caesar_rot = sum(ord(c) for c in transpo_key) % len(b64) 

    transposed_parts = [ciphertext[i - len(transpo_key):i] for i in range(len(transpo_key), len(text), len(transpo_key))]
    reversed_transposition = ["".join(col) for col in zip(*transposed_parts)]
    removed_pads = ["".join(c for c in s if c in b64) for s in reversed_transposition]

    reversed_shuffle = sorted(zip(sorted(transpo_key), removed_pads), key=lambda k : transpo_key.index(k[0]))
    buckets = [s for _, s in reversed_shuffle]

    for i, col in enumerate(buckets):
        if i % 4 == 0:
            buckets[i] = abash_cipher(col, b64)
        elif i % 4 == 1:
            buckets[i] = caesar_cipher(col, caesar_rot, b64, reversed=True)
        elif i % 4 == 2:
            buckets[i] = vigenere_cipher(col, vigenere_key_b64, b64, reversed=True)
        elif i % 4 == 3:
            otp, otps = otps[:len(col)], otps[len(col):]
            buckets[i] = vernam_cipher(col, otp, b64)
    
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
