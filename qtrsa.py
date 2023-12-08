import os
import argparse
import random
import string
import base64
import hashlib as hl

import rsa

# ===== CIPHER FUNCTIONS =====
def abash_cipher(text: str, space: list[str] | str):
    """ 
    Flips the characters in a text to their opposite counterparts in a 
    given character space. Characters that are not in the space are ignored.
    """
    return "".join(space[len(space) - space.index(c) - 1] if c in space else c for c in text)

def caesar_cipher(text: str, rot: int, space: list[str] | str, reversed: bool = False):
    """ 
    Rotates a given set of characters by a given number in a given 
    character space. Characters that are not in the space are ignored.
    """
    rot = rot if not reversed else -rot
    return "".join(space[(space.index(c) + rot) % len(space)] if c in space else c for c in text)

def vigenere_cipher(text: str, keyword: str, space: list[str] | str, reversed: bool = False):
    """ 
    Rotates a given set of characters based on the value of a keyword in a 
    character space. Characters that are not in the character space 
    are ignored, and for the keyword it is stripped. 
    """
    key_rots = [space.index(k) if not reversed else -space.index(k) for k in keyword if k in space]
    if len(key_rots) == 0:
        return text

    return "".join(space[(space.index(c) + key_rots[i % len(key_rots)]) % len(space)] if c in space else c for i, c in enumerate(text))

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

# ===== RSA FUNCTIONS =====
def rsa_encrypt(plaintext: bytes, encryption_key: rsa.PublicKey):
    """ Encrypts text of any length with RSA encryption. """
    header_length = 11 # in bytes
    chunk_size = encryption_key.n.bit_length() // 8 - header_length # in bytes
    chunks = plaintext[:]

    cipher = b""
    while True:
        chunk, chunks = chunks[:chunk_size], chunks[chunk_size:]
        cipher += rsa.encrypt(chunk, encryption_key)
        if len(chunks) == 0: break

    return cipher

def rsa_decrypt(ciphertext: bytes, decryption_key: rsa.PrivateKey):
    """ Decrypts text of any length that was encrypted with RSA encryption. """
    chunk_size = decryption_key.n.bit_length() // 8 # in bytes
    chunks = ciphertext[:]
    
    plain = b""
    while True: 
        chunk, chunks = chunks[:chunk_size], chunks[chunk_size:]
        plain += rsa.decrypt(chunk, decryption_key)
        if len(chunks) == 0: break

    return plain

# ===== QTRSA FUNCTIONS =====
def get_b64_chars():
    """ Gets the characters used in Base64 Encoding. """
    return string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/" 

def parse_b64(b64_text: str):
    """ Parses a Base64 text by splitting its padding and the actual content. """
    padding_last_idx = b64_text.find("=")
    
    content = b64_text[:padding_last_idx] if padding_last_idx != -1 else b64_text
    padding = b64_text[padding_last_idx:] if padding_last_idx != -1 else ""
    
    return content, padding

def qtrsa_encrypt(plaintext: bytes, rsa_encryption_key: rsa.PublicKey, passkey: str, uniquekey: str, encoding: str = "utf-8"):
    """ Encrypt a given text with Quad-Transpositional RSA encryption. """
    b64 = get_b64_chars() 
    non_b64 = [c for c in string.printable if c not in b64]
     
    # Encrypt the text first in RSA, and then encode it to Base64
    rsa_cipher = rsa_encrypt(plaintext, rsa_encryption_key)
    encoded_text, padding = parse_b64(base64.b64encode(rsa_cipher).decode(encoding))
    
    # Build the keys for Vernam, Caesar, and Vigenere
    one_time_pads = ""
    rot = sum(ord(c) for c in uniquekey + passkey) % len(b64) 
    encoded_pass_key = base64.b64encode(passkey.encode(encoding)).decode(encoding)
    
    # Build the columns of the Transposition Cipher, and let each column go through a different cipher
    skips = len(uniquekey)
    columns = ["".join(encoded_text[start_skip::skips]) for start_skip in range(skips)]
    
    for i, col in enumerate(columns):
        if   i % 4 == 0:
            columns[i] = abash_cipher(col, b64)
        elif i % 4 == 1:
            columns[i] = caesar_cipher(col, rot, b64)
        elif i % 4 == 2:
            columns[i] = vigenere_cipher(col, encoded_pass_key, b64)
        elif i % 4 == 3:
            otp = generate_otp(len(col), b64)
            columns[i] = vernam_cipher(col, otp, b64)
            one_time_pads += otp
    
    # Pad the columns with non Base64 characters so they are of equal length
    max_column_length = max(len(column) for column in columns)
    padded_columns = [column.ljust(max_column_length, random.choice(non_b64)) for column in columns]
    
    # Finish the Transposition Cipher by sorting the columns by the key
    sorted_key_column_pairs = sorted(zip(uniquekey, padded_columns), key=lambda pairs : pairs[0])
    
    # Modified Step for Transposition Cipher read the end by row instead of column to mix the ciphers
    ciphertext = "".join("".join(row) for row in zip(*(column for _, column in sorted_key_column_pairs))) + padding
    return ciphertext.encode(encoding), base64.b64encode(one_time_pads.encode(encoding))

def qtrsa_decrypt(ciphertext: bytes, rsa_decryption_key: rsa.PrivateKey, passkey: str, uniquekey: str, otp: bytes, encoding = "utf-8"):
    """ Decrypt a text that was encrypted Quad-Transpositional RSA encryption. """
    b64 = get_b64_chars()
    encoded_text, padding = parse_b64(ciphertext.decode(encoding))
    
    # Build the Keys for Vernam, Caesar, and Vigenere
    one_time_pads = base64.b64decode(otp).decode(encoding)
    rot = sum(ord(c) for c in uniquekey + passkey) % len(b64) 
    encoded_pass_key = base64.b64encode(passkey.encode(encoding)).decode(encoding)
    
    # Regenerate the columns of the Transposition Cipher
    skips = len(uniquekey)
    sorted_columns = ["".join(encoded_text[start_skip::skips]) for start_skip in range(skips)]
    
    # Remove the padding from the columns
    unpadded_columns = ["".join(c for c in column if c in b64) for column in sorted_columns]
    
    # Unsort the columns of the Transposition Cipher by using the unique key
    unsorted_columns = sorted(zip(sorted(uniquekey), unpadded_columns), key=lambda pairs : uniquekey.index(pairs[0]))
    columns = [column for _, column in unsorted_columns]
    
    # Reverse the cipher performed on each column
    for i, col in enumerate(columns):
        if   i % 4 == 0:
            columns[i] = abash_cipher(col, b64)
        elif i % 4 == 1:
            columns[i] = caesar_cipher(col, rot, b64, reversed=True)
        elif i % 4 == 2:
            columns[i] = vigenere_cipher(col, encoded_pass_key, b64, reversed=True)
        elif i % 4 == 3:
            col_otp, one_time_pads = one_time_pads[:len(col)], one_time_pads[len(col):]
            columns[i] = vernam_cipher(col, col_otp, b64)
    
    # Regenerate the RSA encrypted text by reading the columns row-wise
    max_column_length = max(len(column) for column in columns)
    space_padded_columns = [column.ljust(max_column_length) for column in columns]
    encoded_rsa_encrypted_text = "".join("".join(row) for row in zip(*space_padded_columns))
    encoded_rsa_encrypted_text = encoded_rsa_encrypted_text.strip() + padding

    # Reverse the encoding, and decrypt the RSA layer
    rsa_encrypted_text = base64.b64decode(encoded_rsa_encrypted_text.encode(encoding))
    plaintext = rsa_decrypt(rsa_encrypted_text, rsa_decryption_key)
   
    return plaintext

# ===== VIEWS AND HANDLERS =====
def qtrsa_encrypt_file(filename: str, modulus: int, passkey: str, uniquekey: str, output: str, keyname: str):
    print(f"📖 Extracting contents...       <- {filename}")
    with open(filename, "rb") as file:
        plaintext = file.read()

    print("🛠  Generating RSA keys...")
    e_key, d_key = rsa.newkeys(modulus)
    
    print("🛡  Encrypting Content...")
    ciphertext, one_time_pads = qtrsa_encrypt(
        plaintext=plaintext,
        rsa_encryption_key=e_key,
        passkey=passkey,
        uniquekey=uniquekey,
        encoding="utf-8"
    )
    
    print(f"📝 Writing Encrypted Content... -> {output}")
    with open(output, "wb") as output_file:
        output_file.write(ciphertext)
    
    print(f"📝 Writing Decryption Key...    -> {keyname}")
    with open(keyname, "wb") as key_file:
        key_file.write(d_key.save_pkcs1())

        encoded_otps = "-----BEGIN OTPS-----\n".encode("utf-8")
        encoded_otps += one_time_pads
        encoded_otps += "\n-----END OTPS-----".encode("utf-8")
        key_file.write(encoded_otps)
    
    print("🧬 Generating Hashes...")
    md5_plain = hl.md5(plaintext)
    sha1_plain = hl.sha1(plaintext)
    md5_cipher = hl.md5(ciphertext)
    sha1_cipher = hl.sha1(ciphertext)

    print("✅ Successful Encryption!")

    print()
    print("===== Results =====")
    print("# File Summary")
    print(f"Encrypted File         -> {output}") 
    print(f"Decryption Key File    -> {keyname}") 
    
    print()
    print("# Hash Summary")
    print("-- Plain --")
    print("MD5    :", md5_plain.hexdigest())
    print("SHA1   :", sha1_plain.hexdigest())
    print("-- Cipher --")
    print("MD5    :", md5_cipher.hexdigest())
    print("SHA1   :", sha1_cipher.hexdigest())

def qtrsa_decrypt_file(filename: str, filekey: str, passkey: str, uniquekey: str, output: str):
    print(f"📖 Extracting contents...    -> {filename}")
    with open(filename, "rb") as file:
        ciphertext = file.read()

    print(f"📖 Parsing Decryption Key... -> {filekey}")
    with open(filekey, "r") as key_file:
        content = key_file.read().split("-----BEGIN OTPS-----")
        
        d_key = rsa.PrivateKey.load_pkcs1(content[0].encode("utf-8"))
        otp = content[1].split("\n")[1].encode("utf-8")

    print("💌 Decrypting Content...")
    try:
        plaintext = qtrsa_decrypt(
            ciphertext=ciphertext,
            rsa_decryption_key=d_key,
            passkey=passkey,
            uniquekey=uniquekey,
            otp=otp,
            encoding="utf-8"
        )
    except:
        print(f"❌ Decryption Failed!")
        return

    print(f"📝 Writing Decrypted Content -> {output}...")
    with open(output, "wb") as output_file:
        output_file.write(plaintext)
    
    print(f"🧬 Generating Hashes...")
    md5_plain = hl.md5(plaintext)
    sha1_plain = hl.sha1(plaintext)
    md5_cipher = hl.md5(ciphertext)
    sha1_cipher = hl.sha1(ciphertext)

    print(f"✅ Successful Decryption!")

    print()
    print("===== Results =====")
    print("# File Summary")
    print(f"Decrypted File -> {output}") 
    
    print()
    print("# Hash Summary")
    print("-- Plain --")
    print("MD5    :", md5_plain.hexdigest())
    print("SHA1   :", sha1_plain.hexdigest())
    print("-- Cipher --")
    print("MD5    :", md5_cipher.hexdigest())
    print("SHA1   :", sha1_cipher.hexdigest())

def verify_file_hashes(files: list[str]):
    hash_functions = { "md5": hl.md5, "sha1": hl.sha1, "sha3": hl.sha3_256, "sha256": hl.sha256 }
    
    hash_results = []
    for filename in files:
        print(f"📖 Extracting contents and generating hashes... -> {filename}")
        with open(filename, "rb") as file:
            content = file.read()
            hashes = { k: h(content).hexdigest() for k, h in hash_functions.items() }
            hash_results.append((filename, hashes))
    
    print("✅ Successful Hashing!")
    
    print()
    print("===== Results =====")
    basis_name, basis_result = hash_results.pop(0)
    print(f"-- {basis_name} (Basis) --")
    print(*(f"{name:<8}: {res:<64}" for name, res in basis_result.items()), sep="\n")
   
    print()
    for filename, hashes in hash_results:
        print(f"-- {filename} --")
        print(*(f"{name:<8}: {res:<64} [{'✅ MATCH' if basis_result[name] == res else '❌ MISMATCH'}]" for name, res in hashes.items()), sep="\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="qtrsa",
        description="""
        CLI for encrypting and decrypting files with 
        Quad-Transposition RSA (QTRSA) encryption algorithm.
        """,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=True,
        epilog="Created by Jonh Alexis Buot (github.com/LaplaceXD)."
    )
    
    subparsers = parser.add_subparsers(title="What would you like to do?", dest="action", description="Choose an action to perform.")
    
    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a file.")
    encrypt_parser.add_argument("file", metavar="<file>", help="Filename of the file to be encrypted.") 
    encrypt_parser.add_argument("--modulus", "-m", metavar="<size>", type=int, default=1024, help="Modulus / size of the key. (default: 1024)") 
    encrypt_parser.add_argument("--passkey", "-p", metavar="<passphrase>", required=True, help="Passphrase.") 
    encrypt_parser.add_argument("--uniquekey", "-u", metavar="<uniquephrase>", required=True, help="Passphare with no-repeating characters.") 
    encrypt_parser.add_argument("--keyname", "-k", metavar="<filename>", help="Output name of the decryption key (default: [filename].key.pem)") 
    encrypt_parser.add_argument("--output", "-o", metavar="<filename>", help="Output name of the file (default: [filename].encrypted.[ext])") 
    
    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a file.")
    decrypt_parser.add_argument("file", metavar="<file>", help="Filename of the file to be decrypted.") 
    decrypt_parser.add_argument("--passkey", "-p", metavar="<passphrase>", required=True, help="Passphrase.") 
    decrypt_parser.add_argument("--uniquekey", "-u", metavar="<uniquephrase>", required=True, help="Passphare with no-repeating characters.") 
    decrypt_parser.add_argument("--keyname", "-k", metavar="<filename>", required=True, help="Filename of the decryption key.") 
    decrypt_parser.add_argument("--output", "-o", metavar="<filename>", help="Output name of the file (default: [filename].decrypted.[ext])") 
    
    verify_parser = subparsers.add_parser("verify", help="Verify and compare the hash signatures of two files.")
    verify_parser.add_argument("files", nargs="*", help="A list of filenames to compare hash against. The first file will be used as basis.") 
    
    args = parser.parse_args()
    
    if args.action == "encrypt":
        errors = []
       
        # Validations
        if not os.path.exists(args.file):
            errors.append("qtrsa encrypt: error: File does not exist.")
        
        if not args.uniquekey:
            errors.append("qtrsa encrypt: error: Unique key must have a non-empty argument.")
        elif len(set(args.uniquekey)) != len(args.uniquekey):
            errors.append("qtrsa encrypt: error: Unique key must be a passphrase containing no repeating characters.")
        
        if not args.passkey:
            errors.append("qtrsa encrypt: error: Pass key must have a non-empty argument.")
        
        if args.modulus < 512 or (args.modulus & (args.modulus - 1) != 0):
            errors.append("qtrsa encrypt: error: Modulus must be greater than or equal to 512 bits, and should be a power of 2.")
        
        if len(errors) != 0:
            print(*errors, sep="\n", end="\n\n")
            encrypt_parser.print_help()
            exit(1)
        
        # Defaults
        if not args.output:
            split_file = args.file.split(".")
            split_file.insert(-1, "encrypted")
            args.output = ".".join(split_file)

        if not args.keyname:
            split_file = args.file.split(".")
            split_file.insert(-1, "key")
            split_file.insert(-1, "pem")
            args.keyname = ".".join(split_file[:-1])
        
        qtrsa_encrypt_file(
            filename=args.file,
            modulus=args.modulus,
            passkey=args.passkey,
            uniquekey=args.uniquekey,
            output=args.output,
            keyname=args.keyname
        )
    elif args.action == "decrypt":
        errors = []
       
        # Validations
        if not os.path.exists(args.file):
            errors.append("qtrsa encrypt: error: File does not exist.")
        
        if not os.path.exists(args.filekey):
            errors.append("qtrsa encrypt: error: File Key does not exist.")
        
        if not args.uniquekey:
            errors.append("qtrsa encrypt: error: Unique key must have a non-empty argument.")
        
        if not args.passkey:
            errors.append("qtrsa encrypt: error: Pass key must have a non-empty argument.")

        if len(errors) != 0:
            print(*errors, sep="\n", end="\n\n")
            decrypt_parser.print_help()
            exit(1)
        
        # Defaults
        if not args.output:
            split_file = args.file.replace(".encrypted", "").split(".")
            split_file.insert(-1, "decrypted")
            args.output = ".".join(split_file)

        qtrsa_decrypt_file(
            filename=args.file,
            passkey=args.passkey,
            uniquekey=args.uniquekey,
            filekey=args.filekey,
            output=args.output
        )
    elif args.action == "verify":
        errors = []
        if len(args.files) <= 1:
            errors.append("qtrsa encrypt: error: File list must at least have 2 filenames.")
        
        for filename in args.files:
            if not os.path.exists(filename):
                errors.append(f"qtrsa encrypt: error: The file named {filename} does not exist.")
        
        if len(errors) != 0:
            print(*errors, sep="\n", end="\n\n")
            verify_parser.print_help()
            exit(1)
        
        verify_file_hashes(files=args.files)
    else:
        parser.print_help()
