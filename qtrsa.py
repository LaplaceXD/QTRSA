import os
import argparse
import secrets
import string
import base64
import hashlib as hl
from typing import Sequence, TypeVar, Generator, cast

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
    return "".join(secrets.choice(space) for _ in range(size))

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

# ===== QTRSA FUNCTIONS =====
def get_b64_char_space():
    """ Gets a tuple containing the character space of Base64, and the valid characters that are not used in the Base64 space. """
    b64 = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
    b64_with_padding = b64 + "="
    non_b64 = "".join(c for c in string.punctuation if c not in b64_with_padding)

    return b64, non_b64

def parse_b64(b64_text: str):
    """ Parses a Base64 text by splitting its padding and the actual content. """
    padding_last_idx = b64_text.find("=")
    
    content = b64_text[:padding_last_idx] if padding_last_idx != -1 else b64_text
    padding = b64_text[padding_last_idx:] if padding_last_idx != -1 else ""
    
    return content, padding

Sliceable = TypeVar("Sliceable", bound=Sequence)
def cycle_chunks(block: Sliceable, *, size: int, circular: bool = False) -> Generator[Sliceable, None, None]:
    """ 
    Cycles through the contents of an ArrayLike block, and yields a chunk of a given chunk size
    at each cycle.

    Note: If the circular flag is enabled, then it cycles through the block in a circular fashion.
    So, if the current chunk is less than the size, it goes back to the start and appends.
    """
    previous_chunk_end = 0

    while previous_chunk_end < len(block) or circular:
        chunk_end = previous_chunk_end + size 
        chunk = block[previous_chunk_end:chunk_end]
        previous_chunk_end = chunk_end
        
        if circular:
            # Append in circular fashion if desired size is not reached 
            while len(chunk) != size:
                previous_chunk_end = size - len(chunk)
                chunk += block[:previous_chunk_end] # pyright: ignore [reportGeneralTypeIssues]
            
        yield cast(Sliceable, chunk)

def qtrsa_encrypt(plaintext: bytes, rsa_encryption_key: rsa.PublicKey, passkey: str, uniquekey: str, encoding: str = "utf-8"):
    """ Encrypt a given text with QTRSA encryption. """
    b64, non_b64 = get_b64_char_space() 

    # Encrypt the text first in RSA, and then encode it to Base64
    chunk_size = rsa_encryption_key.n.bit_length() // 8 - 11 # in bytes, the 11 is the header length of RSA in bytes
    rsa_cipher = b"".join(rsa.encrypt(c, rsa_encryption_key) for c in cycle_chunks(plaintext, size=chunk_size))
    encoded_text, padding = parse_b64(base64.b64encode(rsa_cipher).decode(encoding))

    # Pad the text, so it gets split into equal length columns during the Transposition Cipher
    padding_length = len(uniquekey) - len(encoded_text) % len(uniquekey)
    padded_text = encoded_text + "".join(secrets.choice(non_b64) for _ in range(padding_length))
    
    # Build the keys for Vernam, Caesar, and Vigenere
    one_time_pads = ""
    rot = sum(ord(c) for c in uniquekey + passkey) % len(b64) 
    b64_pass_key = base64.b64encode(passkey.encode(encoding)).decode(encoding)
    truncated_pass_key = cycle_chunks(b64_pass_key, size=len(uniquekey), circular=True) 
    
    # Build the rows of the Transposition Cipher, and cipher each row differently
    rows = [row for row in cycle_chunks(padded_text, size=len(uniquekey))]
    for i, row in enumerate(rows):
        if   i % 4 == 0:
            rows[i] = abash_cipher(row, b64)
        elif i % 4 == 1:
            rows[i] = caesar_cipher(row, rot, b64)
        elif i % 4 == 2:
            rows[i] = vigenere_cipher(row, next(truncated_pass_key), b64)
        elif i % 4 == 3:
            otp = generate_otp(len(row), b64)
            rows[i] = vernam_cipher(row, otp, b64)
            one_time_pads += otp

    # Transpose the rows, and finish the Transposition Cipher by sorting the columns by the key
    sorted_key_column_pairs = sorted(zip(uniquekey, *rows), key=lambda pairs : pairs[0])
    
    # Read the text by columns to build the ciphertext
    ciphertext = "".join("".join(column[1:]) for column in sorted_key_column_pairs) + padding
    return ciphertext.encode(encoding), base64.b64encode(one_time_pads.encode(encoding))

def qtrsa_decrypt(ciphertext: bytes, rsa_decryption_key: rsa.PrivateKey, passkey: str, uniquekey: str, otp: bytes, encoding = "utf-8"):
    """ Decrypt a given text that was encrypted with QTRSA encryption. """
    b64, non_b64 = get_b64_char_space() 

    # Parse the Base64 ciphertext and regenerate the columns of the Transposition Cipher
    decoded_text, padding = parse_b64(ciphertext.decode(encoding))
    sorted_columns = [column for column in cycle_chunks(decoded_text, size=len(decoded_text) // len(uniquekey))]
    
    # Unsort the columns of the Transposition Cipher by using the unique key
    unsorted_columns = sorted(zip(sorted(uniquekey), sorted_columns), key=lambda pairs : uniquekey.index(pairs[0]))
    columns = [column for _, column in unsorted_columns]
    
    # Build the Keys for Vernam, Caesar, and Vigenere
    one_time_pads = base64.b64decode(otp).decode(encoding)
    rot = sum(ord(c) for c in uniquekey + passkey) % len(b64) 
    b64_pass_key = base64.b64encode(passkey.encode(encoding)).decode(encoding)
    truncated_pass_key = cycle_chunks(b64_pass_key, size=len(uniquekey), circular=True) 
    
    # Transpose the columns into rows, and reverse the cipher on each row
    rows = ["".join(row) for row in zip(*columns)]
    for i, row in enumerate(rows):
        if   i % 4 == 0:
            rows[i] = abash_cipher(row, b64)
        elif i % 4 == 1:
            rows[i] = caesar_cipher(row, rot, b64, reversed=True)
        elif i % 4 == 2:
            rows[i] = vigenere_cipher(row, next(truncated_pass_key), b64, reversed=True)
        elif i % 4 == 3:
            row_otp, one_time_pads = one_time_pads[:len(row)], one_time_pads[len(row):]
            rows[i] = vernam_cipher(row, row_otp, b64)
    
    # Regenerate the RSA encrypted text by reading the rows and stripping the non-Base64 padding characters
    encoded_rsa_encrypted_text = "".join("".join(c for c in row if c not in non_b64) for row in rows) + padding

    # Reverse the encoding, and decrypt the RSA layer
    rsa_encrypted_text = base64.b64decode(encoded_rsa_encrypted_text.encode(encoding))
    chunk_size = rsa_decryption_key.n.bit_length() // 8 # in bytes
    plaintext = b"".join(rsa.decrypt(c, rsa_decryption_key) for c in cycle_chunks(rsa_encrypted_text, size=chunk_size))
   
    return plaintext

# ===== VIEWS AND HANDLERS =====
def qtrsa_encrypt_file(filename: str, modulus: int, passkey: str, uniquekey: str, output: str, keyname: str):
    print(f"📖 Extracting contents...       <- {filename}")
    with open(filename, "rb") as file:
        plaintext = file.read()

    print("🛠  Generating RSA keys...")
    e_key, d_key = rsa.newkeys(modulus)
    
    print("🛡  Encrypting Content...")
    ciphertext, otp = qtrsa_encrypt(
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
        split_key = d_key.save_pkcs1().split(b"\n")
        otp = b"\n".join(otp[start:start+64] for start in range(0, len(otp), 64))
        otp = b"\xe2\x80\x8b" + otp + b"\xe2\x80\x8b"
        split_key.insert(-2, otp)

        key_file.write(b"\n".join(split_key))
    
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

def qtrsa_decrypt_file(filename: str, keyname: str, passkey: str, uniquekey: str, output: str):
    print(f"📖 Extracting contents...       <- {filename}")
    with open(filename, "rb") as file:
        ciphertext = file.read()

    print(f"📖 Parsing Decryption Key...    <- {keyname}")
    with open(keyname, "rb") as key_file:
        keys = key_file.read().split(b"\xe2\x80\x8b")

        d_key = rsa.PrivateKey.load_pkcs1(keys[0] + keys[2])
        otp = keys[1].replace(b"\n", b"")

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

    print(f"📝 Writing Decrypted Content... -> {output}")
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
        print(f"📖 Extracting contents and generating hashes... <- {filename}")
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
        
        if not os.path.exists(args.keyname):
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
            keyname=args.keyname,
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
