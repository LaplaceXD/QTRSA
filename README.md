# Quad-Transpositional RSA (QTRSA) Encryption Algrithm

Quad-Transpositional RSA (QTRSA) is a modified [Rivet-Shamir-Aldeman (RSA)](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) encryption algorithm that utilizes a cipher-mixing layer. The cipher-mixing layer is a combination of four different ciphers ([Vernam](https://www.cryptomuseum.com/crypto/vernam.htm), [Vigenère](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher), [Caesar](https://en.wikipedia.org/wiki/Caesar_cipher), and [Atbash](https://en.wikipedia.org/wiki/Atbash)) from three different cipher types (monoalphabetic, polyalphabetic, and XOR-based cipher). These are concealed within the rows of a [Columnar Transposition Cipher](https://en.wikipedia.org/wiki/Transposition_cipher#Columnar_transposition) before the cipher is read column-wise. This algorithm results in an encryption that requires four keys to decrypt it. These keys are the following: 
- a passphrase for [Vigenère](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher), 
- a unique passphrase containing no-repeating characters for the [Columnar Transposition](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher), 
- a [one-time pad](https://en.wikipedia.org/wiki/One-time_pad) for [Vernam](https://www.cryptomuseum.com/crypto/vernam.htm), and 
- the decryption key for [RSA](https://en.wikipedia.org/wiki/RSA_(cryptosystem)).

> As a side note, this project was built in partial fulfillment for my course `CS3106 - Information Assurance and Security`. This course tackles concepts about cybersecurity, network security, digital forensics, and cryptography.

## Setup
**Prerequisites:** Make sure you have [`Python`](https://www.python.org/downloads/), and the [rsa](https://pypi.org/project/rsa/) `python` library installed. The latter can be installed via [`pip`](https://pypi.org/project/pip/) by using the command `pip install rsa`.

1. Clone this repository.
2. `cd` into the cloned repository.
3. Read up the [Usage](https://github.com/LaplaceXD/QTRSA?tab=readme-ov-file#usage) section to know how to use the program. 

## Usage
The CLI program is built with three subcommands - `encrypt`, `decrypt`, and `verify`. If you want to test out these commands, you can use your own file or the [sample file](https://github.com/LaplaceXD/QTRSA/blob/master/bee-movie.txt) provided above which is the entire [Bee Movie](https://en.wikipedia.org/wiki/Bee_Movie) script.

### Encrypt
The `encrypt` subcommand is used to encrypt a given file with QTRSA.

```bash
py qtrsa.py encrypt [-h] <file> \
    --passkey <passphrase> \
    --uniquekey <uniquephrase> \
    [--modulus <size>] \
    [--keyname <filename>] \
    [--output <filename>]
```

**Required Arguments**
- `<file>`  The name of the file to be encrypted. 
- `--passkey -p` Any passphrase of any length can work here. 
- `--uniquekey -u`  Another passphrase but this time it must contain no-repeating characters.

**Optional Arguments**
- `--keyname -k`  The name of the file where the decryption key is to be outputted (defaults to `[filename].key.pem`).
- `--output -o`  The name of the output file. (defaults to `[filename].encrypted.[ext]`)

**Example Usage**

```bash
py qtrsa.py encrypt bee-movie.txt \
    -p '^^This%Is$A#Very@Strong!Password@@!#' \
    -u 'Champion@!'
```

This encrypts the [sample file](https://github.com/LaplaceXD/QTRSA/blob/master/bee-movie.txt).

### Decypt
The `decrypt` subcommand is used to decrypt a QTRSA encrypted file.

```bash
py qtrsa.py decrypt [-h] <file> \
    --passkey <passphrase> \
    --uniquekey <uniquephrase> \
    --keyname <filename> \
    [--output <filename>]
```

**Required Arguments**
- `<file>`  The name of the QTRSA encrypted file to be decrypted. 
- `--passkey -p` The passphrase used to encrypt the file. 
- `--uniquekey -u`  The unique passphrase used to encrypt the file.
- `--keyname -k`  The filename of the decryption key.

**Optional Arguments**
- `--output -o`  The name of the output file. (defaults to `[filename].decrypted.[ext]`)

**Example Usage**

```bash
py qtrsa.py decrypt bee-movie.encrypted.txt \
    -p '^^This%Is$A#Very@Strong!Password@@!#' \
    -u 'Champion@!' \
    -k bee-movie.key.pem
```

This decryptes the encrypted [sample file](https://github.com/LaplaceXD/QTRSA/blob/master/bee-movie.txt), if it exists.

### Verify
The `verify` subcommand is used to verify the hash values of files. This can be used to get the hash of any number of files, and their hashes are compared to the first file supplied to the command. This is used to verify whether the encryption algorithm successfully decrypted the ciphertext back to its plaintext version without any alterations.

```bash
py qtrsa.py [-h] [files ...]
```
**Required Arguments**
- `[files ...]` These takes any number of files that you want to hash. The first file on this list will be used as the basis, and every other files' hash will be compared to it.

**Example Usage**

```bash
py qtrsa.py verify bee-movie.txt bee-movie.decrypted.txt
```

This compares the hash values of the decrypted [sample file](https://github.com/LaplaceXD/QTRSA/blob/master/bee-movie.txt) and the actual [sample file](https://github.com/LaplaceXD/QTRSA/blob/master/bee-movie.txt) itself.

## Contributing

Unfortunately, I am not accepting pull requests, since this is a one-time project. However, feel free to fork this project, and improve on it!

## License

[MIT](https://github.com/LaplaceXD/QTRSA/blob/master/LICENSE)
