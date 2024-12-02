# **stegify**

`stegify` is a simple command line tool for embedding encrypted messages or files into images using AES encryption. It allows secure communication by hiding data in plain sight, using the concept of [Steganography](https://en.wikipedia.org/wiki/Steganography).

---

### **Features:**

- Embed encrypted messages or small files into images (PNG and BMP formats only).
- Secure decryption with AES encryption, using a password-derived key.
- Support for both message and file embedding.
- Supports password-based key derivation via PBKDF2.

### **Installation:**

- Clone the repository:

   ```bash
   git clone https://github.com/achntj/stegify.git
   cd stegify
   pip install -r requirements.txt
   ```
### **Usage:**

#### Embed a message:

```bash
python stego.py embed --image input.png --message "This is a secret message" --key mySecretPassword --output output.png
```

#### Extract a message:

```bash
python stego.py extract --image output.png --key mySecretPassword
```
#### Embed a file:

```bash
python stego.py embed --image input.png --file secret.txt --key mySecretPassword --output output.png
```

#### Extract to a file:

```bash
python stego.py extract --image output.png --key mySecretPassword --output_file extracted_secret.txt
```

### **Options:**

- `--image`: Path to the input or output image.
- `--message`: Message to embed (use with `--image`).
- `--file`: File to embed (use with `--image`).
- `--key`: Password used for encryption/decryption (PBKDF2-derived AES key).
- `--output`: Path for the output image after embedding the message.
- `--output_file`: Path to save the extracted file.

### TODO

- Data compression before encryption and decompression after extraction.

