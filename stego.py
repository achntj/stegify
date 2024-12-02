# stego.py
import argparse
from argparse import ArgumentParser
from PIL import Image
from encrypt import encrypt_message, decrypt_message

# Password-Based Key Derivation (PBKDF2)
from hashlib import pbkdf2_hmac
import base64

def derive_key(password, salt='stegano_salt', length=32):
    key = pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, dklen=length)
    return base64.urlsafe_b64encode(key).decode('utf-8')[:length]
########################################

def read_file_content(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def embed_file(img_path, file_path, key, output_path):
    file_data = read_file_content(file_path)
    embed_encrypted_message(img_path, file_data.decode(), key, output_path)

def extract_to_file(img_path, key, output_file):
    extracted_message = extract_and_decrypt_message(img_path, key)
    if extracted_message:
        with open(output_file, 'wb') as file:
            file.write(extracted_message.encode())
        print(f"✅ File extracted successfully to {output_file}")

def check_image_format(img_path):
    valid_formats = ['PNG', 'BMP']
    img = Image.open(img_path)
    if img.format not in valid_formats:
        print(f"❌ Error: Unsupported image format '{img.format}'. Only PNG and BMP are supported.")
        return False
    return True


def embed_encrypted_message(img_path, message, key, output_path):
    if not check_image_format(img_path):
        return
    encrypted_message = encrypt_message(key, message)
    img = Image.open(img_path)
    encoded_img = img.copy()
    width, height = img.size
    
    # add EOF marker
    message_binary = ''.join(format(ord(char), '08b') for char in encrypted_message + '\x1E')
    
    data_index = 0
    for y in range(height):
        for x in range(width):
            pixel = list(encoded_img.getpixel((x, y)))
            for n in range(3):  # Loop through R, G, B channels
                if data_index < len(message_binary):
                    pixel[n] = pixel[n] & ~1 | int(message_binary[data_index])
                    data_index += 1
            encoded_img.putpixel((x, y), tuple(pixel))
            if data_index >= len(message_binary):
                encoded_img.save(output_path)
                print(f"\n✅ Message successfully embedded into {output_path}")
                return
    print("❌ Error: Message is too large to fit in the image.")

def extract_and_decrypt_message(img_path, key):
    if not check_image_format(img_path):
        return None
    img = Image.open(img_path)
    width, height = img.size
    
    binary_message = ""
    for y in range(height):
        for x in range(width):
            pixel = img.getpixel((x, y))
            for n in range(3):
                binary_message += str(pixel[n] & 1)
    
    # stop at EOF marker
    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        char = chr(int(byte, 2))
        if char == '\x1E':  # EOF marker
            break
        message += char
    
    decrypted_message = decrypt_message(key, message)
    return decrypted_message

def main():
    parser = ArgumentParser(description="Steganographic tool for embedding and extracting messages in images.")
    subparsers = parser.add_subparsers(dest="command")
    
    # Embed
    parser_embed = subparsers.add_parser('embed', help='Embed a message or file in an image')
    parser_embed.add_argument('--image', required=True, help='Path to the input image')
    parser_embed.add_argument('--message', help='Message to embed (optional, use with --file)')
    parser_embed.add_argument('--file', help='Path to the file to embed (optional, use with --message)')
    parser_embed.add_argument('--key', required=True, help='Password for encryption (PBKDF2 derived)')
    parser_embed.add_argument('--output', required=True, help='Path to save the output image')
    
    # Extract
    parser_extract = subparsers.add_parser('extract', help='Extract and decrypt a message or file from an image')
    parser_extract.add_argument('--image', required=True, help='Path to the image with hidden message or file')
    parser_extract.add_argument('--key', required=True, help='Password for decryption')
    parser_extract.add_argument('--output_file', help='Path to save extracted file (optional)')

    args = parser.parse_args()
    key = derive_key(args.key)

    if args.command == 'embed':
        if args.file:
            embed_file(args.image, args.file, key, args.output)
        elif args.message:
            embed_encrypted_message(args.image, args.message, key, args.output)
        else:
            print("❌ Error: You must provide either a message or a file to embed.")

    elif args.command == 'extract':
        if args.output_file:
            extract_to_file(args.image, key, args.output_file)
        else:
            decrypted_message = extract_and_decrypt_message(args.image, key)
            if decrypted_message is None:
                print("\n❌ Error: Decryption failed. Please check your key.")
            else:
                print(f"\n🔓 Decrypted message: {decrypted_message}")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

