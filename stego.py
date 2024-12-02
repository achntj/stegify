# stego.py
import argparse
from PIL import Image
from encrypt import encrypt_message, decrypt_message

# Password-Based Key Derivation (PBKDF2)
from hashlib import pbkdf2_hmac
import base64

def derive_key(password, salt='stegano_salt', length=32):
    key = pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, dklen=length)
    return base64.urlsafe_b64encode(key).decode('utf-8')[:length]
########################################

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
    
    # Convert binary to characters, stopping at EOF marker
    message = ""
    for i in range(0, len(binary_message), 8):
        byte = binary_message[i:i+8]
        char = chr(int(byte, 2))
        if char == '\x1E':  # EOF marker
            break
        message += char
    
    # Decrypt the extracted message
    decrypted_message = decrypt_message(key, message)
    if decrypted_message is None:
        print("\n❌ Error: Decryption failed. Please check your key.")
    else:
        print(f"\n🔓 Decrypted message: {decrypted_message}")

def main():
    parser = argparse.ArgumentParser(description="Steganography Tool to Embed and Extract Encrypted Messages in Images")
    subparsers = parser.add_subparsers(dest='command', help='Commands: embed or extract')

    # Embed
    parser_embed = subparsers.add_parser('embed', help='Embed an encrypted message into an image')
    parser_embed.add_argument('image', help='Path to the input image')
    parser_embed.add_argument('message', help='Message to embed')
    parser_embed.add_argument('key', help='Encryption key (16, 24, or 32 characters)')
    parser_embed.add_argument('output', help='Path to the output image')

    # Extract
    parser_extract = subparsers.add_parser('extract', help='Extract and decrypt a message from an image')
    parser_extract.add_argument('image', help='Path to the image with hidden message')
    parser_extract.add_argument('key', help='Decryption key (same as used for embedding)')

    args = parser.parse_args()
    key = derive_key(args.key)

    if args.command == 'embed':
        if len(key) not in [16, 24, 32]:
            print("❌ Error: The encryption key must be 16, 24, or 32 characters long.")
            return
        embed_encrypted_message(args.image, args.message, key, args.output)

    elif args.command == 'extract':
        if len(key) not in [16, 24, 32]:
            print("❌ Error: The decryption key must be 16, 24, or 32 characters long.")
            return
        decrypted_message = extract_and_decrypt_message(args.image, key)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()

