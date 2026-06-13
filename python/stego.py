#!/usr/bin/env python3

import argparse
import sys
import logging
from pathlib import Path

try:
    from stegano import lsb
    from PIL import Image
except ImportError as e:
    logging.error(f"[ERROR] Failure to import libs: {e}")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s: %(message)s',
    stream=sys.stderr
)

def encode_image(input_path: str, output_path: str, data: bytes) -> None:
    """
    Hides the binary data within the input image and saves in the specified output_path.
    stegano.lsb.hide expects a string, so we convert the bytes into a safe representation using latin-1
    which preserves bytes 0-255. 
    """
    try:
        data_str = data.decode('latin-1')

        img = Image.open(input_path)
        logging.info(f"Original mode is {img.mode}")
        if img.mode != 'RGB':
            logging.info(f"Converting image from [{img.mode}] to RGB...")
            img = img.convert('RGB')

        secret_image = lsb.hide(img, data_str)
        secret_image.save(output_path)
        logging.info(f"[OK] Hid data successfully at {output_path}")
    except Exception as e:
        logging.error(f"[ERROR] Failure at hiding data: {e}")
        sys.exit

def decode_image(input_path: str) -> bytes:
    """
    Extracts hidden data from the image and returns it as bytes.
    """
    try:
        secret_message = lsb.reveal(input_path)
        if secret_message is None:
            logging.error("[ERROR] No hidden data found in the image.")
            sys.exit(1)

        data_bytes = secret_message.encode('latin-1')
        return data_bytes
    except Exception as e:
        logging.error(f"[ERROR] Failure at data extraction: {e}")
        sys.exit(1)
    
def main() -> None:
    parser = argparse.ArgumentParser(description="Steganography bridge for Stegrust")
    parser.add_argument('--encode', action='store_true', help="Encoding Mode: Hides data string")
    parser.add_argument('--decode', action='store_true', help="Decoding mode: Extracts hidden data")
    parser.add_argument('--input', required=True, help="Input image path")
    parser.add_argument('--output', help="Output image path. Required for encoding")

    args = parser.parse_args()

    if args.encode and not args.output:
        logging.error("[ERROR] --output is required for encoding")
        sys.exit(1)
    
    if not args.encode and not args.decode:
        logging.error("[ERROR] Specify between --encode or --decode")
    
    input_path = Path(args.input)
    if not input_path.exists():
        logging.error(f"[ERROR] Input image not found at: {args.input}")
    
    if args.encode:
        # read binary stin data
        data = sys.stdin.buffer.read()
        if not data:
            logging.error("[ERROR] No data was received in STDIN")
            sys.exit(1)

        encode_image(str(input_path), args.output, data)
        print('{"status": "ok"}')

    elif args.decode:
        extracted = decode_image(str(input_path))
        # write out extracted binary data in STDOUT
        sys.stdout.buffer.write(extracted)

if __name__ == "__main__":
    main()