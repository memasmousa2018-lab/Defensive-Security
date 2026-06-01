from PIL import Image
import numpy as np

def text_to_bits(text):
    return ''.join(format(ord(c), '08b') for c in text)

def bits_to_text(bits):
    chars = [chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8)]
    return ''.join(chars)

def hide_text(image_path, text, output_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = np.array(img)
    bits = text_to_bits(text) + '1111111111111110'
    idx = 0
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                if idx < len(bits):
                    pixels[i][j][k] = (pixels[i][j][k] & 0xFE) | int(bits[idx])
                    idx += 1
    new_img = Image.fromarray(pixels)
    new_img.save(output_path)
    print(f"[+] Text hidden in {output_path}")

def extract_text(image_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    pixels = np.array(img)
    bits = ''
    for i in range(pixels.shape[0]):
        for j in range(pixels.shape[1]):
            for k in range(3):
                bits += str(pixels[i][j][k] & 1)
                if bits.endswith('1111111111111110'):
                    return bits_to_text(bits[:-16])
    return "No hidden text found"

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["hide", "extract"], required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", help="Output image for hide mode")
    parser.add_argument("--text", help="Text to hide")
    args = parser.parse_args()

    if args.mode == "hide":
        hide_text(args.image, args.text, args.output)
    else:
        text = extract_text(args.image)
        print(f"[+] Extracted text: {text}")