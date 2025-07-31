import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
import matplotlib.pyplot as plt


# === Custom Hash Function ===
def custom_hash(text, length=32):
    if not text:
        return '0' * length

    # Step 1: ASCII value manipulation
    ascii_sum = [ord(c) for c in text]

    # Step 2: Modulo arithmetic & shifting
    mixed = [(val * (i + 1) + 7) % 256 for i, val in enumerate(ascii_sum)]

    # Step 3: Compression
    while len(mixed) > length:
        mixed = [mixed[i] ^ mixed[i + length] for i in range(length)]

    # Padding if short
    if len(mixed) < length:
        mixed += [0] * (length - len(mixed))

    # Step 4: Convert to hex string
    return ''.join(f"{x:02x}" for x in mixed[:length])


# === Hamming Distance ===
def hamming_distance(str1, str2):
    bin1 = bin(int(str1, 16))[2:].zfill(len(str1) * 4)
    bin2 = bin(int(str2, 16))[2:].zfill(len(str2) * 4)
    return sum(c1 != c2 for c1, c2 in zip(bin1, bin2))


# === File Reading ===
def read_file(filepath):
    try:
        with open(filepath, 'rb') as f:
            return f.read()
    except Exception as e:
        messagebox.showerror("File Error", str(e))
        return None


# === GUI Functions ===
def hash_input():
    user_input = input_text.get("1.0", tk.END).strip()
    process_input(user_input.encode('utf-8'))


def browse_file():
    filepath = filedialog.askopenfilename()
    if filepath:
        content = read_file(filepath)
        if content is not None:
            process_input(content)


def process_input(data):
    if not data:
        messagebox.showerror("Input Error", "No input provided.")
        return

    try:
        # Hashes
        custom = custom_hash(data.decode('utf-8', errors='ignore'))
        sha256 = hashlib.sha256(data).hexdigest()
        sha1 = hashlib.sha1(data).hexdigest()
        md5 = hashlib.md5(data).hexdigest()

        # Output Display
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, f"Custom Hash:\n{custom}\n\n")
        result_text.insert(tk.END, f"SHA-256:\n{sha256}\n\n")
        result_text.insert(tk.END, f"SHA-1:\n{sha1}\n\n")
        result_text.insert(tk.END, f"MD5:\n{md5}\n\n")

        # Hamming Distance Graph
        visualize_hamming(custom, sha256, sha1, md5)
    except Exception as e:
        messagebox.showerror("Error", str(e))


def visualize_hamming(custom, sha256, sha1, md5):
    hashes = {'SHA-256': sha256, 'SHA-1': sha1, 'MD5': md5}
    distances = [hamming_distance(custom, h) for h in hashes.values()]

    plt.figure(figsize=(6, 4))
    plt.bar(hashes.keys(), distances, color='teal')
    plt.title('Hamming Distance from Custom Hash')
    plt.ylabel('Bit Difference')
    plt.xlabel('Standard Hash Algorithms')
    plt.tight_layout()
    plt.show()


# === GUI Layout ===
root = tk.Tk()
root.title("Custom Hash Generator - Sindhu R")

# Input Frame
input_frame = tk.LabelFrame(root, text="Text Input", padx=10, pady=10)
input_frame.pack(padx=10, pady=5, fill="x")

input_text = tk.Text(input_frame, height=4)
input_text.pack(fill="x")

tk.Button(root, text="Generate Hash from Text", command=hash_input).pack(pady=5)
tk.Button(root, text="Upload File", command=browse_file).pack(pady=5)

# Result Frame
result_frame = tk.LabelFrame(root, text="Hash Output", padx=10, pady=10)
result_frame.pack(padx=10, pady=5, fill="both", expand=True)

result_text = tk.Text(result_frame, height=15)
result_text.pack(fill="both", expand=True)

root.mainloop()
