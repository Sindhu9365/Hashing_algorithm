 Custom Hash Function GUI Tool

This project is a Python-based GUI application that generates a fixed-length hash using:
- A custom hashing algorithm
- Standard hash functions: SHA-256, SHA-1, and MD5

It also visualizes the Hamming distance between the custom hash and the standard ones.

Features

- Text input support
- File input support
- Custom hash using character manipulation, modulo arithmetic, and compression
- Generates SHA-256, SHA-1, and MD5 hashes
- Visual Hamming distance graph using `matplotlib`



 Custom Hash Algorithm Overview

- Converts each character to ASCII
- Applies multiplication, constant addition, modulo 256
- Uses XOR compression to limit hash to 32 characters
- Pads with zeros if input is short
- Outputs a hex-based hash string



 Requirements

bash
pip install matplotlib
