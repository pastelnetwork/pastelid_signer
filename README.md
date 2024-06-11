# PastelID Signer

This project is a Rust implementation of the PastelID signing and verification functionality. It is designed to work with secure containers that store ED448 private keys, providing an interface for signing and verifying messages. This implementation follows the logic of the original C++ code from the Pastel project and exposes the functionality as a Python package using PyO3 and Maturin.

## What It Does

The PastelID Signer:
1. Reads a secure container file containing an ED448 private key.
2. Decrypts the secure container using a passphrase.
3. Provides functions to sign messages using the decrypted private key.
4. Provides functions to verify signatures using the corresponding public key.

## How It Works

### Secure Container Format

The secure container format is a binary structure that includes:
- A fixed header (`PastelSecureContainer`).
- A JSON-encoded structure that stores both public and secure (encrypted) items.

The secure items include:
- `type`: The type of secure item (e.g., `pkey_ed448`).
- `nonce`: A unique nonce used for encryption.
- `data`: The encrypted data (e.g., private key).

### Key Derivation and Encryption

1. **Key Derivation**: The key for decrypting the secure item is derived from the passphrase and nonce using the `crypto_pwhash` function with `OPSLIMIT_INTERACTIVE` and `MEMLIMIT_INTERACTIVE` parameters.
2. **Encryption/Decryption**: The XChaCha20-Poly1305 algorithm is used for encryption and decryption of secure items.

### Comparison with C++ Code

The Rust implementation mirrors the C++ code in the following ways:
- **Header Verification**: Both implementations check for the `PastelSecureContainer` header.
- **Nonce Handling**: Both extract and use the nonce associated with each secure item for key derivation.
- **Key Derivation**: Both use `crypto_pwhash` for deriving the encryption key from the passphrase and nonce.
- **Encryption Algorithm**: Both use XChaCha20-Poly1305 for encrypting and decrypting secure item data.

## Installation

### Prerequisites

- Rust (1.56.0 or newer)
- Python (3.6 or newer)
- Maturin
- Sodiumoxide (for cryptographic operations)

### Steps

1. **Install Rust**

If you don't have Rust installed, you can install it from [rustup](https://rustup.rs/).

2. **Install Maturin**

Maturin is a tool for building and publishing Rust-based Python packages. Install it via pip:

```bash
pip install maturin
```

3. **Build the Python Package**

Navigate to the project directory and build the package using Maturin:

```bash
cd pastelid_signer
maturin develop
```

This will compile the Rust code and install the Python package locally.

## Configuration

Create a configuration file named `config.toml` with the following content:

```toml
[default]
pastelid = { file_path = "/path/to/your/secure_container", passphrase = "your_passphrase" }
```

## Usage

### Example Usage in Python

```python
from pastelid_signer import PastelSigner

# Initialize the signer
signer = PastelSigner()

# Sign a message
message = b"my_message_1__hello_friends"
signature = signer.sign(message)
print(f"Signature: {signature.hex()}")

# Verify the signature
is_valid = signer.verify(message, signature)
print(f"Signature valid: {is_valid}")
```

## Testing

### Running Rust Tests

To run the Rust tests, use the following command:

```bash
cargo test
```

### Running Python Tests

You can also run Python tests using a simple script. Create a file named `test_signer.py` with the following content:

```python
import unittest
from pastelid_signer import PastelSigner

class TestPastelSigner(unittest.TestCase):
    def setUp(self):
        self.signer = PastelSigner()

    def test_sign_and_verify(self):
        message = b"my_message_1__hello_friends"
        signature = self.signer.sign(message)
        self.assertTrue(self.signer.verify(message, signature))

if __name__ == '__main__':
    unittest.main()
```

Then run the tests:

```bash
python test_signer.py
```

## Detailed Explanation

### Header Verification

Both the Rust and C++ implementations start by verifying the file header to ensure it matches the expected value (`PastelSecureContainer`). This step is critical for ensuring that the file being processed is indeed a valid secure container.

### Nonce Handling

The nonce is a unique value generated for each secure item. It is used both for key derivation and as part of the encryption process. In the Rust implementation, the nonce is extracted and used exactly as in the C++ code.

### Key Derivation

Key derivation in both implementations is done using the `crypto_pwhash` function from the libsodium library. The parameters used (`OPSLIMIT_INTERACTIVE` and `MEMLIMIT_INTERACTIVE`) ensure that the key derivation process is secure against brute-force attacks.

### Encryption and Decryption

Encryption and decryption are performed using the XChaCha20-Poly1305 algorithm, which provides authenticated encryption. This ensures that the data cannot be tampered with without detection.

By adhering closely to the original C++ code, this Rust implementation ensures compatibility and security while providing the additional benefits of Rust's safety and performance features.

## Contributing

We welcome contributions to this project. Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Make your changes.
4. Submit a pull request with a detailed explanation of your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
