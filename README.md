## Secure Messaging Protocol Implementation (Signal & PQXDH)

### Overview

This project implements a secure, asynchronous messaging client based on the Signal Protocol, ensuring End-to-End Encryption (E2EE), Forward Secrecy, and Deniability.

Going beyond standard cryptographic primitives, this implementation integrates Post-Quantum Cryptography (PQXDH) using the Kyber Key Encapsulation Mechanism (KEM) to provide resistance against future quantum computing threats.

Developed as a term project for CS411/507 Cryptography at Sabancı University.

### Key Features

End-to-End Encryption (E2EE): Messages are encrypted locally and can only be decrypted by the intended recipient.

Forward Secrecy: Utilizes X3DH (Extended Triple Diffie-Hellman) key exchange to ensure past messages remain secure even if long-term keys are compromised.

Post-Quantum Security: Implements the PQXDH protocol using Kyber-1024 to protect against quantum adversaries.

Double Ratchet Algorithm: (Simplified) Generates fresh keys for every message block to ensure message-level security.

Authentication: Uses Ed25519 (EdDSA) digital signatures and HMAC-SHA256 for message integrity and authentication.

Key Management: Comprehensive management of Identity Keys (IK), Signed Pre-Keys (SPK), and One-Time Pre-Keys (OTK).

### Technical Stack

Language: Python 3

Cryptography Libraries:

cryptography (Primitives, Hazmat)

PyCryptodome (AES, SHA)

kyber-py (Post-Quantum KEM)

libnacl / PyNaCl (ECC operations)

Protocols: Signal Protocol, X3DH, PQXDH, AES-256-CTR, HMAC-SHA256, SHA3-512.

### Project Structure

Client_Phase1.py: Key Generation & Registration - Generates Identity Keys (Ed25519), Signed Pre-Keys, and One-Time Keys (OTKs), and registers them with the server.

Client_Phase2.py: Secure Messaging (X3DH) - Implements the standard Signal Protocol handshake and message exchange using classical ECC.

Client_Phase3.py: Post-Quantum Messaging (PQXDH) - Upgrades the key exchange to use Kyber KEM for quantum resistance and implements Conference Keying.

### Cryptographic Primitives Used

*   **Digital Signature**
    *   Algorithm: Ed25519 (EdDSA)
    *   Usage: Identity verification and key signing.
*   **Key Exchange**
    *   Algorithm: X25519 & Kyber-1024
    *   Usage: Establishing shared session keys (Classical & PQ).
*   **Encryption**
    *   Algorithm: AES-256-CTR
    *   Usage: Encrypting message payloads.
*   **Integrity (MAC)**
    *   Algorithm: HMAC-SHA256
    *   Usage: Ensuring message authenticity.
*   **Hashing**
    *   Algorithm: SHA3-256 / SHA3-512
    *   Usage: Key Derivation Functions (KDF).

### Installation & Usage

Note: This client requires a connection to the specific project server provided during the course for key registration and message relay. The code serves as a reference implementation of the client-side logic.

Install Dependencies:

pip install pycryptodome cryptography kyber-py


Run Phase 1 (Registration):

python Client_Phase1.py


Run Phase 3 (PQXDH Messaging):

python Client_Phase3.py


### License

This project is open-source and available under the MIT License.

Created by Yusufcan Demirkapı
