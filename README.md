# axauth

**AXAuth** is a command-line terminal client for AX.25 amateur packet radio that adds optional authentication using the [Chattervox](https://github.com/markqvist/chattervox) public key protocol. It aims to be a drop-in alternative to `axcall`, providing transparent operation for unauthenticated connections while enabling verified identity when supported.

---

## 🌐 Project Goals

- ✅ Drop-in replacement for `axcall`, preserving existing workflows  
- 🔐 Optional Chattervox-compatible authentication using public/private key pairs  
- 📧 Pluggable key discovery: local keyring, APRS, Winlink, QRZ, etc.  
- 📨 Optional key exchange via Winlink (or via pluggable backend listeners)  
- 🔄 Compatible with existing AX.25 Linux stack (kissattach, axcall, etc.)  
- 🧩 Modular and extensible client design (e.g., chat, UCI chess interfaces)  

---

## 🚀 Example Usage

```bash
axauth ax0 ZL1XYZ
Basic connection, just like axcall.

axauth ax0 ZL1XYZ --auth

Authenticated connection using the Chattervox protocol and a local keyring.

axauth ax0 ZL1XYZ --auth --winlink

If a public key isn’t found locally, attempt to retrieve it via Winlink email.
🔧 Command Line Flags
Flag	Description
--auth	Enables Chattervox-compatible authentication
--keyfile	Path to private key (default: ~/.axauth/private.key)
--pubring	Path to public keyring (default: ~/.axauth/pubring.json)
--winlink	Enables fallback public key discovery via Winlink email
--verbose	Print debug information
🧱 Project Structure

axauth/
├── axauth/
│   ├── cli.py        # CLI argument handling and entrypoint
│   ├── ax25.py       # AX.25 connection interface (shells out to axcall or native TNC)
│   ├── auth.py       # Chattervox protocol handling
│   ├── keyring.py    # Load, store, and manage public/private keyring
│   ├── winlink.py    # Optional fallback key request via Winlink email
├── tests/
│   ├── test_cli.py
├── pyproject.toml    # Poetry-based project metadata
├── README.md
├── LICENSE

🔐 Authentication Flow (Chattervox-style)

    The local client generates or loads a long-term Ed25519 private key.

    When connecting to a remote station, it sends an AXAUTH handshake string with a signed token.

    The remote verifies the signature using a known public key (or retrieves it if missing).

    If verified, both parties consider the connection authenticated.

📨 Winlink Key Exchange (Optional)

If a requested public key is missing from the local keyring:

    axauth can send a structured email to a known Winlink address requesting the public key.

    The remote node replies with the signed public key blob.

    The key is added to the local keyring for future authenticated sessions.

This fallback mechanism is optional and can be disabled.
📦 Installation

Coming soon:

pip install axauth

For now, clone and run using Poetry:

git clone https://github.com/yourusername/axauth.git
cd axauth
poetry install
poetry run axauth ax0 ZL1XYZ

🔮 Planned Features

    ✅ axcall compatibility with transparent fallback

    🔐 Chattervox authentication protocol

    📡 Pluggable trust sources: Winlink, QRZ, APRS, GitHub

    🧠 Integration with UCI chess engines for over-radio play (AXChess)

    💬 Support for chat rooms and signed messages

    🧪 CI tests and public testbed node

🤝 Contributing


📜 License

GPL3 License – use freely, modify, and share. Attribution welcome!
📡 Acknowledgements

    Chattervox by Brannon Dorsey for the auth protocol

    Linux AX.25 tools (axcall, kissattach, etc.)

    The amateur radio community worldwide 🌍
