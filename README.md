##  ⚡ lighCrypt

lighCrypt is a custom Python encryption/decryption CLI built as a personal learning project.

It combines Python, cryptography concepts, file I/O, OOP, generators, regex, and the Rich terminal UI.

> ⚠️ **Note:** *lighCrypt is an experimental project and has not been professionally security-audited. Don't use it for highly sensitive data.*

**✨ Features**

- 🔐 Password-based encryption & decryption
- 🧂 Random salt generation
- 🔑 PBKDF2-HMAC-SHA256
- 🛡️ HMAC-SHA256 authentication
- 🎲 Custom HMAC-based key stream
- 🌐 Unicode support
- 📄 File input/output
- 📝 Multi-line input
- 🎨 Rich CLI interface

**🛠️ Requirements**

- Python 3.14+
- rich

**🚀 Installation**

📋 Prerequisites

Ensure the following are installed:

- Git — Required to clone the repository.
- Python 3 — Required to run lighCrypt.

If either is missing, install it first:

- **Termux:** ``pkg install git python``
- **Windows:** Install [Git](https://git-scm.com/downloads) and [Python](https://www.python.org/downloads/).
- **macOS / Linux:** Install Git and Python 3 using your system's package manager or the official links above.

**🐧 macOS / Linux / Termux**
```
git clone https://github.com/lighning-95/lighCrypt.git
cd lighCrypt
python3 -m pip install rich
python3 main.py
```

**🪟 Windows**
```
git clone https://github.com/lighning-95/lighCrypt.git
cd lighCrypt
py -m pip install rich
py main.py
```
---

**⌨️ Commands**

While entering text:

| Command   |  Function | 
| --- | --- |
|:d / :done |Finish input|
|:f /:file   path/to/file  |   Load a file|
|:q / :quit   |    Cancel and go back|

      
On other ther screens:

| Command |Function|
| --- |---|
|q / :q / :quit |  Go back |

**📚 Library used**
built in libraries
- os
- re
- string
- hashlib
- hmac
- secrets
- time
- base64
- textwrap
- getpass

External library
- rich

**⚙️ How It Works**

Password + random salt
         ↓
PBKDF2-HMAC-SHA256
         ↓
Derived Seed
         ↓
HMAC-based Key Stream
         ↓
Custom Text Transformation
         ↓
HMAC Authentication
         ↓
URL-safe Base64

lighCrypt uses separate derived keys for encryption, authentication, salt protection, and tag protection.

### ⚠️ Responsible Use

>lighCrypt is provided for educational and legitimate purposes only.
>
>Do not use it for illegal activities, unauthorized access, or to conceal unlawful activity.
>
>The author is not responsible for misuse of this software or for any consequences resulting from its use. Users are responsible for ensuring that their use of lighCrypt complies with applicable laws and regulations.

**📜 License**

*This project is licenced under MIT licence*

**👤 Author**

[*lighning-95*](https://GitHub.com/lighning-95)

Built as part of my journey learning Python and building things from scratch. 