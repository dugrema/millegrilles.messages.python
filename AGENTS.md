# MilleGrilles messages project

This is a python library for connecting to the MilleGrilles (millegrilles.com) RabbitMQ backend.

## Development environment
+ Basic technology stack for python 3.13.

## Project description

This library contains a main module under millegrilles_messages/ which is imported by several other applications.

**Layout**

+ bin: Scripts
+ doc: Some documentation
+ fixes: Binaries to fix requirements.
+ millegrilles_messages: Main code module
  + backup: Utilities for backing up and restoring the system
  + bus: Pika bus handling
  + certificats: x.509 certificat handling
  + chiffrage: cryptography, specifically encryption and decryption
  + jobs: Utilities for job handling
  + messages: older module, many utilities were moved to bus, cand pika modules
  + pika: Pika module with runtime.
  + structs: Reusable content structures
  + utils: Various utility classes
+ test: test files and utilities

## Tool usage
+ When using tool **edit_file** to **update** a file, provide a verbose description (50-300 words) in display_description. If the tool fails to apply changes on the first try, switch to the **override** operation.

## Development

- **Source code**: The code is located under module `millegrilles_messages/`.
- **Dependencies**: 
  - Cryptography: cryptography, pycryptodome, pynacl, pyopenssl
  - x.509 certificates: certifi, certvalidator
  - Connectivity: pika, aiohttp, urllib3, requests
  - see requirements.txt for complete list.
- Do not add dependencies unless it is explicitly requested.
