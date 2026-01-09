# MilleGrilles messages project

This is a python library for connecting to the MilleGrilles (millegrilles.com) RabbitMQ backend.

## Development environment
+ Basic technology stack for python 3.13.

## Project description

This library contains a main module under `millegrilles_messages/` which is imported by several other applications.

**Layout**

+ bin: Scripts
+ doc: Some documentation
+ fixes: Binaries to fix requirements.
+ millegrilles_messages: Main code module
  + backup: Utilities for backing up and restoring the system
  + bus: Pika bus handling
  + certificats: x.509 certificat handling
  + chiffrage: cryptography, specifically encryption and decryption
  + docker: Docker related utilities
  + docker_obsolete: Deprecated Docker utilities
  + jobs: Utilities for job handling
  + messages: legacy module, many utilities moved to bus and pika modules
  + pika: Pika module with runtime.
  + structs: Reusable content structures
  + utils: Various utility classes

## Tool usage
+ When using tool **edit_file** to update an existing file, the tool will likely fail to apply the changes. When the tool fails to apply changes on the first try, switch to the **overwrite** operation.

> **Important:** All future modifications to the project should be performed with the `overwrite` mode of the `edit_file` tool.  The `edit` mode is unreliable for inserting new lines or making non‑trivial changes, so to avoid accidental omissions, always supply the complete file content when editing.

## Development

- **Source code**: The code is located under module `millegrilles_messages/`.
- **Dependencies**: 
  - Cryptography: cryptography, pycryptodome, pynacl, pyopenssl
  - x.509 certificates: certifi, certvalidator
  - Connectivity: pika, aiohttp, urllib3, requests
  - see `requirements.txt` for the complete list.
- Do not add dependencies unless it is explicitly requested.
