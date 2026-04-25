import argparse
from pathlib import Path

from millegrilles_messages.messages.Hachage import Hacheur

CHUNK_SIZE = 64 * 1024  # 64KB


def hash_file(file_path: Path, algorithm: str, encoding: str) -> None:
    """Hashes a file in chunks and prints the result."""
    if not file_path.is_file():
        print(f"Error: File '{file_path}' not found or is not a file.")
        return

    hacheur = Hacheur(algorithm, encoding)

    with file_path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hacheur.update(chunk)

    res = hacheur.finalize()
    print(res)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute the hash of a file.")
    parser.add_argument("file_path", type=Path, help="Path to the file to hash")
    parser.add_argument(
        "--algo",
        type=str,
        default="blake2s-256",
        help="Hashing algorithm (e.g., blake2b-512, blake2s-256). Default is 'blake2b-512'.",
    )
    parser.add_argument(
        "--encoding",
        type=str,
        default="base64",
        help="Encoding used by Hacheur (e.g., base64). Default is 'base64'.",
    )

    args = parser.parse_args()
    hash_file(args.file_path, args.algo, args.encoding)


if __name__ == "__main__":
    main()
