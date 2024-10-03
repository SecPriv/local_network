from __future__ import annotations

from argparse import ArgumentTypeError
from hashlib import sha256
from android_dynamic_tool.helper.seeded_random import seeded_random
from pathlib import Path
import string
from typing import Any, List, Union


def get_random_string(length: int = 10) -> str:
    """Returns random string of the given length made from ascii letters, digits and whitespaces

    Args:
        length: The length of the generated string. Defaults to 10. Negative values may lead to unexpected behavior.

    Returns:
        Random string
    """
    letters = string.ascii_letters + string.digits + " "
    result_str = "".join(seeded_random.choice(letters) for _ in range(length))
    return result_str


def get_random_email(local_length: int = 10, domain_length: int = 7, tld: str = "zzz") -> str:
    """Returns random string of the given length made from ascii letters, digits and whitespaces

    Args:
        local_length: The length of the local part (part before the @ sign). Defaults to 10. Shall be greater than 0.
        domain_length: The length of the domain woithout TLD (part between the @ sign and the last dot). Defaults to 7.
            Shall be greater than 0.
        tld: Top-Level Domain to use. Defaults to non-existent TLD zzz.

    Returns:
        Random syntactical valid email address
    """

    if local_length <= 0 or domain_length <= 0:
        raise ValueError("Length must be greater than 0.")

    letters = string.ascii_lowercase + string.digits + "."

    local = "."
    while local.startswith((".",) + tuple(string.digits)) or local.endswith("."):
        local = "".join(seeded_random.choice(letters) for _ in range(local_length))

    domain = "."
    while domain.startswith((".",) + tuple(string.digits)) or domain.endswith("."):
        domain = "".join(seeded_random.choice(letters) for _ in range(domain_length))

    email_address = local + "@" + domain + "." + tld
    return email_address


def get_file_sha256_hash(file: Union[str, Path]) -> str:
    if isinstance(file, str):
        file = Path(file)
    if not file.is_file():
        raise FileNotFoundError(file)
    with file.open(mode="rb") as file:
        sha256hash = sha256()
        for byte_block in iter(lambda: file.read(4096), b""):
            sha256hash.update(byte_block)
        return sha256hash.hexdigest()


def load_word_list(file: Union[str, Path]) -> List[str]:
    if isinstance(file, str):
        file = Path(file)
    if not file.is_file():
        raise FileNotFoundError(file)
    with file.open(mode="r") as file:
        word_list = file.readlines()
        return word_list


def check_path_exists(value: Any) -> Path:
    path = Path(value).absolute()
    if path.exists():
        return path
    raise ArgumentTypeError(f'{value} is not a path to an existing file or directory')
