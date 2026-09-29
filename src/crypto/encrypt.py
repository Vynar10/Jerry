import secrets
import string

from argon2.low_level import (
    hash_secret_raw,
    Type
)


class Encryptions:

    @staticmethod
    def pwd_gen_w_key(choice, length):

        if choice == "ascii":
            alphabet = (
                string.ascii_letters
                + string.digits
                + string.punctuation
            )

        elif choice == "bytes":
            alphabet = ''.join(
                chr(i) for i in range(33, 127)
            )

        else:
            raise ValueError(
                "choice must be 'ascii' or 'bytes'"
            )

        pwd = ''.join(
            secrets.choice(alphabet)
            for _ in range(length)
        )

        salt = secrets.token_bytes(16)

        key = hash_secret_raw(
            secret=pwd.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

        return pwd, key, salt


    @staticmethod
    def pwd_key_giver(pwd):

        salt = secrets.token_bytes(16)

        key = hash_secret_raw(
            secret=pwd.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )

        return key, salt

    @staticmethod
    def derive_key(pwd, salt):

        return hash_secret_raw(
                secret=pwd.encode("utf-8"),
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID
                )
