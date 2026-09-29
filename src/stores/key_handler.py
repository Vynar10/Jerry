import base64
import json
import secrets

from argon2 import PasswordHasher
from argon2.low_level import (
    hash_secret_raw,
    Type,
)

from nacl.secret import Aead


class KeyHandler:

    @staticmethod
    def derive_master_key(master_pwd, salt):
        return hash_secret_raw(
            secret=master_pwd.encode("utf-8"),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            type=Type.ID
        )


    @staticmethod
    def save_entry(
        filename,
        master_pwd,
        password,
        pwd_key,
        pwd_salt
    ):
        # Salt used ONLY for deriving the master encryption key
        master_salt = secrets.token_bytes(16)

        master_key = KeyHandler.derive_master_key(
            master_pwd,
            master_salt
        )

        cipher = Aead(master_key)

        password_hash = PasswordHasher().hash(
            password
        )

        # Everything in here gets encrypted
        payload = {
            "password": password,

            "password_hash": password_hash,

            "pwd_key": base64.b64encode(
                pwd_key
            ).decode("ascii"),

            "pwd_salt": base64.b64encode(
                pwd_salt
            ).decode("ascii"),
        }

        plaintext = json.dumps(
            payload
        ).encode("utf-8")

        encrypted = cipher.encrypt(
            plaintext
        )

        jer_data = {
            "version": 1,

            "master_salt": base64.b64encode(
                master_salt
            ).decode("ascii"),

            "encrypted": base64.b64encode(
                encrypted
            ).decode("ascii")
        }

        with open(filename, "w") as file:
            json.dump(
                jer_data,
                file,
                indent=4
            )


    @staticmethod
    def load_entry(
        filename,
        master_pwd
    ):
        with open(filename, "r") as file:
            jer_data = json.load(file)

        master_salt = base64.b64decode(
            jer_data["master_salt"]
        )

        encrypted = base64.b64decode(
            jer_data["encrypted"]
        )

        master_key = KeyHandler.derive_master_key(
            master_pwd,
            master_salt
        )

        cipher = Aead(master_key)

        plaintext = cipher.decrypt(
            encrypted
        )

        payload = json.loads(
            plaintext.decode("utf-8")
        )

        payload["pwd_key"] = base64.b64decode(
            payload["pwd_key"]
        )

        payload["pwd_salt"] = base64.b64decode(
            payload["pwd_salt"]
        )

        return payload
