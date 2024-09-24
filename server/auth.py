# auth.py

import json
import os
import logging


class UserManager:
    """
    Manages user registration and retrieval of public keys.
    Stores user data in a JSON file.
    """

    def __init__(self, filepath):
        self.filepath = filepath
        self.users = {}
        self.load_users()

    def load_users(self):
        """
        Load users from the JSON file.
        """
        if os.path.exists(self.filepath):
            with open(self.filepath, "r") as f:
                self.users = json.load(f)
            logging.debug(f"Loaded users from '{self.filepath}'.")
        else:
            self.users = {}
            logging.debug(f"No existing user data found at '{self.filepath}'. Starting fresh.")

    def save_users(self):
        """
        Save users to the JSON file.
        """
        with open(self.filepath, "w") as f:
            json.dump(self.users, f, indent=4)
        logging.debug(f"Saved users to '{self.filepath}'.")

    def register_user(self, username, public_key_pem):
        """
        Register a new user with username and public key.
        Returns True if successful, False if username already exists.
        """
        if username in self.users:
            logging.warning(f"Attempted to register existing username: '{username}'.")
            return False
        self.users[username] = {"public_key": public_key_pem}
        self.save_users()
        logging.info(f"Registered new user: '{username}'.")
        return True

    def get_user_public_key(self, username):
        """
        Retrieve the public key PEM for a given username.
        Returns the public key PEM string or None if user not found.
        """
        user = self.users.get(username)
        if user:
            logging.debug(f"Retrieved public key for user '{username}'.")
            return user.get("public_key")
        logging.warning(f"Requested public key for non-existent user '{username}'.")
        return None
