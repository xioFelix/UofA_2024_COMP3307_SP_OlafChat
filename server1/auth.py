import json
import os


class UserManager:
    """
    UserManager handles user registration and retrieval.
    """

    def __init__(self, user_data_file):
        self.user_data_file = user_data_file
        self.users = {}
        self.load_users()

    def load_users(self):
        """
        Load users from the user data file.
        """
        if os.path.exists(self.user_data_file):
            with open(self.user_data_file, "r") as f:
                self.users = json.load(f)
        else:
            self.users = {}

    def save_users(self):
        """
        Save users to the user data file.
        """
        with open(self.user_data_file, "w") as f:
            json.dump(self.users, f)

    def register_user(self, username, public_key_pem):
        """
        Register a new user with username and public key.
        """
        if username in self.users:
            return False  # Username already exists
        self.users[username] = public_key_pem
        self.save_users()
        return True

    def get_user_public_key(self, username):
        """
        Get the public key of a registered user.
        """
        return self.users.get(username)
