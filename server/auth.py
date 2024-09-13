import json
import os


class UserManager:
    def __init__(self, user_data_file):
        self.user_data_file = user_data_file
        self.users = {}
        self.load_users()

    def load_users(self):
        if os.path.exists(self.user_data_file):
            with open(self.user_data_file, "r") as f:
                self.users = json.load(f)
        else:
            self.users = {}

    def save_users(self):
        with open(self.user_data_file, "w") as f:
            json.dump(self.users, f)

    def register_user(self, username, public_key_pem):
        if username in self.users:
            return False  # 用户名已存在
        self.users[username] = public_key_pem
        self.save_users()
        return True

    def get_user_public_key(self, username):
        return self.users.get(username)
