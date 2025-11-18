import json
import hashlib
import base64
import os
import logging

logger = logging.getLogger(__name__)

class AuthManager:
    def __init__(self, users_file):
        self.users_file = users_file
        self.users = {}
        self.load_users()

    def load_users(self):
        try:
            with open(self.users_file, 'r') as f:
                users_list = json.load(f)
                for user in users_list:
                    self.users[user['username']] = user
            logger.info(f"Loaded {len(self.users)} users from {self.users_file}")
        except Exception as e:
            logger.error(f"Failed to load users from {self.users_file}: {e}")
            raise

    def verify_password(self, username, password):
        if username not in self.users:
            return False
        
        user = self.users[username]
        salt = base64.b64decode(user['salt'])
        stored_hash = user['password_hash']
        
        # In a real app, check 'algo' field. Here we assume pbkdf2_sha256 as per setup_data.py
        dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        computed_hash = base64.b64encode(dk).decode()
        
        return computed_hash == stored_hash
