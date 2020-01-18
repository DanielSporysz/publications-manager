import redis
import os
import hashlib
import sys
import json
from datetime import datetime, timedelta

HASH_COUNT = 10
SALT_LENGTH = 32

MAX_FAILED_LOGIN_ATTEMPTS = 5
ACCOUNT_LOCK_TIME = 5
DT_FORMAT = "%Y-%m-%d %H:%M:%S.%f"

class UsersManager:
    def __init__(self, cache):
        self.cache = cache
        self.users_key_to_redis = "users"
        self.users_salt_key_to_redis = "users_salt"
        self.users_failed_login_history = "users_failed_login_history"

    def validate_credentials(self, username, password):
        if username is None and password is None:
            return False

        salt_bag = self.cache.hget(self.users_salt_key_to_redis, username)
        if salt_bag is None:
            return False

        # Check the register of login attempts
        history = self.cache.hget(self.users_failed_login_history, username)
        if history:
            history = json.loads(history.decode())
        else:
            history = []
        if len(history) >= MAX_FAILED_LOGIN_ATTEMPTS:
            last_attempt = history[-1:][0]
            last_attempt = datetime.strptime(last_attempt, DT_FORMAT)

            if last_attempt - datetime.utcnow() < timedelta(minutes=ACCOUNT_LOCK_TIME):
                print(username + " account is locked", file=sys.stderr)
                return False

        # Hash and compare
        given_key = password.encode('utf-8')
        hash_iteration = 0
        while hash_iteration < HASH_COUNT:
            salt = salt_bag[hash_iteration*SALT_LENGTH:hash_iteration*SALT_LENGTH+SALT_LENGTH]
            given_key = hashlib.pbkdf2_hmac(
                'sha256',
                given_key,
                salt,
                100000
            )

            hash_iteration+=1

        known_key = self.cache.hget(self.users_key_to_redis, username)
        if known_key is not None and known_key == given_key:
            # Clear register of failed login attempts
            self.cache.hdel(self.users_failed_login_history, username)

            return True
        else:
            # Register failed login attempt
            history = self.cache.hget(self.users_failed_login_history, username)
            if history:
                history = json.loads(history.decode())
            else:
                history = []
            history.append(str(datetime.utcnow()))

            history = history[-5:] # Remember just last 5 attempts
            self.cache.hset(self.users_failed_login_history, username, json.dumps(history))

            return False

    def is_username_available(self, username):
        if not username:
            return False

        # if password is set then such user exists
        known_key = self.cache.hget(self.users_key_to_redis, username)
        if known_key is not None:
            return False
        else:
            return True

    def register_user(self, username, password, password_change=False):
        if username is None and password is None:
            raise Exception("Recived Nonetype object")

        if not password_change and self.cache.hget(self.users_key_to_redis, username) is not None:
            raise Exception(username + " is already registred")

        key = password.encode('utf-8')
        salt_bag = "".encode('utf-8')
        hash_iteration = 0
        while hash_iteration < HASH_COUNT:
            salt = os.urandom(32)
            key = hashlib.pbkdf2_hmac(
                'sha256',
                key,
                salt,
                100000
            )

            salt_bag = salt_bag + salt
            hash_iteration += 1

        try:
            self.cache.hset(self.users_salt_key_to_redis, username, salt_bag)            
            self.cache.hset(self.users_key_to_redis, username, key)
        except:
            raise Exception(username + "error updating credentials")

    def change_password(self, username, new_password):
        if username is None and new_password is None:
            raise Exception("Recived Nonetype object")

        if self.cache.hget(self.users_key_to_redis, username) is None:
            raise Exception(
                username + " is not registered. Cannot change their password")

        self.register_user(username, new_password, password_change=True)

    # for development purpose
    def init_redis_with_users(self):
        try:
            users = {('admin', 'admin'), ('daniel', 'mistrz')}
            for user in users:
                self.register_user(user[0], user[1], password_change=True)
        except:
            print('DEV_METHOD: ERROR REGISTERING USERS', file=sys.stderr)
            pass
