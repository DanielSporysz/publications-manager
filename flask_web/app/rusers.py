import redis
import os
import hashlib
import sys

HASH_COUNT = 5

class UsersManager:
    def __init__(self, cache):
        self.cache = cache
        self.users_key_to_redis = "users"
        self.users_salt_key_to_redis = "users_salt"

    def validate_credentials(self, username, password):
        if username is None and password is None:
            return False

        hash_iteration = 0
        given_key = password.encode('utf-8')
        while hash_iteration < HASH_COUNT:
            known_salt = self.cache.hget(self.users_salt_key_to_redis + str(hash_iteration), username)
            if known_salt is None:
                if hash_iteration != 0:
                    print("ERROR: there's no enough salt for hashing " + username + "'s password.")
                return False
            given_key = hashlib.pbkdf2_hmac(
                'sha256',
                given_key,
                known_salt,
                100000
            )

            hash_iteration+=1

        known_key = self.cache.hget(self.users_key_to_redis, username)
        if known_key is not None and known_key == given_key:
            return True
        else:
            return False

    def register_user(self, username, password, password_change=False):
        if username is None and password is None:
            raise Exception("Recived Nonetype object")

        if not password_change and self.cache.hget(self.users_key_to_redis, username) is not None:
            raise Exception(username + " is already registred")

        hash_iteration = 0
        key = password.encode('utf-8')
        while hash_iteration < HASH_COUNT:
            salt = os.urandom(32)
            key = hashlib.pbkdf2_hmac(
                'sha256',
                key,
                salt,
                100000
            )

            self.cache.hset(self.users_salt_key_to_redis +
                            str(hash_iteration), username, salt)
            hash_iteration += 1

        try:
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
