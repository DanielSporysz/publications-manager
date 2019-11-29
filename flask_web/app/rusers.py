import redis


class UsersManager:
    def __init__(self, cache):
        self.cache = cache
        self.users_key_to_redis = "users"

    def validate_credentials(self, username, password):
        if username is not None and password is not None:
            known_password = self.cache.hget(self.users_key_to_redis, username)
            if known_password is not None and known_password.decode() == password:
                return True
        else:
            return False

    # for development purpose
    def init_redis_with_users(self):
        users = {('admin', 'admin'), ('daniel', 'mistrz')}
        for user in users:
            # hashing passwords doesn't make sense at this point
            self.cache.hset(self.users_key_to_redis, user[0], user[1])
