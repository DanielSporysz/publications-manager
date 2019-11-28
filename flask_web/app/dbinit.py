import redis

users = {('admin', 'admin'), ('daniel', 'mistrz')}

def init(cache):
    for user in users:
        cache.hset(user[0], "password", user[1])
