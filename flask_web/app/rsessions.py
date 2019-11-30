import redis
from uuid import uuid4


class SessionsManager:
    def __init__(self, cache):
        self.cache = cache
        self.sessions_key_to_redis = "sessions"

    def create_session(self, username):
        # protection from ids conflict
        while True:
            session_id = str(uuid4())
            if not self.validate_session(session_id):
                break

        self.cache.hset(self.sessions_key_to_redis, session_id, username)
        return session_id

    def delete_session(self, session_id):
        if session_id is not None:
            self.cache.hdel(self.sessions_key_to_redis, session_id)

    def validate_session(self, session_id):
        if session_id is not None and self.cache.hget(self.sessions_key_to_redis, session_id) is not None:
            return True
        else:
            return False

    def get_session_user(self, session_id):
        if session_id is not None:
            return self.cache.hget(self.sessions_key_to_redis, session_id)
        return False
