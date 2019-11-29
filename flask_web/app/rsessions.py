import redis
from uuid import uuid4


class SessionsManager:
    def __init__(self, cache):
        self.cache = cache
        self.sessions_key_to_redis = "sessions"

    def create_session(self, username):
        while True:
            session_id = str(uuid4())
            # check for duplicated session id
            if not self.validate_session(session_id):
                break
        self.cache.hset(self.sessions_key_to_redis, session_id, username)
        return session_id

    def delete_session(self, session_id):
        if session_id:
            self.cache.hdel(self.sessions_key_to_redis, session_id)

    def validate_session(self, session_id):
        if session_id and self.cache.hget(self.sessions_key_to_redis, session_id) is not None:
            return True
        else:
            return False
