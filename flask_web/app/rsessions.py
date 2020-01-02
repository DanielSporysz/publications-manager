import redis
from uuid import uuid4
import datetime
import sys


class SessionsManager:
    def __init__(self, cache, max_session_age):
        self.cache = cache
        self.sessions_key_to_redis = "sessions"
        self.session_age_key_to_redis = "session_age"
        self.max_session_age = max_session_age

    def create_session(self, username):
        # protection from ids conflict
        while True:
            session_id = str(uuid4())
            if not self.validate_session(session_id):
                break

        self.cache.hset(self.sessions_key_to_redis, session_id, username)

        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.max_session_age)
        self.cache.hset(self.session_age_key_to_redis, session_id, str(exp))

        return session_id

    def delete_session(self, session_id):
        if session_id is not None:
            self.cache.hdel(self.sessions_key_to_redis, session_id)
            self.cache.hdel(self.session_age_key_to_redis, session_id)

    def validate_session(self, session_id):
        if session_id is not None and self.cache.hget(self.sessions_key_to_redis, session_id) is not None:
            str_session_age = self.cache.hget(
                self.session_age_key_to_redis, session_id).decode()
            dt_format = "%Y-%m-%d %H:%M:%S.%f"
            session_age = datetime.datetime.strptime(
                str_session_age, dt_format)

            if session_age > datetime.datetime.now():
                return True
        return False

    def get_session_user(self, session_id):
        if session_id is not None:
            return self.cache.hget(self.sessions_key_to_redis, session_id)
        return None
