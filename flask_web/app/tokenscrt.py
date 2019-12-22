import datetime
from jwt import encode


class TokenCreator:
    def __init__(self, jwt_session_time, jwt_secret):
        self.jwt_session_time = jwt_session_time
        self.jwt_secret = jwt_secret

    def create_download_token(self, username, fid):
        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.jwt_session_time)
        payload = {
            "iss": "web.company.com",
            "exp": exp,
            "username": username,
            "fid": fid,
            "action": "download"
        }
        return encode(payload, self.jwt_secret, "HS256")

    def create_upload_token(self, username):
        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.jwt_session_time)
        payload = {
            "iss": "web.company.com",
            "exp": exp,
            "username": username,
            "action": "upload"
        }
        return encode(payload, self.jwt_secret, "HS256")

    def create_getFileList_token(self, username):
        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.jwt_session_time)
        payload = {
            "iss": "web.company.com",
            "exp": exp,
            "username": username,
            "action": "fileList"
        }
        return encode(payload, self.jwt_secret, "HS256")

    def create_user_token(self, username):
        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.jwt_session_time)
        payload = {
            "iss": "web.company.com",
            "exp": exp,
            "username": username
        }
        return encode(payload, self.jwt_secret, "HS256")

    def create_delete_token(self, username, fid):
        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.jwt_session_time)
        payload = {
            "iss": "web.company.com",
            "exp": exp,
            "username": username,
            "fid": fid,
            "action": "deleteFile"
        }
        return encode(payload, self.jwt_secret, "HS256")
