import datetime
from jwt import encode


class TokenCreator:
    def __init__(self, session_time, jwt_session_time, jwt_secret):
        self.session_time = session_time
        self.jwt_session_time = jwt_session_time
        self.jwt_secret = jwt_secret

    def create_download_token(self):
        exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=self.jwt_session_time)
        data = {
            "iss": "web.company.com",
            "exp": exp,
        }
        return encode(data, self.jwt_secret, "HS256")

    def create_upload_token(self):
        return self.create_download_token()

    # TODO ADD USER TO THE TOKEN

    def create_getFileList_token(self):
        return self.create_download_token()
