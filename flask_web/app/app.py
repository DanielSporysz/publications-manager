from jwt import encode
from uuid import uuid4
from flask import Flask
from flask import request
from flask import make_response
from dotenv import load_dotenv
from os import getenv
import datetime
import redis
import sys
load_dotenv(verbose=True)

HTML = """<!doctype html>
<head><meta charset="utf-8"/></head>"""

app = Flask(__name__)
PDF = getenv("PDF_HOST")
WEB = getenv("WEB_HOST")
SESSION_TIME = int(getenv("SESSION_TIME"))
JWT_SESSION_TIME = int(getenv('JWT_SESSION_TIME'))
JWT_SECRET = getenv("JWT_SECRET")
INVALIDATE = -1

cache = redis.Redis(host='web_db', port=6379, db=0)
from dbinit import init
init(cache)

@app.route('/')
def index():
  session_id = request.cookies.get('session_id')
  response = redirect("/welcome" if session_id else "/login")
  return response

@app.route('/login')
def login():
  return f"""{HTML}
  <h1>APP</h1>
  <form action="/auth" method="POST">
    <input type="text"     name="username" placeholder="Username"></input>
    <input type="password" name="password" placeholder="Password"></input>
    <input type="submit"/>
  </form>"""

@app.route('/auth', methods=['POST'])
def auth():
  username = request.form.get('username')
  password = request.form.get('password')

  response = make_response('', 303)

  print(password, file=sys.stderr)
  if password.encode() == cache.hget(username, "password"):
    session_id = str(uuid4())
    response.set_cookie("session_id", session_id, max_age=SESSION_TIME)
    cache.set(session_id, "L")
    response.headers["Location"] = "/welcome"
  else:
    response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
    response.headers["Location"] = "/login"

  return response

@app.route('/welcome')
def welcome():
  session_id = request.cookies.get('session_id')
  if session_id:
    download_token = create_download_token().decode('ascii')
    upload_token = create_upload_token().decode('ascii')
    return f"""{HTML}
    <h1>APP</h1>
    <form action="{PDF}/upload" method="POST" enctype="multipart/form-data">
      <input type="file" name="file"/>
      <input type="hidden" name="token"    value="{upload_token}" />
      <input type="hidden" name="callback" value="{WEB}/callback" />
      <input type="submit"/>
    </form> """
  return redirect("/login")


@app.route('/logout')
def logout():
  session_id = request.cookies.get('session_id')
  cache.delete(session_id)

  response = redirect("/login")
  response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
  return response

@app.route('/callback')
def uploaded():
  session_id = request.cookies.get('session_id')
  fid = request.args.get('fid')
  err = request.args.get('error')
  if not session_id:
    return redirect("/login")

  if err:
    return f"<h1>APP</h1> Upload failed: {err}", 400
  if not fid:
    return f"<h1>APP</h1> Upload successfull, but no fid returned", 500
  content_type = request.args.get('content_type','text/plain')
  return f"<h1>APP</h1> User {session_id} uploaded {fid} ({content_type})", 200

def create_download_token(fid=None):
  return create_token()

def create_upload_token():
  return create_token()

def create_getFileList_token():
  return create_token()

def create_token():
  exp = datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_SESSION_TIME)
  return encode({"iss":"web.company.com", "exp":exp}, JWT_SECRET, "HS256")

def redirect(location):
  response = make_response('', 303)
  response.headers["Location"] = location
  return response
