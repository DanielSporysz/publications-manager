from flask import Flask
from flask import request
from flask import make_response
from flask import render_template
from flask import jsonify
import requests
import redis
import rusers
import rsessions
import tokenscrt
from dotenv import load_dotenv
from os import getenv

app = Flask(__name__)

load_dotenv(verbose=True)
PDF = getenv("PDF_HOST")
WEB = getenv("WEB_HOST")
SESSION_TIME = int(getenv("SESSION_TIME"))
JWT_SESSION_TIME = int(getenv('JWT_SESSION_TIME'))
JWT_SECRET = getenv("JWT_SECRET")
INVALIDATE = -1

cache = redis.Redis(host='web_db', port=6379, db=0)
usrs_manager = rusers.UsersManager(cache)
usrs_manager.init_redis_with_users()  # DEV method
sessions_manager = rsessions.SessionsManager(cache)
tokens_manager = tokenscrt.TokenCreator(JWT_SESSION_TIME, JWT_SECRET)


@app.route('/')
def index():
    session_id = request.cookies.get('session_id')
    if session_id is not None and sessions_manager.validate_session(session_id):
        return redirect("/welcome")
    else:
        return redirect("/login")


@app.route('/login')
def login():
    return render_template("login.html")


@app.route('/auth', methods=['POST'])
def auth():
    username = request.form.get('username')
    password = request.form.get('password')

    response = make_response('', 303)
    if username is not None and password is not None and \
            usrs_manager.validate_credentials(username, password):
        session_id = sessions_manager.create_session(username)
        response.set_cookie("session_id", session_id, max_age=SESSION_TIME)
        response.headers["Location"] = "/welcome"
    else:
        response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
        response.headers["Location"] = "/login"

    return response


@app.route('/welcome')
def welcome():
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        upload_token = tokens_manager.create_upload_token(
            username.decode()).decode('ascii')
        list_token = tokens_manager.create_getFileList_token(
            username.decode()).decode('ascii')
        zip_of_file_list = get_zip_of_file_list(username.decode(), list_token)

        return render_template("welcome.html", package=zip_of_file_list,
                               upload_token=upload_token, PDF=PDF, WEB=WEB, username=username.decode())
    else:
        return redirect("/login")


def get_zip_of_file_list(username, list_token):
    req = requests.get("http://pdf:5000/files/" +
                       username + "?token=" + list_token)

    file_names = []
    file_ids = []
    download_tokens = []
    if req.status_code == 200:
        payload = req.json()
        for fid in payload.keys():
            token = tokens_manager.create_download_token(
                username, fid).decode('ascii')

            file_names.append(payload[fid])
            file_ids.append(fid)
            download_tokens.append(token)

    return zip(file_names, file_ids, download_tokens)


@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id is not None:
        sessions_manager.delete_session(session_id)

    response = redirect("/login")
    response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
    return response


@app.route('/callback')
def uploaded():
    session_id = request.cookies.get('session_id')
    if not session_id or not sessions_manager.validate_session(session_id):
        return redirect("/login")

    fname = request.args.get('filename')
    fid = request.args.get('fid')
    err = request.args.get('error')
    username = sessions_manager.get_session_user(session_id).decode()

    msg = []
    if err:
        msg = "Upload failed: " + str(err)
    elif not fid or not fname:
        msg = "Upload successfull, but no fid/file name returned."
    else:
        msg = "File " + str(fname) + " uploaded successfully."

    return render_template("callback.html", msg=msg, username=username)


def redirect(location):
    response = make_response('', 303)
    response.headers["Location"] = location
    return response


'''


Publications API
'''

@app.route('/api/utoken')
def api0():
    login = request.headers.get('login') or request.args.get('login')
    given_password = request.headers.get('password') or request.args.get('password')

    if usrs_manager.validate_credentials(login, given_password):
        token = tokens_manager.create_user_token(login)
        responseObject = {
            'status': 'success',
            'auth_token': token.decode()
        }
        return make_response(jsonify(responseObject)), 201
    else:
        return make_response("Incorrect credentials."), 401


# TODO return list of user's publications
@app.route('/api/publications/list')
def api20():
    return "hello", 200


# TODO receive and update publication
@app.route('/api/publications/update')
def api21():
    return "hello", 200


# TODO receive and save new publication
@app.route('/api/publications/new')
def api22():
    return "hello", 200


# TODO handle publication deletion
@app.route('/api/publications/delete')
def api23():
    return "hello", 200


# TODO handle file download
@app.route('/api/publications/file/download')
def api41():
    return "hello", 200


# TODO handle file upload
@app.route('/api/publications/file/upload')
def api42():
    return "hello", 200


# TODO handle file deletion
@app.route('/api/publications/file/delete')
def api43():
    return "hello", 200
