from flask import Flask
from flask import request
from flask import make_response
from flask import render_template
from flask import jsonify
from flask import redirect
from uuid import uuid4
import json
import requests
import redis
import rusers
import rsessions
import tokenscrt
from dotenv import load_dotenv
from os import getenv
import sys
from jwt import decode, InvalidTokenError

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
        return my_redirect("/welcome")
    else:
        return my_redirect("/login")


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
        publications = get_pub_list(username)

        return render_template("welcome.html", package=zip_of_file_list,
                               upload_token=upload_token, PDF=PDF, WEB=WEB, 
                               username=username.decode(), publications=publications)
    else:
        return my_redirect("/login")


def get_pub_list(username):
    publications_titles = []
    publications_ids = []

    pub_ids = cache.hkeys(username)
    if pub_ids is not None:
        for pid in pub_ids:
            string_pub = cache.hget(username, pid.decode()).decode()
            pub = json.loads(string_pub)

            publications_titles.append(pub["title"])
            publications_ids.append(pub["id"])

    return zip(publications_titles, publications_ids)

def get_zip_of_file_list(username, list_token):
    req = requests.get("http://pdf:5000/files/" +
                       username + "?token=" + list_token)

    file_names = []
    file_ids = []
    download_tokens = []
    delete_tokens = []
    if req.status_code == 200:
        payload = req.json()
        for fid in payload.keys():
            token = tokens_manager.create_download_token(
                username, fid).decode('ascii')

            file_names.append(payload[fid])
            file_ids.append(fid)
            download_tokens.append(token)
            delete_tokens.append(tokens_manager.create_delete_token(username, fid).decode('ascii'))

    return zip(file_names, file_ids, download_tokens, delete_tokens)


@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')
    if session_id is not None:
        sessions_manager.delete_session(session_id)

    response = my_redirect("/login")
    response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
    return response


@app.route('/publication/<pid>', methods=['GET'])
def view_publication(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id', 404

    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        publication_binary = cache.hget(username, pid)
        if publication_binary is None:
            return '<h1>PDF</h1> No such publication', 404

        publication = json.loads(publication_binary.decode())
        return render_template("viewpublication.html", username=username.decode(), publication=publication)
    else:
        return my_redirect("/login")

@app.route('/delete/publication/<pid>', methods=['POST'])
def delete_publication(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id', 404

    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        try:
            cache.hdel(username, pid)
            msg="Publication " + pid + " has been deleted successfully."
        except:
            msg="An error occured while deleting a publication!"
        return render_template("callback.html", msg=msg, username=username.decode())
    else:
        return my_redirect("/login")

@app.route('/callback')
def uploaded():
    session_id = request.cookies.get('session_id')
    if not session_id or not sessions_manager.validate_session(session_id):
        return my_redirect("/login")

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

@app.route('/callback-deletion')
def deleted():
    session_id = request.cookies.get('session_id')
    if not session_id or not sessions_manager.validate_session(session_id):
        return my_redirect("/login")

    fid = request.args.get('fid') or request.headers.get('fid')
    err = request.args.get('error')
    username = sessions_manager.get_session_user(session_id).decode()

    msg = []
    if err:
        msg = "Deletion failed: " + str(err)
    elif not fid:
        msg = "Deletion successfull, but no fid/file name returned."
    else:
        msg = "File " + str(fid) + " deleted successfully."

    return render_template("callback.html", msg=msg, username=username)


def my_redirect(location):
    response = make_response('', 303)
    response.headers["Location"] = location
    return response


'''


Publications API
'''


@app.route('/api/auth-token', methods=['GET'])
def get_auth_token():
    login = request.headers.get('login') or request.args.get('login')
    given_password = request.headers.get(
        'password') or request.args.get('password')

    if usrs_manager.validate_credentials(login, given_password):
        token = tokens_manager.create_auth_token(login)
        responseObject = {
            'auth_token': token.decode()
        }
        return make_response(jsonify(responseObject)), 201
    else:
        return make_response("Incorrect credentials."), 401


@app.route('/api/file-list', methods=['GET'])
def get_filelist():
    auth_token = request.headers.get(
        'auth_token') or request.args.get('auth_token')
    if auth_token is None:
        return '<h1>WEB</h1> No token', 401
    if not valid(auth_token):
        return '<h1>WEB</h1> Invalid token', 401
    payload = decode(auth_token, JWT_SECRET)

    username = payload.get('username')
    if username is None:
        return '<h1>WEB</h1> Incorrect token', 401
    list_token = tokens_manager.create_getFileList_token(username)

    req = requests.get("http://pdf:5000/files/" +
                       username + "?token=" + list_token.decode())

    if req.status_code == 200:
        responseObject = {}
        payload = req.json()
        for fid in payload.keys():
            responseObject[fid] = payload[fid]
        return make_response(jsonify(responseObject)), 201
    else:
        return '<h1>WEB</h1> Error returning list of files.', 500


def valid(token):
    try:
        decode(token, JWT_SECRET)
    except InvalidTokenError as e:
        print(str(e), file=sys.stderr)
        return False
    return True


@app.route('/api/pub-list', methods=['GET'])
def get_publist():
    auth_token = request.headers.get(
        'auth_token') or request.args.get('auth_token')
    if auth_token is None:
        return '<h1>WEB</h1> No token', 401
    if not valid(auth_token):
        return '<h1>WEB</h1> Invalid token', 401
    payload = decode(auth_token, JWT_SECRET)

    username = payload.get('username')
    if username is None:
        return '<h1>WEB</h1> Incorrect token', 401

    pubs = {}
    pub_ids = cache.hkeys(username)
    if pub_ids is not None:
        for pid in pub_ids:
            pubs[pid.decode()] = cache.hget(username, pid.decode()).decode()

    return make_response(jsonify(pubs)), 201


@app.route('/api/new-pub', methods=['POST'])
def create_pub():
    auth_token = request.form["auth_token"]
    str_pub = request.form["publication"]

    if auth_token is None:
        return '<h1>WEB</h1> No token', 401
    if not valid(auth_token):
        return '<h1>WEB</h1> Invalid token', 401
    payload = decode(auth_token, JWT_SECRET)

    username = payload.get('username')
    if username is None:
        return '<h1>WEB</h1> Incorrect token', 401

    # saving a publication
    try:
        pid = str(uuid4())
        # Recreate publication to remove any extra fields
        json_pub = json.loads(str_pub)
        pub = {"id": pid, "title": json_pub["title"], "authors": json_pub["authors"], "year": json_pub["year"],
               "publisher": json_pub["publisher"], "files": json_pub["files"]}
        cache.hset(username, pid, json.dumps(pub))

        return '<h1>WEB</h1> Publication has been posted.', 201
    except:
        return '<h1>WEB</h1> Error during posting a publication.', 500


@app.route('/api/update-pub', methods=['PUT'])
def update_pub():
    auth_token = request.form["auth_token"]
    str_pub = request.form["publication"]
    pid = request.form["pid"]

    if auth_token is None:
        return '<h1>WEB</h1> No token', 401
    if not valid(auth_token):
        return '<h1>WEB</h1> Invalid token', 401
    payload = decode(auth_token, JWT_SECRET)

    username = payload.get('username')
    if username is None:
        return '<h1>WEB</h1> Incorrect token', 401

    # saving a publication
    try:
        json_pub = json.loads(str_pub)
        pub = {"id": pid, "title": json_pub["title"], "authors": json_pub["authors"], "year": json_pub["year"],
                "publisher": json_pub["publisher"], "files": json_pub["files"]}
        cache.hset(username, pid, json.dumps(pub))
        return '<h1>WEB</h1> Publication has been posted.', 201
    except:
        return '<h1>WEB</h1> Error during posting a publication.', 500


@app.route('/api/del-pub', methods=['DELETE'])
def delete_pub():
    auth_token = request.headers.get(
        'auth_token') or request.args.get('auth_token')
    pid = request.headers.get('pid') or request.args.get('pid')

    if auth_token is None:
        return '<h1>WEB</h1> No token', 401
    if not valid(auth_token):
        return '<h1>WEB</h1> Invalid token', 401
    payload = decode(auth_token, JWT_SECRET)

    username = payload.get('username')
    if username is None:
        return '<h1>WEB</h1> Incorrect token', 401
    if pid is None:
        return '<h1>WEB</h1> Incorrect request. Missing pid.', 400

    try:
        cache.hdel(username, pid)
        return '<h1>WEB</h1> Publication has been deleted.', 200
    except:
        return '<h1>WEB</h1> Error deleting a publication.', 500


@app.route('/api/file/download', methods=['GET'])
def download_file():
    auth_token = request.headers.get(
        'auth_token') or request.args.get('auth_token')
    fid = request.headers.get('fid') or request.args.get('fid')

    if auth_token is None:
        return '<h1>WEB</h1> No token', 401
    if not valid(auth_token):
        return '<h1>WEB</h1> Invalid token', 401
    payload = decode(auth_token, JWT_SECRET)

    username = payload.get('username')
    if username is None:
        return '<h1>WEB</h1> Incorrect token', 401
    download_token = tokens_manager.create_download_token(username, fid)

    return redirect("https://web.company.com/download/" + fid + "?token=" + download_token.decode(), code=302)


@app.route('/api/file/upload', methods=['POST'])
def upload_file():
    auth_token = request.form["auth_token"]
    f = request.files["file"]

    if auth_token is None:
        return '<h1>WEB</h1> No token', 401
    if not valid(auth_token):
        return '<h1>WEB</h1> Invalid token', 401
    payload = decode(auth_token, JWT_SECRET)

    username = payload.get('username')
    if username is None:
        return '<h1>WEB</h1> Incorrect token', 401
    upload_token = tokens_manager.create_upload_token(username)

    req = requests.post("http://pdf:5000/upload" + "?token=" +
                        upload_token.decode() + "&fname=" + f.filename, files=[("file", f)])

    if req.status_code == 200:
        return '<h1>WEB</h1> File has been uploaded', 200
    else:
        return '<h1>WEB</h1> An error occurred during file uploading.', 500


@app.route('/api/file/delete', methods=['DELETE'])
def delete_file():
    auth_token = request.headers.get(
        'auth_token') or request.args.get('auth_token')
    fid = request.headers.get('fid') or request.args.get('fid')

    if auth_token is None:
        return '<h1>WEB</h1> No token', 401
    if not valid(auth_token):
        return '<h1>WEB</h1> Invalid token', 401
    payload = decode(auth_token, JWT_SECRET)

    username = payload.get('username')
    if username is None:
        return '<h1>WEB</h1> Incorrect token', 401
    if fid is None:
        return '<h1>WEB</h1> Incorrect request. Missing fid.', 400

    deletion_token = tokens_manager.create_delete_token(username, fid)

    req = requests.delete("http://pdf:5000/delete/" +
                          fid + "?token=" + deletion_token.decode())

    if req.status_code == 200:
        return '<h1>WEB</h1> File has been deleted', 200
    else:
        return '<h1>WEB</h1> An error occurred during file deletion', 500
