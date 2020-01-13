from authlib.integrations.flask_client import OAuth
import authlib
from jose import jwt
from flask_cors import cross_origin
from flask import Flask, request, jsonify, _request_ctx_stack
from functools import wraps
from six.moves.urllib.request import urlopen
from flask import Flask, request, make_response, render_template, jsonify, redirect, Response
from six.moves.urllib.parse import urlencode
from uuid import uuid4
from ast import literal_eval
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
import http.client


app = Flask(__name__)

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id='OAlnyEG2QDnHVOYVv0kPd7s4bqSNQk9E',
    client_secret='B3W-_SVYKjx564Ww-_QS7Kp71dBu3c5j-ckeEvNnOgXjB5su7z1Btnq_g7jiHz9j',
    api_base_url='https://dev-0n-bx69c.eu.auth0.com',
    access_token_url='https://dev-0n-bx69c.eu.auth0.com/oauth/token',
    authorize_url='https://dev-0n-bx69c.eu.auth0.com/authorize',
    client_kwargs={
        'scope': 'openid profile email',
    }
)
AUTH0_SESSIONS_KEY_TO_REDIS = "auth0_sessions"

PUBLIC_PID_KEY_TO_REDIS = "PUBLIC_PID_KEY_TO_REDIS"

load_dotenv(verbose=True)
PDF = getenv("PDF_HOST")
WEB = getenv("WEB_HOST")
SESSION_TIME = int(getenv("SESSION_TIME"))
JWT_SESSION_TIME = int(getenv('JWT_SESSION_TIME'))
JWT_SECRET = getenv("JWT_SECRET")
INVALIDATE = -1
app.secret_key = 'test'

cache = redis.Redis(host='web_db', port=6379, db=0)

usrs_manager = rusers.UsersManager(cache)
usrs_manager.init_redis_with_users()  # DEV method
sessions_manager = rsessions.SessionsManager(cache, SESSION_TIME)
tokens_manager = tokenscrt.TokenCreator(JWT_SESSION_TIME, JWT_SECRET)

def event_stream():
    pubsub = cache.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe('pub')
    for message in pubsub.listen():
        print("SEND MESSAGE TO CLIENTS, NEW PUB", file=sys.stderr)
        yield 'New publication: %s' % message['data']

@app.route('/stream')
def stream():
    print("NEW CLIENT ASKS FOR STREAM", file=sys.stderr)
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/')
def index():
    session_id = request.cookies.get('session_id')
    if session_id is not None and sessions_manager.validate_session(session_id):
        return my_redirect("/welcome")
    else:
        return my_redirect("/logout")


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


@app.route('/auth0-redirect')
def redirect_to_auth0():
    return auth0.authorize_redirect(redirect_uri='https://web.company.com/auth0-callback')


@app.route('/auth0-callback')
def greet_auth0():
    auth0.authorize_access_token()
    resp = auth0.get('userinfo')
    userinfo = resp.json()

    if userinfo['email_verified'] == False:
        return "<h1>WEB</h1> You cannot use this account to log in." , 401

    session_id = sessions_manager.create_session(userinfo["email"])
    cache.hset(AUTH0_SESSIONS_KEY_TO_REDIS, session_id, userinfo["email"])

    response = make_response('', 303)
    response.set_cookie("session_id", session_id, max_age=SESSION_TIME)
    response.headers["Location"] = "/welcome"

    return response


@app.route('/welcome')
def welcome():
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()
        upload_token = tokens_manager.create_upload_token(
            username).decode('ascii')

        files = get_zip_of_file_list(username)
        publications = get_zip_of_pub_list(username)

        return render_template("welcome.html", package=files,
                               upload_token=upload_token, PDF=PDF, WEB=WEB,
                               username=username, publications=publications)
    else:
        return my_redirect("/logout")


def get_zip_of_pub_list(username):
    publications_titles = []
    publications_ids = []

    username = username.encode()
    pub_ids = cache.hkeys(username)
    if pub_ids is not None:
        for pid in pub_ids:
            string_pub = cache.hget(username, pid.decode()).decode()
            pub = json.loads(string_pub)

            publications_titles.append(pub["title"])
            publications_ids.append(pub["id"])

    return zip(publications_titles, publications_ids)


def get_zip_of_file_list(username):
    list_token = tokens_manager.create_getFileList_token(
        username).decode('ascii')

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
            delete_tokens.append(tokens_manager.create_delete_token(
                username, fid).decode('ascii'))

    return zip(file_names, file_ids, download_tokens, delete_tokens)


@app.route('/logout')
def logout():
    session_id = request.cookies.get('session_id')

    if session_id is not None:
        sessions_manager.delete_session(session_id)

        # if it's auth0 session
        if cache.hget(AUTH0_SESSIONS_KEY_TO_REDIS, session_id):
            params = {'returnTo': 'https://web.company.com',
                'client_id': 'OAlnyEG2QDnHVOYVv0kPd7s4bqSNQk9E'}
            return redirect(auth0.api_base_url + '/v2/logout?' + urlencode(params))

    response = my_redirect("/login")
    response.set_cookie("session_id", "INVALIDATE", max_age=INVALIDATE)
    return response


@app.route('/account', methods=['GET'])
def account_management():
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        # Check if it's auth0 session
        if cache.hget(AUTH0_SESSIONS_KEY_TO_REDIS, session_id):
            msg = "You cannot manage your auth0 account here"
            return render_template("error_callback.html", username=username, msg=msg), 400

        return render_template("account.html", PDF=PDF, WEB=WEB, username=username)
    else:
        return my_redirect("/logout")

@app.route('/update-password', methods=['POST'])
def update_password():
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    password = request.form.get('password')
    new_password = request.form.get('newPassword')
    re_new_password = request.form.get('reNewPassword')

    # Check if it's auth0 session
    if cache.hget(AUTH0_SESSIONS_KEY_TO_REDIS, session_id):
        msg = "You cannot manage your auth0 account here"
        return render_template("error_callback.html", username=username, msg=msg), 400

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        if not password or not new_password or not re_new_password:
            msg = "The form is missing some fields"
            return render_template("error_callback.html", username=username, msg=msg), 400
        if new_password != re_new_password:
            msg = "Fields with new password don't match"
            return render_template("error_callback.html", username=username, msg=msg), 400
        if not usrs_manager.validate_credentials(username, password):
            msg = "Wrong password"
            return render_template("error_callback.html", username=username, msg=msg), 401

        usrs_manager.register_user(username, new_password, password_change=True)

        msg = "Password has been changed sucessfully"
        return render_template("callback.html", username=username, msg=msg)
    else:
        return my_redirect("/logout")


@app.route('/publication/<pid>', methods=['GET'])
def view_publication(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id', 404

    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()
        publication_binary = cache.hget(username, pid)
        if publication_binary is None:
            return '<h1>PDF</h1> No such publication', 404

        publication = json.loads(publication_binary.decode())
        list_of_file_ids = str(publication["files"]).replace(
            '[', '').replace(']', '').replace(',', '').split()

        # fetching file names from PDF service, publication contains only file ids
        req = requests.get("http://pdf:5000/files/" + username
                           + "?token=" + tokens_manager.create_getFileList_token(username).decode())
        file_ids = []
        file_display_names = []
        file_download_tokens = []
        if req.status_code == 200:
            payload = req.json()

        # preparing display names for files and download tokens
        for file_id in list_of_file_ids:
            file_ids.append(file_id)
            file_download_tokens.append(
                tokens_manager.create_download_token(username, file_id).decode())
            if req.status_code == 200 and file_id in payload.keys():
                file_display_names.append(
                    payload[file_id] + " (" + file_id + ")")
            elif req.status_code != 200:
                file_display_names.append(file_id)
            else:
                file_display_names.append(
                    "FILE HAS BEEN DELETED (" + file_id + ")")

        return render_template("viewpublication.html", username=username,
                               publication=publication, file_package=zip(file_ids,
                                                                         file_display_names, file_download_tokens),
                               PDF=PDF)
    else:
        return my_redirect("/logout")


@app.route('/new/publication', methods=['POST'])
def new_publication():
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        title = request.form.get("title")
        authors = request.form.get("authors")
        publisher = request.form.get("publisher")
        year = request.form.get("year")
        files = request.form.get("files")

        if not title or not authors or not year or not publisher:
            return '<h1>WEB</h1> Incorrect request. The form must contain title, authors, publisher and year fields.', 400

        # saving a publication
        try:
            pid = str(uuid4())
            pub = {"id": pid, "title": title, "authors": authors, "year": year,
                   "publisher": publisher, "files": files}
            cache.hset(username, pid, json.dumps(pub))

            cache.publish('pub', 'NEW PUB HAS BEEN ADDED')
            print("PUBLISHING", file=sys.stderr)

            msg = "New publication has been created successfully."
            return render_template("callback.html", msg=msg, username=username)
        except:
            return '<h1>WEB</h1> Error during posting a publication.', 500
    else:
        return my_redirect("/logout")


@app.route('/edit/publication/<pid>', methods=["GET"])
def publication_editor(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id.', 404

    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        if pid.encode() not in cache.hkeys(username):
            return '<h1>PDF</h1> Publication not found.', 404

        string_pub = cache.hget(username, pid).decode()
        pub = json.loads(string_pub)
        list_of_file_ids = str(pub["files"]).replace(
            '[', '').replace(']', '').replace(',', '').split()

        return render_template("editpub.html", username=username, pid=pid, pub=pub, list_of_file_ids=list_of_file_ids)
    else:
        return my_redirect("/logout")


@app.route('/update/publication/<pid>', methods=['POST'])
def update_publication(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id.', 404

    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        title = request.form.get("title")
        authors = request.form.get("authors")
        publisher = request.form.get("publisher")
        year = request.form.get("year")
        files = request.form.get("files")

        if not title or not authors or not year or not publisher:
            return '<h1>WEB</h1> Incorrect request. The form must contain title, authors, publisher and year fields.', 400

        # saving a publication
        try:
            if pid.encode() not in cache.hkeys(username):
                return '<h1>WEB</h1> There is no such publication on your list: ' + pid, 404

            pub = {"id": pid, "title": title, "authors": authors, "year": year,
                   "publisher": publisher, "files": files}
            cache.hset(username, pid, json.dumps(pub))

            msg = "Publication has been updated successfully."
            return render_template("callback.html", msg=msg, username=username)
        except:
            return '<h1>WEB</h1> Error during updating a publication.', 500
    else:
        return my_redirect("/logout")


@app.route('/creator/publication', methods=["GET"])
def publication_creator():
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()
        return render_template("createpublication.html", username=username)
    else:
        return my_redirect("/logout")


@app.route('/delete/publication/<pid>', methods=['POST'])
def delete_publication(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id', 404

    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        try:
            if pid.encode() not in cache.hkeys(username):
                return '<h1>WEB</h1> There is no such publication on your list: ' + pid, 404

            cache.hdel(username, pid)
            msg = "Publication " + pid + " has been deleted successfully."
        except:
            msg = "An error occured while deleting a publication!"
        return render_template("callback.html", msg=msg, username=username.decode())
    else:
        return my_redirect("/logout")


@app.route('/attach-file-chooser/publication/<pid>', methods=['GET'])
def chose_attachment(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id', 404

    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        if pid.encode() not in cache.hkeys(username):
            return '<h1>WEB</h1> There is no such publication on your list: ' + pid, 404

        string_pub = cache.hget(username, pid).decode()
        pub = json.loads(string_pub)
        already_attached_fids = str(pub["files"]).replace(
            '[', '').replace(']', '').replace(',', '').split()

        # fetching all user files from PDF server
        list_token = tokens_manager.create_getFileList_token(
            username).decode('ascii')
        req = requests.get("http://pdf:5000/files/" +
                           username + "?token=" + list_token)
        if req.status_code == 200:
            payload = req.json()
            all_fids = payload.keys()

            fids = [x for x in all_fids if x not in already_attached_fids]
            display_names = []
            for fid in fids:
                display_names.append(payload[fid])

            return render_template("attachfile.html", username=username, pub=pub, files=zip(fids, display_names))
        else:
            return '<h1>WEB</h1> There has been an error fetching list of your files.', 500
    else:
        return my_redirect("/logout")


@app.route('/attach-file/publication/<pid>', methods=['POST'])
def attach_file(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id', 404
    fid = request.form.get('fid')
    if fid is None:
        return '<h1>PDF</h1> The form is missing file id to attach.', 400
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        if pid.encode() not in cache.hkeys(username):
            return '<h1>WEB</h1> There is no such publication on your list: ' + pid, 404

        # veryfing if the file belongs to the user
        list_token = tokens_manager.create_getFileList_token(
            username).decode('ascii')
        req = requests.get("http://pdf:5000/files/" +
                           username + "?token=" + list_token)
        if req.status_code == 200:
            payload = req.json()
            user_files = payload.keys()

            if fid not in user_files:
                return '<h1>WEB</h1> You cannot attach files you do not own.', 403
        else:
            return '<h1>WEB</h1> There has been an error verifying if the file to attach belongs to you.', 500

        # adding fid to publication
        string_pub = cache.hget(username, pid).decode()
        pub = json.loads(string_pub)
        already_attached_fids = str(pub["files"]).replace(
            '[', '').replace(']', '').replace(',', '').split()
        already_attached_fids.append(fid)
        pub["files"] = str(already_attached_fids).replace("'", '')
        cache.hset(username, pid, json.dumps(pub))

        msg = 'File ' + fid + ' has been attached to \"' + \
            pub["title"] + '\" successfully.'
        return render_template("callback.html", msg=msg, username=username)
    else:
        return my_redirect("/logout")


@app.route('/dettach-file-chooser/publication/<pid>', methods=['GET'])
def chose_dettachment(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id', 404

    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        if pid.encode() not in cache.hkeys(username):
            return '<h1>WEB</h1> There is no such publication on your list: ' + pid, 404

        string_pub = cache.hget(username, pid).decode()
        pub = json.loads(string_pub)
        already_attached_fids = str(pub["files"]).replace(
            '[', '').replace(']', '').replace(',', '').split()

        # fetching all user files from PDF server to get file names
        list_token = tokens_manager.create_getFileList_token(
            username).decode('ascii')
        req = requests.get("http://pdf:5000/files/" +
                           username + "?token=" + list_token)
        if req.status_code == 200:
            payload = req.json()
            all_fids = payload.keys()
        else:
            return '<h1>WEB</h1> There has been an error fetching list of your files.', 500

        display_names = []
        for fid in already_attached_fids:
            if fid in all_fids:
                display_names.append(payload[fid])
            else:
                display_names.append("FILE HAS BEEN DELETED")

        return render_template("dettachfile.html", username=username, pub=pub, files=zip(already_attached_fids, display_names))

    else:
        return my_redirect("/logout")


@app.route('/dettach-file/publication/<pid>', methods=['POST'])
def dettach_file(pid):
    if len(pid) == 0:
        return '<h1>PDF</h1> Missing publication id', 404
    fid = request.form.get('fid')
    if fid is None:
        return '<h1>PDF</h1> The form is missing file id to dettach.', 400
    session_id = request.cookies.get('session_id')
    username = sessions_manager.get_session_user(session_id)

    if sessions_manager.validate_session(session_id) and username is not None:
        username = username.decode()

        if pid.encode() not in cache.hkeys(username):
            return '<h1>WEB</h1> There is no such publication on your list: ' + pid, 404

        # removing fid to publication
        string_pub = cache.hget(username, pid).decode()
        pub = json.loads(string_pub)
        already_attached_fids = str(pub["files"]).replace(
            '[', '').replace(']', '').replace(',', '').split()
        already_attached_fids.remove(fid)
        pub["files"] = str(already_attached_fids).replace("'", '')
        cache.hset(username, pid, json.dumps(pub))

        msg = 'File ' + fid + ' has been dettached from \"' + \
            pub["title"] + '\" successfully.'
        return render_template("callback.html", msg=msg, username=username)
    else:
        return my_redirect("/logout")


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

    return redirect("https://pdf.company.com/download/" + fid + "?token=" + download_token.decode(), code=303)


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