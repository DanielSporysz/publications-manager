from jwt import decode, InvalidTokenError
from uuid import uuid4
import redis
from flask import Flask
from flask import request
from flask import make_response
from flask import jsonify
import sys
from os import getenv
from dotenv import load_dotenv

app = Flask(__name__)

load_dotenv(verbose=True)
JWT_SECRET = getenv('JWT_SECRET')
PDF = getenv("PDF_HOST")
WEB = getenv("WEB_HOST")

cache = redis.Redis(host='pdf_db', port=6379, db=0)


@app.route('/download/<fid>')
def download(fid):
    if len(fid) == 0:
        return '<h1>PDF</h1> Missing fid', 404

    token = request.headers.get('token') or request.args.get('token')
    if token is None:
        return '<h1>PDF</h1> No token', 401
    if not valid(token):
        return '<h1>PDF</h1> Invalid token', 401
    payload = decode(token, JWT_SECRET)

    p_fid = payload.get('fid')
    p_username = payload.get('username')
    p_action = payload.get('action')
    try:
        if p_fid is None or p_username is None or p_action is None:
            raise Exception()
        if p_fid != fid or p_action != "download":
            raise Exception()
    except:
        return '<h1>PDF</h1> Incorrect token payload', 401

    try:
        f = cache.hget(p_username, p_fid)
        file_name = cache.get(p_fid).decode()

        headers = {"Content-Disposition": "attachment; filename=%s" % file_name}
        return make_response((f, headers))
    except:
        return '<h1>PDF</h1> File not found', 404


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files["file"]
    t = request.headers.get('token') or request.args.get('token')
    c = request.headers.get('callback') or request.args.get('callback')
    fn = request.headers.get('fname') or request.args.get('fname')

    if f is None:
        return redirect(f"{c}?error=No+file+provided") if c \
            else ('<h1>PDF</h1> No file provided', 400)
    if t is None:
        return redirect(f"{c}?error=No+token+provided") if c \
            else ('<h1>PDF</h1> No token provided', 401)
    if not valid(t):
        return redirect(f"{c}?error=Invalid+token") if c \
            else ('<h1>PDF</h1> Invalid token', 401)
    payload = decode(t, JWT_SECRET)

    fid = str(uuid4())
    p_username = payload.get('username')
    p_action = payload.get('action')
    try:
        if p_username is None or p_action is None:
            raise Exception()
        if p_action != "upload":
            raise Exception()
    except:
        return '<h1>PDF</h1> Incorrect token payload', 401

    try:
        cache.hset(p_username, fid, f.read())
        if fn is None:
            cache.set(fid, f.filename)
        else:
            cache.set(fid, fn)
            #cache.bgsave()
        return redirect(f"{c}?filename={f.filename}&fid={fid}") if c \
            else (f'<h1>PDF</h1> Uploaded {f.filename} - {fid}', 200)
    except:
        return redirect(f"{c}?error=Error+while+saving+a+file") if c \
            else ('<h1>PDF</h1> Error while saving a file', 500)


@app.route('/files/<username>', methods=['GET'])
def files(username):
    if len(username) == 0:
        return '<h1>PDF</h1> Missing fid', 404

    token = request.headers.get('token') or request.args.get('token')
    if token is None:
        return '<h1>PDF</h1> No token', 401
    if not valid(token):
        return '<h1>PDF</h1> Invalid token', 401
    payload = decode(token, JWT_SECRET)

    p_username = payload.get('username')
    p_action = payload.get('action')
    try:
        if p_username is None or p_action is None:
            raise Exception()
        if p_action != "fileList":
            raise Exception()
    except:
        return '<h1>PDF</h1> Incorrect token payload', 401

    fnames = {}
    file_ids = cache.hkeys(username)
    if file_ids is not None:
        for fid in file_ids:
            fnames[fid.decode()] = cache.get(fid.decode()).decode()

    return jsonify(fnames)


@app.route('/delete/<fid>', methods=['DELETE'])
def delete(fid):
    # validation
    if len(fid) == 0:
        return '<h1>PDF</h1> Missing fid', 404

    token = request.headers.get('token') or request.args.get('token')
    if token is None:
        return '<h1>PDF</h1> No token', 401
    if not valid(token):
        return '<h1>PDF</h1> Invalid token', 401
    payload = decode(token, JWT_SECRET)

    p_username = payload.get('username')
    p_action = payload.get('action')
    p_fid = payload.get('fid')
    try:
        if p_username is None or p_action is None:
            raise Exception()
        if p_action != "deleteFile":
            raise Exception()
        if p_fid is None or p_fid != fid:
            raise Exception()
    except:
        return '<h1>PDF</h1> Incorrect token payload', 401

    # Handling a file deletion
    try:
        cache.hdel(p_username, fid)
        cache.delete(fid)
        return ('<h1>PDF</h1> File has been deleted.', 200)
    except:
        return ('<h1>PDF</h1> An error occured during the deletion of a file.', 500)


def valid(token):
    try:
        decode(token, JWT_SECRET)
    except InvalidTokenError as e:
        print(str(e), file=sys.stderr)
        return False
    return True


def redirect(location):
    response = make_response('', 303)
    response.headers["Location"] = location
    return response
