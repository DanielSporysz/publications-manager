from jwt import decode, InvalidTokenError
from uuid import uuid4
import redis
from flask import Flask
from flask import request
from flask import make_response
from flask import send_file
import json
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
    try:
        p_fid = payload.get('fid')
        p_username = payload.get('username')
        p_action = payload.get('action')
    except:
        return '<h1>PDF</h1> Incorrect token payload', 401

    if p_fid != fid or p_action != "download":
        return '<h1>PDF</h1> Incorrect token payload', 401

    try:
        f = cache.hget(p_username, p_fid)
        filename = cache.get(p_fid).decode()
    except:
        return '<h1>PDF</h1> File not found', 404

    return send_file(f, attachment_filename=filename, as_attachment=True)


@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('file')
    t = request.form.get('token')
    c = request.form.get('callback')

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
    if payload.get("username") is None:
        return redirect(f"{c}?error=Invalid+token") if c \
            else ('<h1>PDF</h1> Invalid token', 401)
    if payload.get('action') is not None and payload.get('action') != "upload":
        return redirect(f"{c}?error=Invalid+token") if c \
            else ('<h1>PDF</h1> Invalid token', 401)

    fid, content_type = str(uuid4()), f.content_type
    username = payload.get("username")

    cache.hset(username, fid, f.read())
    cache.set(fid, f.filename)

    return redirect(f"{c}?filename={f.filename}&fid={fid}&content_type={content_type}") if c \
        else (f'<h1>PDF</h1> Uploaded {f.filename} - {fid}', 200)


@app.route('/files/<username>', methods=['GET'])
def files(username):
    token = request.headers.get('token') or request.args.get('token')
    if len(username) == 0:
        return '<h1>PDF</h1> Missing fid', 404
    if token is None:
        return '<h1>PDF</h1> No token', 401
    if not valid(token):
        return '<h1>PDF</h1> Invalid token', 401
    payload = decode(token, JWT_SECRET)
    if payload.get('action') is not None and payload.get('action') != "fileList":
        return '<h1>PDF</h1> Incorrect token payload', 401

    fnames = {}
    file_ids = cache.hkeys(username)
    if file_ids is not None:
        for fid in file_ids:
            fnames[fid.decode()] = cache.get(fid.decode()).decode()

    return jsonify(fnames)


def valid(token):
    try:
        decode(token, JWT_SECRET)
    except InvalidTokenError as e:
        print(str(e), file=sys.stderr)
        print(str(e), file=sys.stderr)
        print(str(e), file=sys.stderr)
        print(str(e), file=sys.stderr)
        print(str(e), file=sys.stderr)
        print(str(e), file=sys.stderr)
        print(str(e), file=sys.stderr)
        return False
    return True


def redirect(location):
    response = make_response('', 303)
    response.headers["Location"] = location
    return response
