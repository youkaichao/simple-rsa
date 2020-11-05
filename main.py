from flask import Flask, request, make_response, render_template
from lib import *
import json
import time

app = Flask(__name__)


@app.route('/generate', methods=['POST'])
def generate():
    data = json.loads(request.data)
    key_size = int(data['key_size'])
    now = time.time()
    private, public = generate_key_pair(key_size)
    now = '%.4f' % (time.time() - now)
    ans = make_response({
        'p': to_hex(private.p),
        'q': to_hex(private.q),
        'n': to_hex(public.n),
        'e': to_hex(public.e),
        'd': to_hex(private.d),
        'time': now
    })
    ans.content_type = 'application/json'
    return ans


@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = json.loads(request.data)
    n = int(data['n'], base=16)
    e = int(data['e'], base=16)
    message = int(data['message'], base=16)
    public = PublicKey(n, e)
    ans = make_response({
        'cipher': to_hex(public.encrypt(message)),
    })
    ans.content_type = 'application/json'
    return ans


@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = json.loads(request.data)
    p = int(data['p'], base=16)
    q = int(data['q'], base=16)
    d = int(data['d'], base=16)
    cipher = int(data['cipher'], base=16)
    private = PrivateKey(p, q, d)
    ans = make_response({
        'message': to_hex(private.decrypt(cipher)),
    })
    ans.content_type = 'application/json'
    return ans


@app.route('/sign', methods=['POST'])
def sign():
    data = json.loads(request.data)
    p = int(data['p'], base=16)
    q = int(data['q'], base=16)
    d = int(data['d'], base=16)
    message = data['message']
    method = data['method']
    private = PrivateKey(p, q, d)
    ans = make_response({
        'signature': to_hex(private.sign(message, method)),
    })
    ans.content_type = 'application/json'
    return ans


@app.route('/verify', methods=['POST'])
def verify():
    data = json.loads(request.data)
    n = int(data['n'], base=16)
    e = int(data['e'], base=16)
    signature = int(data['signature'], base=16)
    method = data['method']
    message = data['message']
    public = PublicKey(n, e)
    ans = make_response({
        'verified': public.verify(message, signature, method),
    })
    ans.content_type = 'application/json'
    return ans


@app.route('/', methods=['GET'])
def main():
    return render_template('index.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
