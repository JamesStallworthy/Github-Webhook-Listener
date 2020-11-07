#!/usr/bin/env python

#Author: James Stallworthy
#Date: 05/11/2020

import subprocess
import hmac
import json
import ipaddress
import requests
from flask import Flask, request

config = json.loads(open("./config.json").read())

route = config["route"]
secret = config["secret"].encode('UTF-8')
deploymentScript = config["deploymentScript"]

metaData = requests.get("https://api.github.com/meta")
webHookIPs = json.loads(metaData.text)["hooks"]

app = Flask(__name__)

@app.route(route, methods = ['POST'])
def hello_world():
    validIP = False
    for cidr in webHookIPs:
        if ipaddress.ip_address(request.headers.get('X-Real-IP')) in ipaddress.ip_network(cidr):
            validIP = True

    if not validIP:
        return '', 403

    req_signature = request.headers.get('X-Hub-Signature')
    if req_signature is None:
        return '', 403

    sha_type, req_signature = req_signature.split('=')

    if sha_type != 'sha1':
        return 403

    calc_signature = hmac.new(secret, request.data, digestmod='sha1').hexdigest()

    if not hmac.compare_digest(str(calc_signature), req_signature):
        return '', 403
    if not str(calc_signature) == req_signature:
        return '', 403

    if request.headers.get('X-GitHub-Event') == 'push':
        subprocess.Popen(["sh",deploymentScript])

    return '', 204

app.run(port=3000)
