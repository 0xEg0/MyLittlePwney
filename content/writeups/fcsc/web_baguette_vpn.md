---
title: 'WEB - Baguette VPN - FCSC 2021'
date: 2023-02-20
draft: false
categories:
  - web
  - fcsc
tags:
  - web
  - fcsc
---

## Analyse
![[Pasted image 20231207143508.png]]

Pour le début nous avons 2 possibilités. Soit on FUZZ les endpoints, soit on fait un joli **CTRL-U** pour trouver les 2 endpoints suivants:
```html
<!--
Changelog :
	- Site web v0
	- /api/image : CDN interne d'images
	- /api/debug
TODO :
	- VPN
-->
```

Lorsque l'on accède au */api/image*, on tombe sur une page qui semble attendre un paramètre GET:
```HTTP
HTTP/1.1 400 BAD REQUEST
Server: Werkzeug/2.2.3 Python/3.7.3
Date: Thu, 07 Dec 2023 13:39:25 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 19
Connection: close

Paramètre manquant
```

Le endpoint */api/debug* est beaucoup plus bavard. Ce dernier nous donne toute une liste d'objets utilisés par l'application **Python** ainsi que les attributs qui en découlent.
![[Pasted image 20231207144610.png]]
Et au milieu de l'output, on a un attribut assez intéressant:
```HTTP
"__file__":"/app/baguettevpn_server_app_v0.py"
```
On peut se douter que c'est le code source de l'application. Et si on essaye d'y accèder à la racine du site, le code source s'affiche : http://172.19.0.2:1337/baguettevpn_server_app_v0.py.
```python
# /usr/bin/env python3
# -*- coding:utf-8 -*-
# -*- requirements:requirements.txt -*-

# Congrats! Here is the flag for Baguette VPN 1/2
#   FCSC{e5e3234f8dae908461c6ee777ee329a2c5ab3b1a8b277ff2ae288743bbc6d880}

import os
import urllib3
import sys
from flask import Flask, request, jsonify, Response
app = Flask(__name__)

@app.route('/')
def index():
    with open('index.html', 'r') as myfile:
        return myfile.read()

@app.route('/api')
def api():
    return Response('OK', status = 200)

@app.route("/api/image")
def image():
    filename = request.args.get("fn")
    if filename:
        http = urllib3.PoolManager()
        return http.request('GET', 'http://baguette-vpn-cdn' + filename).data
    else:
        return Response('Paramètre manquant', status = 400)

@app.route("/api/secret")
def admin():
    if request.remote_addr == '127.0.0.1':
        if request.headers.get('X-API-KEY') == 'b99cc420eb25205168e83190bae48a12':
            return jsonify({"secret": FLAG})
        return Response('Interdit: mauvaise clé d\'API', status = 403)
    return Response('Interdit: mauvaise adresse IP', status = 403)

@app.route("/api/debug")
def debug():
    data = {}
    for k, v in globals().copy().items():
        if not isinstance(v, str):
            data[k] = str(dir(v))
        else:
            data[k] = v
    data['__version__'] = sys.version
    return jsonify(data)

@app.route('/<path:path>')
def load_page(path):
    if '..' in path:
        return Response('Interdit', status = 403)
    try:
        with open(path, 'r') as myfile:
            mime = 'text/' + path.split('.')[-1]
            return Response(myfile.read(), mimetype=mime)
    except Exception as e:
        return Response(str(e), status = 404)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port = 1337)
```

Parmi les fonctions intéressantes:
- **image()**: Va effectuer un GET sur une ressource que l'on contrôle (SSRF)
- **admin()**: Nous donne le flag, a condition que la requête soit faite depuis le localhost et qu'elle contienne un header HTTP particulier.
- **load_page()**: Nous donne le contenu de n'importe quel fichier du server web.

## Exploit
### Check 1
En premier lieu on va devoir exploiter la SSRF pour bypass le premier check de la fonction **admin()**.
La seule contrainte est que notre input est ajoutée à la fin de : http://baguette-vpn-cdn. Donc on ne contrôle pas le domaine cible. Sauf si... On considère que le domaine imposé est enfait un sous domaine:
- input : /api/secret
- URL:    http://baguette-vpn-cdn/api/secret

- input : .localhost:1337/api/secret
- URL:    http://baguette-vpn-cdn.localhost:1337/api/secret

![[Pasted image 20231207150310.png]]

Bingo premier check bypass!

### Check 2
Maintenant on doit trouver un moyen de passer le header
