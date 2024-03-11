# WEB - Baguette VPN - FCSC 2021


## Analyse
![[Pasted image 20231207143508.png]]

Pour le début nous avons 2 possibilités. Soit on FUZZ les endpoints, soit on fait un joli **CTRL-U** pour trouver les 2 endpoints suivants:
```html
&lt;!--
Changelog :
	- Site web v0
	- /api/image : CDN interne d&#39;images
	- /api/debug
TODO :
	- VPN
--&gt;
```

Lorsque l&#39;on accède au */api/image*, on tombe sur une page qui semble attendre un paramètre GET:
```HTTP
HTTP/1.1 400 BAD REQUEST
Server: Werkzeug/2.2.3 Python/3.7.3
Date: Thu, 07 Dec 2023 13:39:25 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 19
Connection: close

Paramètre manquant
```

Le endpoint */api/debug* est beaucoup plus bavard. Ce dernier nous donne toute une liste d&#39;objets utilisés par l&#39;application **Python** ainsi que les attributs qui en découlent.
![[Pasted image 20231207144610.png]]
Et au milieu de l&#39;output, on a un attribut assez intéressant:
```HTTP
&#34;__file__&#34;:&#34;/app/baguettevpn_server_app_v0.py&#34;
```
On peut se douter que c&#39;est le code source de l&#39;application. Et si on essaye d&#39;y accèder à la racine du site, le code source s&#39;affiche : http://172.19.0.2:1337/baguettevpn_server_app_v0.py.
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

@app.route(&#39;/&#39;)
def index():
    with open(&#39;index.html&#39;, &#39;r&#39;) as myfile:
        return myfile.read()

@app.route(&#39;/api&#39;)
def api():
    return Response(&#39;OK&#39;, status = 200)

@app.route(&#34;/api/image&#34;)
def image():
    filename = request.args.get(&#34;fn&#34;)
    if filename:
        http = urllib3.PoolManager()
        return http.request(&#39;GET&#39;, &#39;http://baguette-vpn-cdn&#39; &#43; filename).data
    else:
        return Response(&#39;Paramètre manquant&#39;, status = 400)

@app.route(&#34;/api/secret&#34;)
def admin():
    if request.remote_addr == &#39;127.0.0.1&#39;:
        if request.headers.get(&#39;X-API-KEY&#39;) == &#39;b99cc420eb25205168e83190bae48a12&#39;:
            return jsonify({&#34;secret&#34;: FLAG})
        return Response(&#39;Interdit: mauvaise clé d\&#39;API&#39;, status = 403)
    return Response(&#39;Interdit: mauvaise adresse IP&#39;, status = 403)

@app.route(&#34;/api/debug&#34;)
def debug():
    data = {}
    for k, v in globals().copy().items():
        if not isinstance(v, str):
            data[k] = str(dir(v))
        else:
            data[k] = v
    data[&#39;__version__&#39;] = sys.version
    return jsonify(data)

@app.route(&#39;/&lt;path:path&gt;&#39;)
def load_page(path):
    if &#39;..&#39; in path:
        return Response(&#39;Interdit&#39;, status = 403)
    try:
        with open(path, &#39;r&#39;) as myfile:
            mime = &#39;text/&#39; &#43; path.split(&#39;.&#39;)[-1]
            return Response(myfile.read(), mimetype=mime)
    except Exception as e:
        return Response(str(e), status = 404)

if __name__ == &#39;__main__&#39;:
    app.run(host=&#39;0.0.0.0&#39;, port = 1337)
```

Parmi les fonctions intéressantes:
- **image()**: Va effectuer un GET sur une ressource que l&#39;on contrôle (SSRF)
- **admin()**: Nous donne le flag, a condition que la requête soit faite depuis le localhost et qu&#39;elle contienne un header HTTP particulier.
- **load_page()**: Nous donne le contenu de n&#39;importe quel fichier du server web.

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


---

> Author:   
> URL: https://0xeg0.github.io/MyLittlePwney/writeups/fcsc/web_baguette_vpn/  

