---
title: 'Shellcodes'
date: 2023-02-20
draft: true
description: "fa-solid fa-trash-can fa-fw fa-sm"
categories:
  - shellcoding
tags:
  - pwn
  - shellcoding
---

L’objectif principal lors d’une exploitation de binaire est très souvent d’obtenir un shell sur la machine qui l’héberge. Pour cela on utilise des _Shellcodes_. Ce sont des morceau de codes machines que l’ont va tenter de load en mémoire et de faire executer par le binaire.

## Ecrire un Shellcode

Les _Shellcodes_ vont être écris en language assembleur.

Il est aussi possible d’écrire ce que l’on appelle des _Non-Shell Shellcodes_, qui sont des _Shellcodes_ dont l’objectif n’est pas de faire spawn un shell. Par exemple, là où on peut utiliser l’instruction : `execve(”/bin/sh”, NULL, NULL)` dans un shellcode classique, on peut également tenter de simplement ouvrir un fichier avec : `sendfile(1, open(”/flag.txt”, NULL), 0, 1000)`.

Ainsi pour craft un _Shellcode_, nous allons écrire un programme très simple en assembleur, exécutant les actions souhaitées, puis le compiler en fichier ELF et enfin en extraire le code machine.

```assembly
# Shellcode
.global _start
_start:
.intel_syntax noprefix
		mov rax, 59
		lea rdi, [rip+binsh]
		mov rsi, 0
		mov rdx, 0
		syscall
binsh:
		.string "/bin/sh"
```

```sh
# Compile le code
root@test~$ gcc -nostdlib -static shellcode.s -o shellcode-elf

# Extraire le code machine du binaire
root@test~$ objcopy --dump-section .text=raw_shellcode shellcode-elf
```

### Quelques Commandes

```sh
# Compiler un Shellcode
root@test~$ gcc -nostdlib -static shellcode.s -o shellcode-elf

# Extraire le code machine du binaire
root@test~$ objcopy --dump-section .text=raw_shellcode shellcode-elf

# Désassembler le binaire
root@test~$ objdump -M intel -d shellcode-elf

# Evoyer le code machine au stdin d'un process
root@test~$ cat raw_shellcode /dev/stdin | ./vuln

# Strace un programme avec le shellcode en input
root@test~$ cat raw_shellcode | strace ./vuln

# Debug un programme avec le shellcode en input
root@test~$ gdb ./vuln
(gdb) r < raw_shellcode
```

## Debug un Shellcode

L’idéal pour debug un shellcode qui ne semble pas fonctionner, est de commencer par lancer un `strace` dessus. Cela permet de tracer l’ensemble des syscall effectuer avec leurs arguments.

Si cela ne suffit pas, il suffit alors de le debug en dynamique avec `gdb`.

## Cross-Architecture

## Filter bypass

Lorsque l’on rédige un _Shellcode_, il est très commun de faire certaines petites erreurs qui empêche totalement le fonctionnement du . Mais au dela de ça, il est possible d’avoir besoin de bypass certains filtres ou même de devoir simplement adapter notre Shellcode au contexte dans lequel on souhaite l’injecter.

De manière générale, il vaut mieux prendre le réflexe de réfléchir à l’envers lorsque l’on craft un Shellcode. C’est à dire d’abord réfléchir à là où on veut aller avant de savoir par où commencer.

### Petites Erreurs

![[Screenshot from 2023-09-26 18-15-38.png]]

### Forbidden Bytes

Selon le contexte dans lequel notre _Shellcode_ va être lu ou executé, il est souvent necessaire de l’adapter afin de le rendre fonctionnel.

Par exemple, si notre _Shellcode_ est lu avec strcpy, alors la lecture s’arrêtera à la fin string, autrement dit, au premier null bytes rencontré.

![[Screenshot from 2023-09-26 18-19-33.png]]


Heureusement, l’assembleur est un langage très pusissant et il est tout à fait possible de jouer avec les instructions pour manipuler le code machine à la sortie du compiler.

Voici quelques exemples de manipulation du code assembleur :

![[Screenshot from 2023-09-26 18-18-07.png]]

### Forbidden Instructions

Il est également possible que certaines instructions soient bannies ou ne fonctionnent simplement pas. Dans ce cas il est important de se rappeler que, sur un architecture _Von Neumann_, `CODE == DATA`. Ainsi il suffit donc de manipuler les opcodes injectés en mémoire pour bypass ce genre de problèmes.
## Advanced Shellcoding

### Advanced Filters

Il existe certains cas où l’input que l’on va fournir au programme peut être filtrée. Selon le filtres qui sont implémentés, il peut devenir réellement compliqué pour nous d’écrire un _Shellcode_ utile.

La solution dans ce cas est souvent d’utiliser un _Multi-Stage Shellcode_. Le principe est assez simple mais plus compliqué à mettre en place. Suivons cet exemple:

Imaginons que nous pouvons envoyer un Shellcode à notre programme pour qu’il soit executé mais celui-ci est filtré. Les filtres étant trop robustes, il nous est impossible d’obtenir un shell.

Solution: Pour resoudre ce problème, nous pouvons simplement créer un _Shellcode_ qui va lire l’input avec une fonction comme `read()` puis écrire cet input en mémoire. Ainsi l’input envoyé à travers la fonction `read()` du premier _Shellcode_ ne sera soumise à aucun filtre.

### Shellcodes Encoding

????????

## Protections

De nos jours, la protection NX est activé par défaut sur la plus part des compilateurs. Cette protection permet d’éviter d’avoir des zones mémoires accessibles à la fois en écriture et en exécution.

Il reste tout de même possible de bypass ce genre de protections en exploitant un _ROP, JOP, COP_… En faisant un appel à `mprotect()` pour change les droits d’accès sur une zone mémoire ou un appel à `mmap()` pour allouer une nouvelle zone mémoire accessible en _RWX_.

## Tips

- Lorsqu’on on injecte un shellcode dans un process tournant avec un _SUID_, si on veut spawn un shell, il nous faut set le _Real UID_ à la même valeur que l’_Effective UID_ pour ne pas perdre les privilèges. Le _Real UID_ est l’UID de l’utilisateur actuel, quand à l’_Effective UID_, c’est l’UID du user dont les droits sont utilisé pour lancer le process. Pour changer la valueur du _Real UID_, on utilise `setreuid()`.
- Il peut arriver que l’on ai besoin de placer notre shellcode à une addresse différente de là où le binaire écrit notre input. Ex: L’addresse à partir de laquelle le code est executé est aléatoire. Dans ce cas il existe une techinque qui s’appelle le _NOP Sled_. On utilise simplement l’instruction `nop` que l’on va placer autant de fois que necessaire avant notre shellcode. Cette instruction va simplement pointer vers l’instruction suivante. Ainsi quelle que soit l’addresse à partir de laquelle le code est executé, si le `$rip` pointe vers un `nop`, alors il va incrémenter jusqu’à atteindre le début de notre shellcode.

[Exemples](Pwn/Shellcodes/Exemples)

