---
title: 🪜 Kernel Privesc 🪜
date: 2024-02-19
draft: false
description: Introduction au pwn kernel, concept d'élévation des privilèges d'un process.
categories:
  - attacks
  - kernel
tags:
  - pwn
  - kernel
---
## Overview

L'objectif de ce post est d'aborder la couche d'abstraction nécéssaire à la compréhension du pwn kernel.
Pour cela, il est nécéssaire de comprendre comment les différents process interagissent avec le kernel, et comment un contrôle de flow d'execution en kernel-mode peut nous permettre d'améliorer nos privilèges en user-land.
## Process x Kernel
Il est important de noter que l'on interagit avec le kernel de pleins de manières différentes. Que ce soit en modifiant le filesystem, avec des syscalls, en communiquant avec des devices...
Toutes ces actions nécéssitent une intervention du kernel au niveau des process qui les initient.

Pour comprendre et manipuler les process, le kernel linux utilise une structure [task_struct](https://github.com/torvalds/linux/blob/master/include/linux/sched.h#L748) contenant toutes le informations dont il a besoin : PID, état du process, niveau de permissions...
Il sauvegarde la **task_struct** de tous les process en mémoire, sous forme de liste chainée.
![task_struct](/images/task_struct.png)
## Privesc
Puisque le kernel peut modifier la structure d'un process, alors il peut modifier les permissions de ce process, et notamment les passer a root.
Ainsi, si on trouve une faille niveau kernel qui nous permet de prendre le contrôle du flow d'execution, alors nous pouvons simplement lancer un process en user-land, augmenter ses privileges côté kernel et retourner en user-land.

Pour faire cela, on va donc modifier la **task_struct** du process qu'on a lancé et changer ses privilèges. Comme les privilèges d'une **task_struct** sont, eux aussi, définis sous forme de structure, on va faire appel à des fonctions kernel pour modifier proprement la **task_struct**.
```c title:/linux/sched.h#L1062
/* Process credentials: */

	/* Tracer's credentials at attach: */
	const struct cred __rcu		*ptracer_cred;

	/* Objective and real subjective task credentials (COW): */
	const struct cred __rcu		*real_cred;

	/* Effective (overridable) subjective task credentials (COW): */
	const struct cred __rcu		*cred;

```

Les fonctions *commit_creds()* et *prepare_kernel_cred()* vont nous permettre de faire cela.
Pour les appeler correctement, a partir de leur adresse, il faut d'abord les définir.

```c title:exploit.c
unsigned long __attribute__((regparm(3))) (*commit_creds)(unsigned long cred);
unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred)(unsigned long cred);

void escalate_privs(void){
	commit_creds = 0x...;
	prepare_kernel_cred = 0x...;
	commit_creds(prepare_kernel_cred(0));
}
```

| NB: Il y a plusieurs moyens de trouver les adresses de fonctions kernel. Le plus simple est de lire le fichier */proc/kallsyms* qui map les adresses et le symboles kernels. |
| --- |

II ne reste donc plus qu'à appeler la fonction *escalate_privs()*. Ce qui n'est possible que si le kernel a des droits d'execution en user-land (pas de **SMEP**). Sinon il faudra trouver un moyen détourné de faire l'appel aux fonctions.

Et maintenant le process détient des privilèges root sur la machine.

## TLDR
Pour simplifier, le but est d'exploiter une vulnerabilité pour prendre le contrôle du flow d'execution côté kernel. Ensuite, on va utiliser les fonctions kernel *commit_creds()* et *prepare_kernel_cred()* pour modifier les privilèges de notre process. Enfin, on va retourner en user-land pour continuer l'execution de notre process avec les privilèges ameliorés.
![Kernel Privesc](/images/kernel_privesc.png)
