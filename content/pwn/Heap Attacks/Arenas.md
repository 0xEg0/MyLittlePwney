---
title: 'Arenas'
date: 2023-02-20
draft: true
description: "fa-solid fa-trash-can fa-fw fa-sm"
categories:
  - heap
tags:
  - pwn
  - heap
---

### Overview
Les arenas sont des structures de données utilisées par malloc pour administrer les heaps utilisées par les différents process. En théorie, chaque thread peut avoir sa propre arena. Mais le nombre maxium d'arenas disponibles pour un process dépend du nombre de cores disponibles à ce process.

### Details
Les arenas sont donc utilisées par malloc pour administrer les heaps. Leur principale utilitée est de gérer le recyclage des free chunks. Pour faire cela, elles sont constituées de [bins](/MyLittlePwney/pwn/heap-attacks/bins/), des structures de données qui vont référencer efficacement les chunks qui ont été free.

Les arenas sont définies selon la struct *malloc_state*. De nouvelles arenas peuvent être créées et initialisées via les fonctions *_init_new_arena()* et *malloc_init_state()*. 

### Layout
Une arena est designée comme une structure de données. Il est donc necessaire de comprendre comment les données sont agencées pour savoir comment interpréter une arena à partir des données en mémoire.
![Arenas Layout](/MyLittlePwney/images/arenas_layout.png)
#### mutex
Un mutex agit comme une sorte de gardien d'une zone mémoire. Il permet d'éviter qu'une zone mémoire ne soit altérée par une utilisation simultanée venant de différents thread. C'est une protection assez efficace lorsque plusieurs thread essaient d'accèder à une même zone mémoire.

Ainsi, le premier thread à accèder à la zone va d'abord vérifier si la valeur du **mutex** indique que la zone est libre. Si c'est le cas il va changer la valeur pour indiquer que la zone mémoire est lock, puis il va y accèder. Sinon, il va attendre que le thread qui l'occupe ai fini ses modifications et delock le mutex.

#### flags
Donne diverses informations sur l'état de l'arena. Par exemple, c'est dans la section flags qu'il sera dit si l'arena est collée à d'autres donnée en mémoire.

Les flags sont assez spécifique, il est important de se renseigner pour connaitre leur valeur et comment les manipuler.
#### have_fastchunks
C'est un booléen qui indique que les fastbins ne doivent pas être nul. Il est initialisé chaque fois qu'un chunk est link à un fastbin et il remit à NULL lorsqu'on fait un appel à *malloc_consolidate()*.

Pour **GLIBC <= 2.26**, cette valeur fait partie des [flags](#flags) de l'arena.
#### top
Selon le code source de malloc, un top chunk est le chunk le plus haut de la heap. Il limite la heap et la fin de la mémoire disponible. Dès qu'une arena est initialisée, un top chunk est créé. Il n'en existe, d'ailleurs, qu'un par arena. C'est de ce top chunk que va venir l'espace mémoire alloué lorsqu'il ne peut pas venir des bins.

