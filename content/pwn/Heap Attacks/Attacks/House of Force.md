---
title: 🔥 House of Force 🔥
date: 2023-02-20
draft: false
description: fa-solid fa-trash-can fa-fw fa-sm
categories:
  - heap
  - attacks
tags:
  - pwn
  - heap
---
## Overview
L'objectif de cette attaque est d'overwrite les metadata du top chunk pour augmenter sa size. Ainsi on va pouvoir faire des malloc sur un espace mémoire beaucoup plus grand et donc malloc en dehors de la **HEAP**.
## Detail
Dans les versions de la **GLIBC < 2.29**, il n'y a pas de check sur l'intégrité des metadata du top chunk. Ainsi, si la size du top chunk est overwrite, l'algorithme *malloc* fonctionnera quand même.
Comme les chunks sont alloués à partir du top chunk, si on overwrite la size du top chunk, on devrait être en mesure de couvrir l'ensemble des adresses de la mémoire, y compris les addresses en dehors de la heap.

![Malloc from Top Chunk](/images/malloc_chunk_alloc.png)

L'intérêt de cette attaque est de pouvoir overwrite des valeurs à des adresses plus basses que l'adresse de la **HEAP**. Voir de simplement overwrite des valeurs en dehors de la **HEAP**.

![Malloc from Top Chunk](/images/house_of_force.png)

## Exploit
L'attaque en elle même se déroule en 3 étapes : 
- Overflow notre buffer et overwrite la size du *top chunk*. On va le set à une valeur suffisamment grande pour que l'adresse ciblée soit comprise dans la range d'adresses couvertes par le top chunk.
- On fait un malloc pour placer le début du *top chunk* juste avant l'adresse ciblée.
- On effectue un nouveau *malloc()* qui va nous permettre d'atteindre l'adresse ciblée.
## Further use
Pour aller plus loin, on peut tenter d'utiliser cette attaque pour obtenir un shell. 
Pour cela, un stratégie peut être d'overwrite l'adresse du **Malloc hook**. Ce dernier étant utilisé à chaque appel de la fonction *malloc()*, on peut le remplacer par l'adresse de la fonction *system()* et lui passer une adresse pointant vers un **"/bin/sh"**.
Ainsi, chaque nouvel appel à la fonction *malloc()* va hook vers un appel à *system()*.
## Limitations
A partir de la **GLIBC 2.29**, la size du top chunk est vérifiée pour s'assurer que le top chunk ne sorte pas de sa zone mémoire.

[GLIBC Top Chunk Size check](/pwn/heap/mitigations#Top%20Chunk%20Size%20check)
