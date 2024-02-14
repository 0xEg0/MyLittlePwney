---
title: 'Bins'
date: 2023-02-20
draft: true
description: "fa-solid fa-trash-can fa-fw fa-sm"
categories:
  - heap
tags:
  - pwn
  - heap
---

## Fastbins
Les fastbins sont une collection de listes chaînées permettant de référencer les chunks ayant été free.

Les fastbins sont définis par la taille des chunks qu'ils référencent. En effet, le fastbin 0x20 ne référence que des chunks de tailles 0x20 bytes, le fastbin 0x30 ne référence que des chunks de tailles 0x30 bytes.

Par défaut, il y a 7 fastbins disponibles définis par la variable **global_max_fast**. On a donc des fastbins allant de 0x20 à 0x80.
Mais il est tout à fait possible d'augmenter cette valeur en applant la fonction *mallopt()*. On peut ainsi retrouver des fastbins allant de 0x20 à 0xb0.

Au niveau de l'[arena](Pwn/Heap/Arenas#Layout), un espace mémoire pouvant contenir une adresse est réservé pour chaque fastbin. Ainsi on va placer dans chaque espace mémoire l'adresse du chunk en tête de liste. Pour chaque free chunk, les premiers bytes contiennent le forward pointer (fd) indiquant l'adresse du chunk suivant dans la la liste.
![[Pasted image 20240102161917.png]]
## Unsorted Bins
Le Unsorted Bins a été créé pour optimiser les allocations dynamiques de mémoires, et notamment pour gérer efficacement les *malloc()* juste après avoir *free()*.
Le Unsorted Bins est une circular doubly linked list. Il en existe un seul par Arena. Ce Bins garde la trace des freed chunks ne trouvant pas leur place dans les fastbins. On appel ces chunks les **"normal chunks"**.

Les free chunks sont directement link à l'Unsorted Bin si le Tcache Bin correspondant est full ou si la size ne match pas avec le tcache.
Pour les versions de la libc sans tcache, les free chunks sont link à l'Unsorted Bin s'ils ne peuvent pas être placés dans un fastbin. De plus, s'il est adjacent au top chunk, le chunk free sera directement consolidé au top chunk au lieu d'être placé dans l'Unsorted Bin.

Lorsqu'un chunk est free, l'algo de malloc va vérifier si le chunk peut être consolidé au top chunk, ou au chunk précédent en utilisant le **prev_inuse** flag stocké inline.
A compléter : [...]


## Tcache Bins

## Small Bins

## Large Bins
