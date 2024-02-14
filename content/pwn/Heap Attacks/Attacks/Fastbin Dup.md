---
title: 'Fastbin Dup'
date: 2023-02-20
draft: true
description: "fa-solid fa-trash-can fa-fw fa-sm"
categories:
  - heap
  - attacks
tags:
  - pwn
  - heap
---

## Overview
House of Spirit, aussi connu sous le nom de fastbin dup, est une attaque qui vise à exploiter un double free pour obtenir un arbitrary file write, voir une Code Execution.
Cette permet de manipuler les adresses des futurs chunk alloués par malloc, et donc de potentiellement overwrite, n'importe quelle zone mémoire accessible en écriture.

## Details
### Vulnérability
Pour faire une rapide passe sur le **Double Free**, c'est une vulnérabilté qui permet d'exploiter le fonctionnement des [fastbins](Pwn/Heap/Bins#Fastbins) en faisant 2 free sur le même chunk.
Puisque seul la head du [fastbin](Pwn/Heap/Bins#Fastbins) est stocké dans la main arena et que les autre chunks du [fastbin](Pwn/Heap/Bins#Fastbins) ont leur adresse stockée inline, dans le cas d'un [fastbin](Pwn/Heap/Bins#Fastbins) de la forme `chunkA <- chunkB <- chunkA -> NULL`, les données de 1 er chunkA à être *malloc()* seront interprétées comme le FD du 2 ème chunkA à être *malloc()*.
### Schema
Ici nous sommes dans le cas où on a fait un :
```c
chunkA = malloc(0x48)
chunkB = malloc(0x48)

free(chunkA)
free(chunkB)
free(chunkA)
```
![[Pasted image 20240105191021.png]]

## Exploit
La technique d'attaque est de jouer avec le 1 er *malloc()*. Ce qui va se passer est que nous allons enlever le head chunk du [fastbin](Pwn/Heap/Bins#Fastbins) et écrire dans les données. Mais les [fastbins](Pwn/Heap/Bins#Fastbins) utilisent les premiers bytes des chunks free pour référencer le chunk suivant dans le liste. Et grâce au double free, l'adresse du chunk `0x0000` est utilisée pour le premier malloc et pour le dernier. Ainsi, lorsque l'on va malloc le dernier chunk du [fastbin](Pwn/Heap/Bins#Fastbins), les 8 premiers bytes du chunk `0x0000` sont utilisés par le [fastbin](Pwn/Heap/Bins#Fastbins) comme **Forward Pointer**. Donc, en contrôlant les données du chunk `0x0000`, nous contrôlons l'adresse du dernier chunk alloué à partir du `fastbin[0x50]`.

## Further Use
L'objectif de ce genre d'attaque peut être d'effectuer une execution de code. Pour cela il a plusieurs technique différentes, mais l'objectif sera souvent d'overwrite le pointeur d'une fonction ou d'un hook appelé par le programme avec par un **one gadget** par exemple.
Pour cela il faudra passer par un **fake chunk**, autrement dit un chunk proche de l'adresse à overwrite et dont les metadata sont valides. Il faudra ensuite effectuer la technique d'exploitation de base du House of Spirit pour inclure l'adresse de ce fake chunk dans le [fastbin](Pwn/Heap/Bins#Fastbins) correspondant.

Il n'est pas commun de trouver des **fake chunk** parfaitement agencés, avec la bonne size, la proximité suffisante, ... Une technique peut être de créer notre propre **fake chunk** dans la main arena. On peut utiliser 2 [fastbins](Pwn/Heap/Bins#Fastbins) différents pour avoir à une adresse la size et l'autre , l'adresse du **fake chunk**.
![[Pasted image 20240105201209.png]]
