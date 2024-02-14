---
title: 'Mitigations'
date: 2023-02-20
draft: true
description: "fa-solid fa-trash-can fa-fw fa-sm"
categories:
  - heap
tags:
  - pwn
  - heap
---

## Double Free
### Mitigation
Beaucoup de versions de la LIBC implémentent maintenant une protection pour éviter qu'un programme ne *free()* 2 fois le même chunk. Si c'était possible, alors un même chunk serait link 2 fois dans un même [fastbin](Pwn/Heap/Bins#Fastbins). Ce qui pourrait non seulement casser tout le programme, mais aussi laisser place à l'exploitation de cette vulnérabilité grâce à l'attaque du [fastdup](House%20of%20Spirit%20-%20Fastbin%20Dup.md).

```c title:malloc.c
{
	/* Check that the top of the bin is not the record we are going to add (i.e., double free).  */
	if (__builtin_expect (old == p, 0))
		malloc_printerr ("double free or corruption (fasttop)");
	p->fd = old;
	*fb = p;
}
```
### Bypass
Comme décrit dans le code source de malloc, si le chunk qu'on essaye de free est le même que le chunk au top du [fastbin](Pwn/Heap/Bins#Fastbins). Ce qui veut dire que si le chunk est déjà dans le [fastbin](Pwn/Heap/Bins#Fastbins) mais qu'il n'est pas le top du [fastbin](Pwn/Heap/Bins#Fastbins), alors la protection ne s'applique pas.

Par exemple, si on free le chunk `0x603010` dans ces conditions : 
```
# Va crash
Fastbins[0x30]  ←  Chunk(0x603010)

# Ne va pas crash
Fastbins[0x30]  ←  Chunk(0x603040)  ←  Chunk(0x603010)
```

Pour bypass cette protection, il nous suffit donc de nous débrouiller pour que le chunk qu'on veut double free ne soit pas sur le top du chunk du [fastbin](Pwn/Heap/Bins#Fastbins) correspondant.
Et si nous y arrivons, BINGO:
```
Fastbins[0x30] ← Chunk(0x603010)  ←  Chunk(0x603040)  ←  Chunk(0x603010)
```

## Fastbins size check
### Mitigation
Lorsqu'on essaye de *malloc()* un chunk depuis un [fastbin](Pwn/Heap/Bins#Fastbins), il existe une protection qui permet de vérifier que le chunk est légitime à être alloué. Pour ça, *malloc()* va vérifier que les metadata du chunk alloué depuis le [fastbin](Pwn/Heap/Bins#Fastbins) indiquent une taille de chunk identique à celle du [fastbin](Pwn/Heap/Bins#Fastbins). Si ce n'est pas le cas, alors *malloc()* va faire un call à *abort()*.
```c title:malloc.c
if (__glibc_likely (victim != NULL))
{
	size_t victim_idx = fastbin_index (chunksize (victim));
	if (__builtin_expect (victim_idx != idx, 0))
		malloc_printerr ("malloc(): memory corruption (fast)");
	check_remalloced_chunk (av, victim, nb);

...

```
### Bypass
Il n'existe pas réellement de super technique pour bypass cette protection. Néanmoins, le fait qu'elle se base sur l'intégrité des données dans un partie de la mémoire potentiellement corrompue, la rend faillible. Il suffit de modifier les données présentes à l'adresse du chunk pour renseigner de fausses metadata, et donc une fausse size pour tromper le check de *malloc()*.

Une autre option pour bypass cette protection serait de trouver une adresse suffisamment proche de celle qu’on veut overwrite pour pouvoir être considérée comme une fake_size_chunk. Il est donc nécessaire que cette adresse contienne une size cohérente.
En sachant que le Check ne vérifie pas l’alignement’ il est tout à fait possible d’utiliser des morceaux de données comme chunk size. Par exemple, le 0x7f qui commence de nombreuses adresses peut être utiliser comme chunk size.

```ad-info
Info Max production environnement 
```

## Top Chunk Size check
### Mitigation
A partir de la version 2.29 de la **GLIBC**, une protection sur la size du top chunk est implémentée. Pour ce faire, la taille initiale du top chunk est gardée en mémoire. Ainsi si, à un moment, la taille du top chunk dépasse cette valeur initiale, alors on aura un **ABORT**.

```c title:malloc.c
victim = av->top;
       size = chunksize (victim);
 
+      if (__glibc_unlikely (size > av->system_mem))
+        malloc_printerr ("malloc(): corrupted top size");
+
       if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE))
         {
           remainder_size = size - nb;
```
### Bypass
Il n'existe pas réellement de technique de bypass. Si lors d'une attaque, on a besoin d'overwrite l'adresse du top chunk, le mieux à faire est de s'assurer que la size du top chunk interprétée par malloc à partir de son adresse, n'excède pas la size initiale du top chunk. 
## TCache Double Free
https://drive.google.com/file/d/1g2qIENh2JBWmYgmfTJMJUier8w0XAGDt/view
