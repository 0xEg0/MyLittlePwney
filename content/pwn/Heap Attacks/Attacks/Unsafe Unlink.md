---
title: 'Unsafe Unlink'
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
L'objectif de cette attaque est d'exploiter la manière dont sont consolidés les chunks dans l'Unsorted Bin. En effet, lorsque les conditions le permettent, l'algorithme malloc va unlink certains chunk de [l'Unsorted Bin](Pwn/Heap/Bins#Unsorted%20Bins), ce qui peut potentiellement nous permettre d'obtenir un arbitrary write.
## Detail
Lors d'une consolidation de chunk, le chunk déjà présent dans [l'Unsorted Bin](Pwn/Heap/Bins#Unsorted%20Bins) va être unlink par l'Algo malloc. Puisque c'est une doubly linked list, et que les valeurs du **fd** et du **bk** sont stockées inline sur la heap, alors un contrôle sur ces valeurs nous permettrait d'obtenir un arbitrary write.
Voilà un schéma de setup de l'attaque:
![[Pasted image 20240110151923.png]]

L'intérêt de cette attaque est assez simple. Exploiter une vulnérabilité classique sur la heap (ex: buffer overflow) pour avoir un arbitrary write et ainsi espérer rediriger le flow d'execution du programme pour obtenir une command execution.
## Further use
Ici, la technique a été décrite dans le cas d'une backward consolidation, mais il est tout a fait possible de le faire également en forward.
## Limitations
Cette technique n'est viable que pour les très vieilles versions de la LIBC puisque le safe unlink a été introduit avec la version **2.3.3** de la GLIBC en 2004. Cette technique était d'ailleurs beaucoup utilisée sur des binaires sans **NX/DEP**.
