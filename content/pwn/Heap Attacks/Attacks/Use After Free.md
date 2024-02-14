---
title: 'Use After Free'
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
Comme son nom l'indique, le use after free est une vulnérabilité qui est rencontrée lorsque un chunk est utilisé après avoir été free. Ainsi, le programme va utiliser des données qui ne sont plus censés exister.

## Detail
Lorsque l'on souhaite libérer de la mémoire dynamiquement, on va utiliser la fonction free. Ainsi le chunk que l'on va libérer va être ajouté aux [Fastbins](Pwn/Heap/Bins#Fastbins) et pourra être réutilisé. Pour autant, toutes les données qu'il contient ne seront pas effacées. Il est donc nécessaire de réinitialiser le pointeur vers le chunk, juste après avoir free.
Ce qu'il va se passer si ce n'est pas fait correctement, est qu'une partie des données vont rester accessibles grâce au pointeur, même après avoir free.

## Exploit
```c title:Hackndo
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char ** argv) {
        char *admin = NULL;
        char *prenom = NULL;

        admin = malloc(32);
        admin[0] = 0;

        // la zone mémoire de admin est libérée, mais la variable admin n'est pas réinitialisée !
        free(admin);

        // Et puis une autre allocation de mémoire est faite.
        // Sauf que comme admin a été libéré, cette nouvelle zone mémoire réutilise cet espace !
        prenom = malloc(32);
        strncpy(prenom, "pixis", 5);
        
        // Ici, admin pointe toujours vers la zone mémoire initiale, qui a été réutilisée par "prenom".
        // Du coup, admin[0] vaut "p", admin[1] vaut "i", etc.
        // Ainsi, d'après cette vérification, nous sommes administrateur !
        if (admin == NULL || admin[0] == 0) {
                printf("Cette section est interdite !\n");
                return -1;
        }
        
        printf("Zone d'administration super secrète !\n");

		// Bonne pratique
		free(prenom);
        prenom = NULL;
        return 0;
}
```
