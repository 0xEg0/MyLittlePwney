## The Bug
Le Buffer Overflow est un bug qui se produit lorsqu'un programme ecrit dans un buffer plus de bytes que le buffer ne peut en accueillir. 
Ce que l'on designe par le terme de buffer est une zone memoire dont le programme controle le contenu. Cela peut representer n'importe quel element present en memoire (variables, constantes, zone memoire dynamique...).

Le probleme avec ce bug etant que le programme tout entier s'appuie sur la memoire pour fonctionner. Ainsi en debordant du buffer le programme va potentiellement reecrire d'autres elements presents en memoire et donc des element necessaire a son propre fonctionnement, ce qui va souvent provoquer un crash.

## Demonstration du Bug
Pour que ce soit plus parlant voici un exemple tres basique que l'on va etudier en assembleur pour mieux comprendre le reel fonctionnement du programme et comment il interragit avec la memoire.
```c title:test.c
#include <stdio.h>

int main(){
	int check = 0;
	char buffer[16];

	gets(buffer);
	if (check == 0x1337)
		printf("Well Done!!");
	return 0;
}
```

### Analysis
Le programme est tres simple. Il defini une variable **check** qu'il initialise a 0. Il defini ensuite un tableau de caracteres, que l'on peu definir comme un buffer puisque un tableau de 16 carateres reprensente concretement une zone memoire de 16 bytes reservee a cette variable. Ensuite, il lit depuis l'entree standard et save l'input lu dans le buffer. Enfin, il verifie que la variable **check** est bien egale a **0x1337**.

Ca peut paraitre un peu bizarre. Pourquoi la variable check serait egale a 0x1337 si elle a ete initialisee a 0 et inchangee. Et bien peut etre que le programme est vulnerable et que l'on peut reecrire la valeur de check 😈.

Si on s'en referre a la man page de gets(), on se rend compte que la fonction gets() lit la premiere ligne de l'entree standard (stdin) et la sauvegarde dans le buffer passe en parametre.
```md title:man_gets
DESCRIPTION

       gets()  reads  a line from stdin into the buffer pointed to by s until either a terminating newline or EOF, which it replaces with a
       null byte ('\0').  No check for buffer overrun is performed (see BUGS below).
```

Wait, wait, wait... Si gets() lit la premiere ligne de stdin, et que notre buffer ne peut accueilir que 16 bytes, que se passe-t-il si la ligne lu fait plus de 16 bytes?

### Assembly
Pour le comprendre, regardons ce que fait le programme en bas niveau :
```nasm title:test.s
push   rbp
mov    rbp,rsp
sub    rsp,0x20
mov    DWORD PTR [rbp-0x4],0x0
lea    rax,[rbp-0x20]
mov    rdi,rax
mov    eax,0x0
call   0x1040 <gets@plt>
cmp    DWORD PTR [rbp-0x4],0x1337
jne    0x1186 <main+61>
lea    rax,[rip+0xe8b]        # 0x2004
mov    rdi,rax
mov    eax,0x0
call   0x1030 <printf@plt>
mov    eax,0x0
leave
ret
```

Concretement, il y a 2 parties interressantes a regarder :
- D'abord, le programme va sauvegarder la valeur de check sur la stack.
```nasm
mov    DWORD PTR [rbp-0x4],0x0
```
- Ensuite il reserve une zone memoire de minimum 16 bytes (sur la stack) et passe son adresse en argunent a gets().
```nasm
lea    rax,[rbp-0x20]
mov    rdi,rax
mov    eax,0x0
call   0x1040 <gets@plt>
```

Ainsi, si on deroule l'execution du programme notre stack va ressembler a quelque chose comme ca:
[SCHEMA]

### Exploit
Si on s'interesse a ce que fait reelement la fonction gets(), elle prend tout simplement un adresse memoire (ici l'adresse de notre buffer), et y ecrit les bytes lus depuis l'entree standard. Le probleme est qu'a l'adresse de buffer+0x1c, il y a la valeur de check. Donc si gets lit plus de 28 bytes, il va ecrire par dessus la valeur de check.
[SCHEMA]

Si on lance un debugger, qu'on test notre exploit et qu'on break sur l'instruction qui verifie la valeur de check, on peut voir qu'on a bien reecrit la valeur de check sauvegardee en memoire.
```
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000001149 <+0>:	push   rbp
   0x000000000000114a <+1>:	mov    rbp,rsp
   0x000000000000114d <+4>:	sub    rsp,0x20
   0x0000000000001151 <+8>:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000001158 <+15>:	lea    rax,[rbp-0x20]
   0x000000000000115c <+19>:	mov    rdi,rax
   0x000000000000115f <+22>:	mov    eax,0x0
   0x0000000000001164 <+27>:	call   0x1040 <gets@plt>
   0x0000000000001169 <+32>:	cmp    DWORD PTR [rbp-0x4],0x1337
   0x0000000000001170 <+39>:	jne    0x1186 <main+61>
   0x0000000000001172 <+41>:	lea    rax,[rip+0xe8b]        # 0x2004
   0x0000000000001179 <+48>:	mov    rdi,rax
   0x000000000000117c <+51>:	mov    eax,0x0
   0x0000000000001181 <+56>:	call   0x1030 <printf@plt>
   0x0000000000001186 <+61>:	mov    eax,0x0
   0x000000000000118b <+66>:	leave
   0x000000000000118c <+67>:	ret

(gdb) b *main+32
Breakpoint 1 at 0x1169

(gdb) r
Starting program: /root/a.out
AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
```

On inspecte le contexte dans lequel on a break dans gdb.
```
(gdb) x/i $rip
=> 0x555555555169 <main+32>:	cmp    DWORD PTR [rbp-0x4],0x1337

(gdb) x/wx $rbp-0x4
0x7fffffffe2dc:	0x42424242
```

On a donc bien reussi a overwrite la valeur de check 🙂.

### Scripting the Exploit
Pour finaliser la technique d'exploitation, on va faire un petit script python qui va gerer toutes les interactions a notre place.

