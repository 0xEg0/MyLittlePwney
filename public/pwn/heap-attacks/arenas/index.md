# Arenas


### Overview
Les arenas sont des structures de données utilisées par malloc pour administrer les heaps utilisées par les différents process. En théorie, chaque thread peut avoir sa propre arena. Mais le nombre maxium d&#39;arenas disponibles pour un process dépend du nombre de cores disponibles à ce process.

### Details
Les arenas sont donc utilisées par malloc pour administrer les heaps. Leur principale utilitée est de gérer le recyclage des free chunks. Pour faire cela, elles sont constituées de [bins](/MyLittlePwney/pwn/heap-attacks/bins/), des structures de données qui vont référencer efficacement les chunks qui ont été free.

Les arenas sont définies selon la struct *malloc_state*. De nouvelles arenas peuvent être créées et initialisées via les fonctions *_init_new_arena()* et *malloc_init_state()*. 

### Layout
Une arena est designée comme une structure de données. Il est donc necessaire de comprendre comment les données sont agencées pour savoir comment interpréter une arena à partir des données en mémoire.
![Arenas Layout](/MyLittlePwney/images/arenas_layout.png)
#### mutex
Un mutex agit comme une sorte de gardien d&#39;une zone mémoire. Il permet d&#39;éviter qu&#39;une zone mémoire ne soit altérée par une utilisation simultanée venant de différents thread. C&#39;est une protection assez efficace lorsque plusieurs thread essaient d&#39;accèder à une même zone mémoire.

Ainsi, le premier thread à accèder à la zone va d&#39;abord vérifier si la valeur du **mutex** indique que la zone est libre. Si c&#39;est le cas il va changer la valeur pour indiquer que la zone mémoire est lock, puis il va y accèder. Sinon, il va attendre que le thread qui l&#39;occupe ai fini ses modifications et delock le mutex.

#### flags
Donne diverses informations sur l&#39;état de l&#39;arena. Par exemple, c&#39;est dans la section flags qu&#39;il sera dit si l&#39;arena est collée à d&#39;autres donnée en mémoire.

Les flags sont assez spécifique, il est important de se renseigner pour connaitre leur valeur et comment les manipuler.
#### have_fastchunks
C&#39;est un booléen qui indique que les fastbins ne doivent pas être nul. Il est initialisé chaque fois qu&#39;un chunk est link à un fastbin et il remit à NULL lorsqu&#39;on fait un appel à *malloc_consolidate()*.

Pour **GLIBC &lt;= 2.26**, cette valeur fait partie des [flags](#flags) de l&#39;arena.
#### top
Selon le code source de malloc, un top chunk est le chunk le plus haut de la heap. Il limite la heap et la fin de la mémoire disponible. Dès qu&#39;une arena est initialisée, un top chunk est créé. Il n&#39;en existe, d&#39;ailleurs, qu&#39;un par arena. C&#39;est de ce top chunk que va venir l&#39;espace mémoire alloué lorsqu&#39;il ne peut pas venir des bins.



---

> Author:   
> URL: https://0xeg0.github.io/MyLittlePwney/pwn/heap-attacks/arenas/  

