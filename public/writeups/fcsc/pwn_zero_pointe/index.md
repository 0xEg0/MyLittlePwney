# MISC - Zéro Pointé - FCSC 2023

```c title:main.c

static void flag(int sig) {
    (void) sig;
    char flag[128];

    int fd = open(&#34;flag.txt&#34;, O_RDONLY);
    if (fd == -1) {
        perror(&#34;open&#34;);
        exit(EXIT_FAILURE);
    }

    int n = read(fd, flag, sizeof(flag));
    if (n == -1) {
        perror(&#34;read&#34;);
        exit(EXIT_FAILURE);
    }

    flag[n] = 0;
    flag[strstr(flag, &#34;\n&#34;) - flag] = 0;

    if (close(fd) == -1) {
        perror(&#34;close&#34;);
        exit(EXIT_FAILURE);
    }

    printf(&#34;%s\n&#34;, flag);
    exit(EXIT_SUCCESS);
}

long read_long()
{
    long val;
    scanf(&#34;%ld&#34;, &amp;val);
    return val;
}

int main()
{
    long a;
    long b;
    long c;

    if (signal(SIGFPE, flag) == SIG_ERR) {
        perror(&#34;signal&#34;);
        exit(EXIT_FAILURE);
    }

    a = read_long();
    b = read_long();
    c = b ? a / b : 0;

    printf(&#34;%ld\n&#34;, c);
    exit(EXIT_SUCCESS);
}
```

In the code, the `signal()` function is used to catch the `SIGFPE` signal, which is an arithmetic exception that occurs when there is a divide-by-zero error or other arithmetic error.
The `flag()` function is set as the signal handler for `SIGFPE`. This means that if a divide-by-zero error occurs, the `flag()` function will be called automatically.

Yes, there is a vulnerability in the provided code that can be exploited to call the `flag()` function. The vulnerability lies in the handling of arithmetic exceptions, specifically the division by zero.

In the code, the `signal()` function is used to catch the `SIGFPE` signal, which is an arithmetic exception that occurs when there is a divide-by-zero error or other arithmetic error:
```c title:vuln.c
if (signal(SIGFPE, flag) == SIG_ERR) {     
	perror(&#34;signal&#34;);     
	exit(EXIT_FAILURE); 
}
```

The `flag()` function is set as the signal handler for `SIGFPE`. This means that if a divide-by-zero error occurs, the `flag()` function will be called automatically.

Now let&#39;s look at the part of the code that performs the division:
```c
a = read_long(); 
b = read_long(); 
c = b ? a / b : 0;
```

The code checks if `b` is non-zero before performing the division, which prevents a divide-by-zero error in normal circumstances. However, there is still a way to trigger the `SIGFPE` signal, forcing the program to call the `flag()` function.

The vulnerability can be exploited by providing input values for `a` and `b` that cause an integer overflow. When an integer overflow occurs, the result of the division will be undefined, which can lead to the `SIGFPE` signal being raised. To trigger the integer overflow, you can use the minimum and maximum values of a signed long integer:

-   Set `a` to the minimum value of a signed long integer, which is `-9223372036854775808` (or `LONG_MIN` in C).
-   Set `b` to `-1`.

When dividing `a` by `b`, an integer overflow occurs, as the result cannot be represented within the range of a signed long integer. This will raise a `SIGFPE` signal, causing the program to call the `flag()` function.


---

> Author:   
> URL: https://0xeg0.github.io/MyLittlePwney/writeups/fcsc/pwn_zero_pointe/  

