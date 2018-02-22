include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv){
    char buf[10];
    printf("system: %p, buf: %p\n",system,buf);
    fgets(buf,100, stdin);
    return 0;
}
