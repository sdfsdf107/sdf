#include <stdio.h>

int main(int argc , char **argv)
{
        FILE *fp=fopen(argv[1],"r");
        if (!fp)
                return -1;
int s=0;
char c,d;
        while(EOF!=(c = fgetc(fp))) {
if (c=='/') {
        if (s==0)
{
        c = fgetc(fp);
        if ('/' == c)
        s=1;
else  if ('*' ==c)
        s=2;
else
        fseek(fp,-1,SEEK_CUR);

}
}
else if(c=='\n') {
if (s==1)
        s=0;
}
else if(c=='*') {
if (s==2) {
c = fgetc(fp);
if (c=='/') {
c = fgetc(fp);
s=0;
}
        }
}
if (!s)
        printf("%c",c);

        }
}
