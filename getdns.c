#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>

int main(int argc, char **argv)
{
	struct hostent *hptr;
	char   **ptr, **pptr;
	char addresslsit[1024];
	char str[32];
	
	if((hptr = gethostbyname(domain)) == NULL)
    {
 		return 0; 
    }

	switch(hptr->h_addrtype)
    {
        case AF_INET:
        case AF_INET6:
			int i=0;
			for(ptr = hptr->h_aliases; *ptr != NULL; ptr++)
            	for(pptr=hptr->h_addr_list; *pptr!=NULL; pptr++) {
				i+=snprintf(addresslsit+i,sizeof(addresslsit)-i,"%s %s\n",*ptr,inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
            }
        break;
        default:
          //  printf("unknown address type\n");
        break;
    }
	printf("%s\n",addresslsit);
 //       printf("%s %s\n", *pptr, addresslsit);

}
#if 0
int main(int argc, char **argv)
{
    char   *ptr, **pptr;
    struct hostent *hptr;
    char   str[32];
	char addresslsit[1024];
	int i, n;
	if (argc < 2) {
		printf("You should provide some urls [./%s  url]\n",argv[0]);
		return 0;
	}
	
    ptr = argv[1];

    if((hptr = gethostbyname(ptr)) == NULL)
    {
        printf(" gethostbyname error for host:%s\n", ptr);
        return 0; 
    }

 /*   printf("official hostname:%s\n",hptr->h_name);
    for(pptr = hptr->h_aliases; *pptr != NULL; pptr++)
        printf(" alias:%s\n",*pptr);
*/
    switch(hptr->h_addrtype)
    {
        case AF_INET:
        case AF_INET6:
            pptr=hptr->h_addr_list;
			i=0;
            for(; *pptr!=NULL; pptr++) {
				i+=snprintf(addresslsit+i,sizeof(addresslsit)-i,"%s ",inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
            //    printf(" address:%s\n", inet_ntop(hptr->h_addrtype, *pptr, str, sizeof(str)));
            }
        //    printf(" first address: %s\n", inet_ntop(hptr->h_addrtype, hptr->h_addr, str, sizeof(str)));
        break;
        default:
          //  printf("unknown address type\n");
        break;
    }

    for(pptr = hptr->h_aliases; *pptr != NULL; pptr++)
        printf("%s %s\n",*pptr,addresslsit);
	
    return 0;
}

#endif

int  mytrim(char s[])
{
   int  i=strlen(s)-1;
   for(;i>=0;i--)
          if(s[i]!='\t'&&s[i]!=' '&&s[i]!='\n')
                 break;
   s[i+1]='\0';
   return  i;
}






























