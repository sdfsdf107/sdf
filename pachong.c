#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/stat.h>
#include <regex.h>
#include <pthread.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/errno.h>
#include<rpc/des_crypt.h>	/*for ecd_crypt */

#ifndef MAXMATCH
#define  MAXMATCH   10 
#endif
#define MAX_THR 10
#define MAX_URL_LEN 1024	/*长度大于MAX_LINK_LEN的超链接忽略 */
#define  MAX_LINK_LEN MAX_URL_LEN
#define MAX_URLPATH_NUM	1000000	/*url path数目的上限(必须是1000的整倍数) */
#define MAX_URLDOMAIN_NUM	(MAX_URLPATH_NUM)/1000	/*url domain数目的上限(必须是1000的整倍数) */
#define MAX_HANSH_NUM 1023
#define DEBUG_PRINTF 
#if defined DEBUG_PRINTF 
//#define debug_printf(...) fprintf (stderr, __VA_ARGS__) 
#define debug_printf(format, ...) fprintf (stderr, format, ## __VA_ARGS__)
#else 
#define debug_printf(...) do{}while(0); 
#endif 

pthread_mutex_t queue_cs;    
pthread_mutex_t queue_dns;                        //
pthread_cond_t  queue_cv;                          //
pthread_mutex_t dtlock = PTHREAD_MUTEX_INITIALIZER;

int d_table[MAX_URLDOMAIN_NUM] = { 0 };

typedef struct urllist {
	struct urllist *pre;
	struct urllist *next;
	char str[MAX_URL_LEN];
} Url;
Url todolist_head;

typedef struct ip {
	struct ip* next;
	struct sockaddr_in ipaddres;
} Ip;

typedef struct dns {
	struct dns* next;
	char domain[MAX_URL_LEN];
	Ip *iphead;
} Dns;

Dns *HANSH[MAX_HANSH_NUM];

void addtodolistnode(Url *node) {
	if (todolist_head.next != &todolist_head) {
		node->next = todolist_head.next;
		todolist_head.next->pre=node;
		node->pre = &todolist_head;
		todolist_head.next=node;
	} else {
		todolist_head.next = node;
		todolist_head.pre = node;
		node->next = &todolist_head;
		node->pre = &todolist_head;
	}
}

void deletetodolistnode(Url *node) {
	node->next->pre = node->pre;
	node->pre->next = node->next;
}

inline Url *gettodolistnode()
{
	if (todolist_head.next != &todolist_head)
		return todolist_head.pre;
	else
		return NULL;
}

void des_encrypt(const char *key, char *data, int len)
{
    char pkey[8];
    strncpy(pkey, key, 8);
    des_setparity(pkey);
    do {
        data[len++] = '\x8';
    } while (len % 8 != 0);
    ecb_crypt(pkey, data, len, DES_ENCRYPT);
}
Url * dequeue()
{
    Url * url;

    pthread_mutex_lock(&queue_cs);

    while (!(url = gettodolistnode()))
        pthread_cond_wait(&queue_cv,&queue_cs);
	
	deletetodolistnode(url);
	
    pthread_mutex_unlock(&queue_cs);

    return url;
}

/*把超链接末尾的/去掉,长度大于MAX_LINK_LEN的超链接不爬取，把link设为NULL*/
void pretreatLink(char *link)
{
	debug_printf("%s %d defore delete last '/' from link [%s]\n",__func__,__LINE__,link);
	int len = strlen(link);
	if (link[len - 1] == '/')	/*把超链接末尾的/去掉 */
		link[len - 1] = '\0';
	
	debug_printf("%s %d after  delete last '/' from link [%s]\n",__func__,__LINE__,link);
	return;
}
int myEncrypt(char *str, char *key)
{
	assert(str != NULL);
	int var=0;
	int i;
	des_encrypt(key,str,strlen(str));
	
	for ( i = 0; i < MAX_LINK_LEN; i++)
		var = (var * 7 + ((unsigned int)str[i])) % (int)INT_MAX;

	return var;
}
int bloomDomain(char *link, int add)
{
	debug_printf("%s %d check link [%s] whether it is dealed\n",__func__,__LINE__,link);
	int flag = 0;
	char* salt[] = { "Dm", "VB", "ui", "LK", "uj", "RD", "we", "fc" };
	int i;
	char domaintmp[MAX_LINK_LEN];
	pthread_mutex_lock(&dtlock);
	for (i = 0; i < 8; i++) {
		memcpy(domaintmp,link,MAX_LINK_LEN);
		int f = myEncrypt(domaintmp, salt[i]);
		int index = f % MAX_URLDOMAIN_NUM;
		int pos = f % 32;
		if (d_table[index] & (1 << pos))
			flag++;
		else if(add)
			d_table[index] |= (1 << pos);
	}
	pthread_mutex_unlock(&dtlock);
	i = 1;
	if (flag == 8)
		i = 0;	//已存在则返回true
	debug_printf("%s %d check link [%s] is [%s]\n",__func__,__LINE__,link,i ? "dealed" : "undealed");
	return i;
}

/*从link中获取host和resource*/
void getHRfromlink(char *link, char *domain, char *path)
{
	debug_printf("%s %d get domain and path from [%s]\n",__func__,__LINE__,link);
	char *p = index(link, '/');
	
	if (p == NULL) {
		strcpy(domain, link);
		path[0] = '/';
		path[1] = '\0';
	} else {
		int dlen = p - link;
		int plen = strlen(link) - dlen;
		strncpy(domain, link, dlen);
		domain[dlen] = '\0';
		strcpy(path, p);
		path[plen] = '\0';
	}
	debug_printf("%s %d get domain[%s] and path[%s] from [%s]\n",__func__,__LINE__,domain,path,link);
	return ;
}

int hansh(char *domain)
{
	int i;
	unsigned long sum=0;
	int len = strlen(domain)%MAX_HANSH_NUM;
	for(i=0;i<len;i++)
		sum+=(unsigned short)domain[i];
	return sum%MAX_HANSH_NUM;
}

Ip *getdns(char *domain)
{
	char str[32];
	Dns *temp;
	int hashsum  ;
	int flag = 0;
	int i=0;
	int err;
	
	hashsum = hansh(domain);
    pthread_mutex_lock(&queue_dns);
	if (temp = HANSH[hashsum]) {
		while(temp) {
			if (!strcmp(temp->domain,domain) ) {
    			pthread_mutex_unlock(&queue_dns);
				return temp->iphead;
			}
			else
				temp = temp->next;
		}	
	}
	pthread_mutex_unlock(&queue_dns);
	
	
	temp = calloc(1, sizeof(*temp));
	if(!temp)
		return NULL;

#if 1
	struct hostent *myhost;
	char ** pp;
	struct in_addr addr;
	myhost = gethostbyname(domain);
	pp = myhost->h_addr_list;
	while(*pp!=NULL)
	{
		Ip *Ips = calloc(1, sizeof(Ip));
			if(!Ips)
				continue;
		
		addr.s_addr = *((unsigned int *)*pp);
		Ips->ipaddres.sin_addr = addr;
		Ips->next = temp->iphead ;

		temp->iphead = Ips;

		debug_printf("address is %s\n",inet_ntoa(addr));
		
		pp++;
	}
	
#else 
	struct addrinfo hints, *res = NULL;  
	memset(&hints, 0, sizeof(hints));
	struct addrinfo *aip;
	const char             *addr;
	char                 abuf[INET_ADDRSTRLEN];
	
	hints.ai_flags = AI_CANONNAME;
	if ((err = getaddrinfo(domain, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "Error getaddrinfo: %s\n", gai_strerror(err));
		free(temp);
		return NULL;
	}
	
	for (aip = res; aip != NULL; aip = aip->ai_next) {
        debug_printf("\n\thost %s", aip->ai_canonname?aip->ai_canonname:"-");
        if (aip->ai_family == AF_INET) {
		//	sinp = (struct sockaddr_in *)aip->ai_addr;
			Ip *Ips = calloc(1, sizeof(Ip));
			if(!Ips)
				continue;
			memcpy(&Ips->ipaddres, aip->ai_addr, sizeof(struct sockaddr_in));
			Ips->next = temp->iphead ;
			
			temp->iphead = Ips;
		}
    }
	freeaddrinfo(res);
#endif
	
	strcpy(temp->domain,domain);
	if(!temp->iphead) {
		free(temp);
		return NULL;
	}

	pthread_mutex_lock(&queue_dns);
	
	temp->next = HANSH[hashsum];
	HANSH[hashsum] = temp;
	
	pthread_mutex_unlock(&queue_dns);
	
	return temp->iphead;
}

void enqueue(Url *  url)
{
    pthread_mutex_lock(&queue_cs);

	addtodolistnode(url);

    pthread_cond_signal(&queue_cv);

    pthread_mutex_unlock(&queue_cs);
	return;
}

void link2fn(char * domain,char * path,char *filename)
{
	int i = 0;
	int l1 = strlen(domain);
	int l2 = strlen(path);
	
	for (; i < l1; ++i)
		filename[i] = domain[i];
	for (i = 0; i < l2; ++i)
		filename[i + l1] = (path[i] == '/' ? '_' : path[i]);
	filename[l1 + l2] = '\0';
	return;
}

/*字符串向左平移，直到最后一个空格移到首位为止，返回字符串中还剩多少字符*/
int leftshift(char *buf)
{
	char *p = rindex(buf, ' ');
	if (p == NULL) {	/*空格没有出现，则清空buf，返回0 */
		memset(buf, 0x00, strlen(buf));
		return 0;
	} else {
		int leftlen = p - buf;
		int rightlen = strlen(buf) - leftlen;
		char *tmp = (char *)malloc(rightlen);
		strncpy(tmp, p, rightlen);
		memset(buf, 0x00, strlen(buf));
		strncpy(buf, tmp, rightlen);
		free(tmp);
		return rightlen;
	}
}

/*去掉开头的http[s]，如果是以“/”开头的，就把它接在domain后面*/
int patchlink(char *link, char *domain, Url *temp)
{
	int len1 = strlen(link);
	int len2 = strlen(domain);
	char *rect = temp->str;
	int i;
	if (strncmp(link, "http", 4) == 0) {
		int llen;
		if (strncmp(link, "https", 5) == 0)
			llen = 8;
		else
			llen = 7;
		
		for (i = 0; i < len1 - llen; ++i)
			rect[i] = link[i + llen];
		rect[len1 - llen] = '\0';
	} else if (strncmp(link, "/", 1) == 0) {
	
		for (i = 0; i < len2; ++i)
			rect[i] = domain[i];
		for (i = 0; i < len1; ++i)
			rect[i + len2] = link[i];
		rect[len1 + len2] = '\0';
	//	debug_printf("all link：|%s|\n",rect);
	} else {		/*既不是以http[s]开头，也不是以“/”开头，则返回NULL */
		return 1;
	}
	return 0;
}

/*从字符串中抽取所有的超链接，移除左侧包含所有超链接的最短子串，返回剩余子串的长度*/
int extractLink(char *buf, char *domain)
{
	const char *regex = "href=\"[^ >]*\"";
	regex_t preg;
	regmatch_t pm[MAXMATCH];
	int nmatch = MAXMATCH;
	char tmp[MAX_LINK_LEN];
	
	if (regcomp(&preg, regex, REG_EXTENDED|REG_ICASE) != 0) {	/*编译正则表达式失败 */
		debug_printf("%s %d init regex failed \n",__func__,__LINE__);
		return leftshift(buf);
	}
	int z, i;
	z = regexec(&preg, buf, nmatch, pm, 0);
	regfree(&preg);
	if (z == REG_NOMATCH) {	/*无匹配项 */
		return leftshift(buf);
	} else {		/*有匹配的超链接 */
		for (i = 0; i < nmatch && pm[i].rm_so != -1; ++i) {	/*把超链接都提取出来 */
			int bpos = pm[i].rm_so + 6;
			int epos = pm[i].rm_eo - 2;
			int len = epos - bpos + 1;
			
			strncpy(tmp, buf + bpos, len);
			tmp[len] = '\0';
			debug_printf("%s %d original link：[%p]\n",__func__,__LINE__,tmp);
			Url *temp = calloc(1, sizeof(Url));
			if(!temp)
				continue;
			if(patchlink(tmp, domain,temp)) {
				free(temp);
				continue;
			}
			debug_printf("%s %d whole link：[%p]\n",__func__,__LINE__,temp->str);
			enqueue(temp);
		}
		
		return leftshift(buf + pm[nmatch - 1].rm_eo);
	}
}

/*发送http request*/
int sendRequest(char * domain,char * path, int fd)
{
	char request[1024] = { 0 };
	sprintf(request, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", path,
		domain);
	int need = strlen(request);	/*还需要向sockfd中写入这么多的数据 */
	int tmp = 0;		/*记录已发送的数据量 */
	int n;			//记录读写的实际字节数
	int i = 0;
	while (need > 0) {
		n = write(fd, request + tmp, need);
		if (n < 0) {
			if (errno == EAGAIN) {	/*写缓冲队列已满，延时后重试 */
				usleep(1000);
				continue;
			}
			
			i = -1;
			break;
		}
		need -= n;
		tmp += n;
	}
	
	debug_printf("%s %d send http request[%s] [%s]==>[%s%s]\n",
		__func__,__LINE__,request,i?"failed":"success",domain,path);
	return i;
}

int dealurlres(Ip *res,char *domain, char *path)
{	
	int s = -1;
	char filename[2*MAX_LINK_LEN+1];
	int ret;
	struct ip* next = res;

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}
	
	/*创建服务器套接口地址 */
	struct sockaddr_in server_address;
	bzero(&server_address, sizeof(struct sockaddr_in));
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(80);

	while(next) {
		server_address.sin_addr = next->ipaddres.sin_addr;
		if ((ret = connect
			(s, (struct sockaddr *)&server_address,
		     sizeof(struct sockaddr_in))) < 0) {
			next = next->next;
			perror("connect");
		}
		else
			break;
	}
	
	if(ret <0) {
		close(s);
		return -1;
	}

	ret = sendRequest(domain,path,s);
	if(ret <0) {
		close(s);
		return -1;
	}
	
	link2fn(domain,path,filename);
	int htmlfd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);	/*以只写方式打开html文件 */
	if (htmlfd < 0) {
		close(s);
		return -1;
	}
	int i, n, need, ll = 0;
	char buf[1024] = { 0 };
	char buf1[1024] = { 0 };
	while (1) {
		need = sizeof(buf) - 1 - ll;
		n = read(s, buf+ll, need);
		if (n < 0) {
			if (errno == EAGAIN) {
				usleep(1000);
				continue;
			} else {
				fprintf(stderr, "%s %d read http response error\n",__func__,__LINE__);
				close(htmlfd);
				close(s);
				return -1;
			}
		} else if (n == 0) {	/*读取http响应这完毕 */
			debug_printf("%s %d get http response success==>[%s%s]\n",__func__,__LINE__,domain,path);
			break;
		} else {	/*还需要继续读 */
			debug_printf("%s %d from socket read:[%s] and will go on\n",__func__,__LINE__,buf);
			memcpy(buf1, buf, sizeof(buf));
			ll = extractLink(buf, domain);
			write(htmlfd, buf1, n-ll);
		}
	}
	close(htmlfd);
	return 0;
}

void * process_queue()
{
	Url *url;
    pthread_t mth = pthread_self();  
	char domain[MAX_URL_LEN];
	char path[MAX_URL_LEN];
	Ip  *res;
	
    for(;;) {
        debug_printf("this is %u thread\n", (unsigned int)mth);
        url = dequeue(); 
		debug_printf("%s %d [%s] is fetched from queue\n",__func__,__LINE__,url?url->str:"NULL");
		if(!url)
			continue;

		pretreatLink(url->str);

		if (bloomDomain(url->str, 0)) {
			getHRfromlink(url->str, domain, path);
			if(res = getdns(domain) ) { /* 查询到dns后 */
				if(dealurlres(res, domain, path))
					enqueue(url);
				else /*处理成功*/
					free(url);
			} else {/* 没有查询到dns后,url 放回去 */
				enqueue(url);
			}
		} else {/* link出现过，则忽略此link */	
			continue;
		}
    }

    return NULL;
}
 
/*创建分离线程*/
int CreateThread(void *(*start_routine) (void *), void *arg, pthread_t * thread,
		 pthread_attr_t * pAttr)
{
	pthread_attr_t thr_attr;
	if (pAttr == NULL) {
		pAttr = &thr_attr;
		pthread_attr_init(pAttr);	/*初始化线程属性 */
		pthread_attr_setstacksize(pAttr, 1024 * 1024);	/*1 M的堆栈 */
		pthread_attr_setdetachstate(pAttr, PTHREAD_CREATE_DETACHED);	/*线程分离，主线程不需要等子线程结束 */
	}
	pthread_t tid;
	if (thread == NULL) {
		thread = &tid;
	}
	int r = pthread_create(thread, pAttr, start_routine, arg);
	pthread_attr_destroy(pAttr);	/*销毁线程属性 */
	return r;
}

int main(int argc, char **argv)
{
	int i, n;
	pthread_t tid[MAX_THR];
    pthread_mutex_init(&queue_dns,NULL);
    pthread_mutex_init(&queue_cs,NULL);
	pthread_cond_init(&queue_cv,NULL);

	if (argc < 2) {
		printf("You should provide some entry urls in the command line\n"
		     "For example:%s www.sogou.com/ www.cnblogs.com/cate/c\n",
		     argv[0]);
		return 0;
	}
	todolist_head.pre = todolist_head.next = &todolist_head;
	Url *temp = calloc(1, sizeof(Url));
	if(!temp)
		exit( 0);
	strcpy(temp->str, argv[1]);
	addtodolistnode(temp);

	for(i = 0; i <MAX_THR; i++)
    {
        fprintf(stderr,"Starting thread %d \n",i);
		//CreateThread(process_queue, NULL,NULL, &tid[i]);
        pthread_create(&tid[i],NULL,(void*(*)(void*))process_queue,NULL);
    }
	pthread_exit(NULL);
//	while(1)
//		sleep(10000000);
	return 0;
}



















