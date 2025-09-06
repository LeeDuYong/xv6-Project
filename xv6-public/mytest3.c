#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"
#include "memlayout.h"
#include "mmu.h"
#include "param.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "proc.h"
#include "syscall.h"

int main(void)
{	
	char* testf;
	char* testa;
	char* testnpf;
	uint errcase;
	int fd;
	//int i;
	fd = open("README", O_RDONLY);
	printf(1,"free: %d\n", freemem());

	errcase = mmap(1,4096,PROT_READ, MAP_POPULATE, fd, 0);
	printf(1,"err addr not page : %d\n", errcase);
	errcase = mmap(0, 4000, PROT_READ, MAP_POPULATE, fd, 0);
	printf(1, "err length not page aligned: %d\n", errcase);
	errcase = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_POPULATE, fd, 0);
	printf(1, "err prot invalid : %d\n", errcase);
	errcase = mmap(0, 4096, PROT_READ, MAP_POPULATE, -1, 0);
	printf(1, "err not ano fd -1 : %d\n", errcase);
	errcase = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS, fd,0);
	printf(1, "err ano fd not -1 : %d\n", errcase);
	errcase = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS, -1, 4096);
	printf(1, "err ano offset not 0 %d\n", errcase);
	printf(1,"free: %d\n", freemem());

	testa = (char*)mmap(0, 4096, PROT_READ, MAP_POPULATE|MAP_ANONYMOUS, -1,0);
	printf(1, "free: %d\n", freemem());
	testf = (char*)mmap(4096, 4096, PROT_READ, MAP_POPULATE, fd, 1);
	printf(1, "free: %d\n", freemem());
	testnpf = (char*)mmap(8192, 4096, PROT_READ, 0, fd, 1);
	printf(1, "%d %d %d\n", testa[0], testa[1], testa[2]);
	printf(1, "%c %c %c\n", testf[0], testf[1], testf[2]);
	printf(1, "%c %c %c\n", testnpf[0], testnpf[1], testnpf[2]);
	if(fork() == 0){
		printf(1, "child free: %d, child test:%x %x %x\n", freemem(), (uint)testa, (uint)testf, (uint)testnpf);
		printf(1, "child %d %d %d\n", testa[0], testa[1], testa[2]);
		printf(1, "child %c %c %c\n", testf[0], testf[1], testf[2]);
		printf(1, "child %c %c %c\n", testnpf[0], testnpf[1], testnpf[2]);
		exit();
	}
	wait();
	close(fd);
	//for(i = 0; i < 1000; ++i){
		//printf(1, "%c", testf[i]);
	//}
	printf(1, "free: %d\n", freemem());
	printf(1, "err munmap addr not page aligned: %d\n", munmap(5));
	printf(1, "err munmap addr invalid: %d\n", munmap(12288));
	printf(1, "munmap testa%d\n",munmap((uint)testa));
	printf(1, "free: %d\n", freemem());
	printf(1, "munmap testf%d\n",munmap((uint)testf));
	printf(1, "free: %d\n", freemem());
	printf(1, "munmap testnpf%d\n", munmap((uint)testnpf)); 
	printf(1, "free: %d\n", freemem());
	exit();
}
