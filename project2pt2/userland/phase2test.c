#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>


#define __NR_cs3013_syscall2 378


typedef struct processinfo {
  long state;
  pid_t pid;
  pid_t parent_pid;
  pid_t youngest_child;
  pid_t younger_sibling;
  pid_t older_sibling;
  uid_t uid;
  long long start_time;
  long long user_time;
  long long sys_time;
  long long cu_time;
  long long cs_time;
} pinfo;// struct processinfo

long testCall2 ( pinfo * info) {
        return (long) syscall(__NR_cs3013_syscall2, info);
}

int main() {
	pinfo *info = malloc(sizeof(pinfo));
	printf("Hi, I'm a user program! My PID is %d\n", getpid());

	int pid;

	// Command specified in args- fork and run
    if ((pid = fork()) < 0) { // negative pid = error forking
        fprintf(stderr, "Fork error\n");
        exit(1);
    } else if (pid == 0) {
        /* child process */
    	printf("I am a child process! My PID is %d\n", getpid());
    	sleep(5);
    	printf("Bye bye ~%d\n", getpid());
    	exit(0);
    } else {
    	printf("I am the parent process! Firstborn: %d\n", pid);
  //        parent process 
		// printf("Running test call 2, struct addr %p\n", info);
		// testCall2(info);

		if ((pid = fork()) < 0) { // negative pid = error forking
	        fprintf(stderr, "Fork error\n");
	        exit(1);
	    } else if (pid == 0) {
	        /* child process */
	    	printf("I am the younger child! My PID is %d\n", getpid());
    		printf("Running test call 2 as child, struct addr %p\n", info);
	    	sleep(2);
			testCall2(info);
	    	sleep(5);
	    	printf("Bye bye ~%d\n", getpid());
	    	exit(0);
	    } else {
	    	printf("I am the parent process! Anotha one: %d\n", pid);
	        /* parent process */
			printf("Running test call 2, struct addr %p\n", info);
			testCall2(info);
		}
	}
}