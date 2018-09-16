#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

// Define system call id as obtained from syscall table
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
  long long cutime;
  long long cstime;
} pinfo;// struct processinfo

void printinfo(pinfo *info);

long testCall2 ( pinfo * info) {
        return (long) syscall(__NR_cs3013_syscall2, info);
}

int main() {
	// Allocate struct to store process info from syscall
	pinfo *info = malloc(sizeof(pinfo));
	// Store pid from fork call
	int pid;
	printf("Running syscall test case for nullptr:\n");
	if(testCall2(NULL)) {
		printf("Success! testCall2 returned error for null param\n\n");
	} else {
		printf("FAIL! testCall2 did not return error for null param\n\n");
	}

	printf("Running syscall test cases for valid process structure:\n");
	// Fork parent to create child 1
    if ((pid = fork()) < 0) { // negative pid = error forking
        fprintf(stderr, "Fork error\n");
        exit(1);
    } else if (pid == 0) {
        /* child 1 process */
        sleep(1); // sleep for 1s to give parent time to print stats
    	printf("I am a child process! My PID is %d\n", getpid());
    	printf("My parent process is %d\n", getppid());
		if(testCall2(info)) {
			printf("ERROR: testCall2 encountered error while sending process data\n");
		}
		printinfo(info);
		sleep(2); // sleep for 2s to give child 2 time to find its sibling
    	exit(0);
    } else {
    	/* Back to parent process after creating child 1 */
    	printf("I am the parent process! My PID is %d\n", getpid());

    	// Fork parent to create child 2
		if ((pid = fork()) < 0) { // negative pid = error forking
	        fprintf(stderr, "Fork error\n");
	        exit(1);
	    } else if (pid == 0) {
	        /* child 2 process */
	        sleep(2); // sleep for 2s to give parent and child 1 time to print stats
	    	printf("I am a second child process! My PID is %d\n", getpid());
			if(testCall2(info)) {
				printf("ERROR: testCall2 encountered error while sending process data\n");
			}
			printinfo(info);
	    	exit(0);
	    } else {
	        /* parent process */
			printf("Process Info Obtained from Kernel:\n");
			if(testCall2(info)) {
				printf("ERROR: testCall2 encountered error while sending process data\n");
			}
			// while(!info->pid);
			printinfo(info);
			wait(0);
		}
	}
}

void printinfo(pinfo *info) {
	printf("state:       	 %10ld\n", info->state);
	printf("pid:             %10ld\n", info->pid);
	printf("parent_pid:      %10ld\n", info->parent_pid);
	printf("youngest_child:  %10ld\n", info->youngest_child);
	printf("younger_sibling: %10ld\n", info->younger_sibling);
	printf("older_sibling:   %10ld\n", info->older_sibling);
	printf("uid:             %10ld\n", info->uid);
	printf("start_time:      %10lld\n", info->start_time);
	printf("user_time:       %10lld\n", info->user_time);
	printf("sys_time:        %10lld\n", info->sys_time);
	printf("cutime:          %10lld\n", info->cutime);
	printf("cstime:          %10lld\n\n", info->cstime);
}