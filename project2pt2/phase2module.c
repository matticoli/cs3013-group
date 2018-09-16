#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/time.h>
#include <asm/cputime.h>
#include <linux/uidgid.h>

unsigned long **sys_call_table;


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

asmlinkage long (*ref_sys_cs3013_syscall2)(void);

asmlinkage long new_sys_cs3013_syscall2(struct processinfo *info) {
   // printk(KERN_INFO "\nP2M: =========================\n");
    //printk(KERN_INFO "\n\nP2M: Here's the struct: %p\n", info);

    printk(KERN_INFO "P2M: State: %ld\n", current->state);
    printk(KERN_INFO "P2M: PID: %ld\n", current->pid);
    printk(KERN_INFO "P2M: Parent PID: %ld\n", current->parent->pid);

  //to store user and system time of children
  long long int utimeChild = 0;
  long long int stimeChild = 0;

  struct list_head *position = NULL; //position counter
  long long int latestStart = 0; //store latest start seen
  struct task_struct* child = NULL;
  long int youngChild = 0; //store pid of youngest child seen

  list_for_each_entry(child, &(current->children), sibling) {
    //printk(KERN_INFO "\tP2M: Child at %p has pid %d\n", child, child->pid);

    if(child->start_time > latestStart){
      youngChild = child->pid;
      latestStart = child->start_time;
    }
  utimeChild = (utimeChild + child->utime);
  stimeChild = (stimeChild + child->stime);

  } 

  if(latestStart == 0){
    youngChild = -1;
  }

  printk(KERN_INFO "P2M: Youngest Child PID: %ld\n", youngChild);


  //printk(KERN_INFO "P2M: Siblings:\n");

  position = NULL; //position counter
  long long int closestOlder = 0; //store latest start seen
  long long int closestYounger = 0; //store latest start seen
  struct task_struct* sib = NULL;
  long int youngSibling = 0; //store pid of youngest child seen
  long int oldSibling = 0; //store pid of youngest child seen


  list_for_each_entry(sib, &(current->real_parent->children), sibling) {
    u64 diff;
    int isNegative;
  
    if(sib->start_time >= current->start_time) {
        diff = sib->start_time - current->start_time;
        isNegative = 0;
    } else {
        diff = current->start_time - sib->start_time;
        isNegative = 1;
    }

    // printk(KERN_INFO "\tP2M: PID %d DIFF %lld\n", sib-> pid, diff);
    if(sib->pid != current->pid && isNegative && (diff < closestOlder || closestOlder ==0)) {
      // printk(KERN_INFO "\tP2M: Le diff %lld\n", diff);
      oldSibling = sib->pid;
      closestOlder = sib->start_time;
    } 
    // printk(KERN_INFO "P2M: <0 %d , oldest younger: %d\n", diff < 0 , (diff > closestYounger || closestYounger == 0));
    if(sib->pid != current->pid && !isNegative && (diff < closestYounger || closestYounger == 0)) {
      youngSibling = sib->pid;
      closestYounger = sib->start_time;
    }
  }

  if(closestYounger == 0){
    youngSibling = -1;
  }
  if(closestOlder == 0){
    oldSibling = -1;
  }
  printk(KERN_INFO "P2M: Next Older Sibling PID: %ld\n", oldSibling);
  printk(KERN_INFO "P2M: Next Younger Sibling PID: %ld\n", youngSibling);


    // printk(KERN_INFO "P2M: Youngest: %ld\n", current->children); TODO get data from list
    printk(KERN_INFO "P2M: UID: %ld\n", current->cred->uid);
    printk(KERN_INFO "P2M: Start Time: %llu\n", current->start_time);
    printk(KERN_INFO "P2M: User Time %llu\n", cputime_to_usecs(current->utime));
    printk(KERN_INFO "P2M: System Time %llu\n", cputime_to_usecs(current->stime));
    

    printk(KERN_INFO "P2M: User Time of Children %llu\n", cputime_to_usecs(utimeChild));
    printk(KERN_INFO "P2M: System Time of Children %llu\n", cputime_to_usecs(stimeChild));


/* COPY DATA TO USER */
//store in struct info
    printk(KERN_INFO "P2M: Print data to send to user\n");
pinfo stats;

    printk(KERN_INFO "P2M: Fill data to send to user\n");
stats.state = current->state;
stats.pid = current->pid;
stats.parent_pid = current->parent->pid;
stats.youngest_child = youngChild;
stats.older_sibling = oldSibling;
stats.younger_sibling = youngSibling;
stats.uid = __kuid_val(current->cred->uid);
stats.start_time = current->start_time;
stats.user_time = cputime_to_usecs(current->utime);
stats.sys_time = cputime_to_usecs(current->stime);
stats.cutime = cputime_to_usecs(utimeChild);
stats.cstime = cputime_to_usecs(stimeChild);

printk(KERN_INFO "P2M: Send data to user\n");
if (copy_to_user(info, &stats, sizeof(stats))) {
  printk(KERN_INFO "P2M: Uh oh- something broke\n");
  return EFAULT; // Fail
}

    // pinfo processData = malloc(sizeof(pinfo));
    return 0;

}
static unsigned long **find_sys_call_table(void) {
  unsigned long int offset = PAGE_OFFSET;
  unsigned long **sct;
  
  while (offset < ULLONG_MAX) {
    sct = (unsigned long **)offset;

    if (sct[__NR_close] == (unsigned long *) sys_close) {
      printk(KERN_INFO "Interceptor: Found syscall table at address: 0x%02lX\n",
                (unsigned long) sct);
      return sct;
    }
    
    offset += sizeof(void *);
  }
  
  return NULL; // Success
}

static void disable_page_protection(void) {
  /*
    Control Register 0 (cr0) governs how the CPU operates.

    Bit #16, if set, prevents the CPU from writing to memory marked as
    read only. Well, our system call table meets that description.
    But, we can simply turn off this bit in cr0 to allow us to make
    changes. We read in the current value of the register (32 or 64
    bits wide), and AND that with a value where all bits are 0 except
    the 16th bit (using a negation operation), causing the write_cr0
    value to have the 16th bit cleared (with all other bits staying
    the same. We will thus be able to write to the protected memory.

    It's good to be the kernel!
   */
  write_cr0 (read_cr0 () & (~ 0x10000));
}

static void enable_page_protection(void) {
  /*
   See the above description for cr0. Here, we use an OR to set the 
   16th bit to re-enable write protection on the CPU.
  */
  write_cr0 (read_cr0 () | 0x10000);
}

static int __init interceptor_start(void) {
  /* Find the system call table */
  if(!(sys_call_table = find_sys_call_table())) {
    /* Well, that didn't work. 
       Cancel the module loading step. */
    return -1;
  }
  
  /* Store a copy of all the existing functions */
  ref_sys_cs3013_syscall2 = (void *)sys_call_table[__NR_cs3013_syscall2];

  /* Replace the existing system calls */
  disable_page_protection();

  sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)new_sys_cs3013_syscall2;
  
  enable_page_protection();
  
  /* And indicate the load was successful */
  printk(KERN_INFO "Loaded interceptor!");

  return 0;
}

static void __exit interceptor_end(void) {
  /* If we don't know what the syscall table is, don't bother. */
  if(!sys_call_table)
    return;
  
  /* Revert all system calls to what they were before we began. */
  disable_page_protection();
  sys_call_table[__NR_cs3013_syscall2] = (unsigned long *)ref_sys_cs3013_syscall2;
  enable_page_protection();

  printk(KERN_INFO "Unloaded interceptor!");
}

MODULE_LICENSE("GPL");
module_init(interceptor_start);
module_exit(interceptor_end);
