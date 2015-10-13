#include <linux/module.h>	
#include <linux/kernel.h>
#include <linux/sched.h>	
#include <linux/moduleparam.h>
#include <linux/unistd.h>
#include <asm-generic/cacheflush.h>
#include "main.h"

/*
 * This is the array of protected system locations. These will always
 * be protected initially, but later we'll provide a mechanism for a
 * user to customize this (as root, obviously).
 */
const char *protected_locations[5] = {
	"/usr/bin/",
	"/bin",
	"/boot",
	"/sbin",
	NULL
	};

/*
 * This is the Linux system call table. Modifying this is dangerous!
 */
void **sys_call_table;

/*
 * This is the original version of the open system call. We save it
 * so that we can restore it later. 
 */
asmlinkage int (*original_open_call)(const char *, int, int);
asmlinkage int (*original_unlink_call)(const char *);
asmlinkage int (*original_unlink_at_call)(const char *);
asmlinkage int (*getuid_call)(void);

/*
 * This function removes the protection from the system call table
 * so that we can write to it. If we don't do this then we get
 * rather ugly results!
 */
void set_page_rw(long unsigned int _addr) {
	unsigned int level;
    pte_t *pte = lookup_address(_addr, &level);

    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}

static int check_write_valid(const char *filename) {
	const char **needle = protected_locations;
	while (*needle) {
		char *p = strstr(filename, *needle);
		if ( p && p - filename == 0 && *p == '/' ) {
			printk(KERN_DEBUG "%s found in %s\n", *needle, filename);
			return false;
		}
		needle++;
	}

	return true;
}

asmlinkage int our_sys_unlinkat(const char *filename) {
	printk(KERN_DEBUG "user wants to unlinkat %s\n", filename);
	// In order to be invalid, an operation must:
	// 1) be a write operation AND
	// 2) be to a protected system location.
	//
	// First, check if the desired file is in a protected directory.
	if (check_write_valid(filename)) {
		goto all_ok;
	}

	printk(KERN_DEBUG "A file was unlinked by uid %d\n", getuid_call());
	printk(KERN_INFO "Blocking unlinkat operation to %s\n", filename);
	return EACCES;

all_ok:
	// Call the original system call. Otherwise, we lose the ability to
	// open any files. Needless to say, that's bad.
	return original_unlink_at_call(filename);
}

asmlinkage int our_sys_unlink(const char *filename) {
	printk(KERN_DEBUG "user wants to unlink %s\n", filename);
	// In order to be invalid, an operation must:
	// 1) be a write operation AND
	// 2) be to a protected system location.
	//
	// First, check if the desired file is in a protected directory.
	if (check_write_valid(filename)) {
		goto all_ok;
	}

	printk(KERN_DEBUG "A file was unlinked by uid %d\n", getuid_call());
	printk(KERN_INFO "Blocking unlink operation to %s\n", filename);
	return EACCES;

all_ok:
	// Call the original system call. Otherwise, we lose the ability to
	// open any files. Needless to say, that's bad.
	return original_unlink_at_call(filename);
}

/*
 * This is our new version of the open system call. This will replace
 * the current version running in the kernel.
 *
 * At some point, this might change, but this is unlikely, since any
 * sane OS will maintain a relatively stable system call interface so
 * as to not break existing programs.
 */
asmlinkage int our_sys_open(const char *filename, 
                            int flags, 
                            int mode) {
	// In order to be invalid, an operation must:
	// 1) be a write operation AND
	// 2) be to a protected system location.
	//
	// First, check if the desired file is in a protected directory.
	if (check_write_valid(filename)) {
		goto all_ok;
	}

	// Okay, the user is trying to read in a protected directory. This
	// isn't a problem as long as the user has permission, so skip ahead
	// and allow the read.
	if (mode & O_RDONLY) {
		goto all_ok;
	}

	printk(KERN_DEBUG "A file was opened by uid %d, mode %d\n", getuid_call(), mode);
	printk(KERN_INFO "Blocking write operation to %s\n", filename);
	return EACCES;

all_ok:
	// Call the original system call. Otherwise, we lose the ability to
	// open any files. Needless to say, that's bad.
	return original_open_call(filename, flags, mode);
}

/*
 * These are the module load and unload functions. Relatively basic
 * stuff.
 */
int init_module(void) {
	printk(KERN_INFO "Filesystem Hierarchy Protection for LINUX(tm) Starting Up...\n");

	// WARNING: following will fail on a relocatable kernel!
	sys_call_table = (void **)0xffffffff81801400;
	original_open_call = sys_call_table[__NR_open];
	original_unlink_call = sys_call_table[__NR_unlink];
	original_unlink_at_call = sys_call_table[__NR_unlinkat];
	getuid_call = sys_call_table[__NR_getuid];

	set_page_rw((long unsigned int)sys_call_table);
	sys_call_table[__NR_open] = our_sys_open;
	sys_call_table[__NR_unlink] = our_sys_unlink;
	sys_call_table[__NR_unlinkat] = our_sys_unlinkat;
	return 0;
}
 
void cleanup_module(void) {
	printk(KERN_INFO "Filesystem Hierarchy Protection for LINUX(tm) Shutting Down...\n");

	if (sys_call_table[__NR_open] != our_sys_open) {
		printk(KERN_WARNING "The current open system call is not the one we replaced."
		       " There may be issues...");
	}

	sys_call_table[__NR_open] = original_open_call;
	sys_call_table[__NR_unlink] = original_unlink_call;
	sys_call_table[__NR_unlinkat] = original_unlink_at_call;
}


MODULE_AUTHOR("SevenBits");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Filesystem Hierarchy Protection (FHP) Module for LINUX(tm)");
MODULE_VERSION(VERSION);
