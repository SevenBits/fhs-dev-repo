/*
 * The KERNEL_VERSION macro is not defined in some older
 * kernels.
 */
#ifndef KERNEL_VERSION
#define KERNEL_VERSION(a,b,c) ((a)*65536+(b)*256+(c))
#endif

#define VERSION "0.1"
