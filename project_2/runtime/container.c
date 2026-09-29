/* container.c: STUDENT IMPLEMENTATION FILE for Project 2.
 *
 * You implement a minimal container runtime here. main.c parses the command
 * line and calls container_run(); everything after that is yours.
 *
 * The TODOs below are the checklist: what to call and in what order. SPEC.md
 * explains what each mechanism is and why the order matters, and is the
 * contract if the two ever disagree.
 *
 * As shipped, container_run() returns 1 and nothing runs, so no checks pass.
 * Start by getting the command to execute: that needs container_run() and
 * container_init() to spawn it and container_setup() to pivot into the rootfs,
 * because the command lives inside the rootfs.
 *
 * Provided: main.c (argument parsing), util.c (write_file()), net.c (the --net
 * host side), container.h (the struct, the declarations, the stack size).
 */
#define _GNU_SOURCE
#include "container.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>

#if defined(__x86_64__)
#define CONTAINER_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CONTAINER_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "Unsupported architecture"
#endif

#define DENY_SYSCALL(name)                                      \
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1),      \
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)

/* ---- Part I: namespaces ----------------------------------------------- */

int container_namespaces(void)
{
    /* TODO(student): return the bitwise-OR of CLONE_NEWUSER, CLONE_NEWPID,
     * CLONE_NEWNS, CLONE_NEWUTS and CLONE_NEWNET. Returning 0 gives no
     * isolation at all. */
    return CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWNET;
}

int container_write_idmaps(struct container *c, pid_t child)
{
    (void)c; (void)child;
    /* TODO(student): a USER namespace starts with an EMPTY uid/gid map, so the
     * child cannot do anything until you write one. Write, using write_file():
     *   /proc/<child>/uid_map     <- "0 <your-uid> 1"
     *   /proc/<child>/setgroups   <- "deny"      (required before gid_map)
     *   /proc/<child>/gid_map     <- "0 <your-gid> 1"
     * This maps container id 0 (root) to your real id outside. See getuid(2). */

    uid_t uid = getuid(); 
    gid_t gid = getgid();

    char value[64];
    char path[64];

    snprintf(value, sizeof(value), "0 %u 1", uid);
    snprintf(path, sizeof(path), "/proc/%u/uid_map", child);
    if (write_file(path, value) == -1) {
        return -1;
    } 

    snprintf(value, sizeof(value), "deny");
    snprintf(path, sizeof(path), "/proc/%u/setgroups", child);
    if (write_file(path, value) == -1) {
        return -1;
    } 

    snprintf(value, sizeof(value), "0 %u 1", gid);
    snprintf(path, sizeof(path), "/proc/%u/gid_map", child);
    if (write_file(path, value) == -1) {
        return -1;
    } 

    return 0;
}

/* ---- Part V: cgroup --------------------------------------------------- */

int container_cgroup_init(struct container *c)
{
    (void)c;
    /* TODO(student): create this container's cgroup and set its limits (SPEC
     * Part V):
     *   - enable the controllers you need in the BASE cgroup's subtree_control:
     *       write "+pids +memory" to <cgroup_base>/cgroup.subtree_control;
     *   - mkdir <cgroup_base>/<name>  and store that path in c->cg_path
     *     (cleanup needs it);
     *   - write c->pids_max to <cg_path>/pids.max and c->mem_max to
     *     <cg_path>/memory.max (a value < 0 means the literal string "max"), and
     *     write "0" to <cg_path>/memory.swap.max so hitting the memory cap
     *     OOM-kills instead of swapping. */
    char *value = "+pids +memory";
    char path[64];

    snprintf(path, sizeof(path), "%s/cgroup.subtree_control", c->cgroup_base);
    if (write_file(path, value) == -1) return -1;

    snprintf(c->cg_path, sizeof(c->cg_path), "%s/%s", c->cgroup_base, c->name);
    if (mkdir(path, 0755) == -1) return -1; //check mode bits 

    snprintf(path, sizeof(path), "%s/pids.max", c->cg_path);
    if (write_file(path, c->pids_max) == -1) return -1;

    snprintf(path, sizeof(path), "%s/memory.max", c->cg_path);
    if (write_file(path, c->mem_max) == -1) return -1;

    snprintf(path, sizeof(path), "%s/memory.swap.max", c->cg_path);
    if (write_file(path, 0) == -1) return -1;

    return 0;
}

int container_cgroup_enter(struct container *c, pid_t child)
{
    (void)c; (void)child;
    /* TODO(student): move `child` into this container's cgroup by writing its
     * pid to <cg_path>/cgroup.procs. */
    char path[64];
    snprintf(path, sizeof(path), "%s/cgroup.procs", c->cg_path);
    if (write_file(path, child) == -1) return -1;
    return 0;
}

/* ---- Parts I/II/III: isolation, run inside the container init --------- */

int container_setup(struct container *c)
{
    (void)c;
    /* Runs inside the container's init, after the parent has written your id
     * maps and put you in the cgroup, and before you launch the command.
     *
     * TODO(student) Part I   - set the hostname to c->hostname (sethostname(2)).
     *
     * TODO(student) Part I   - call container_network() to bring up loopback
     *     (before the capability drop; it needs CAP_NET_ADMIN).
     *
     * TODO(student) Part I   - if c->net_enabled, call container_net_config(c)
     *     to set up the veth the host provided (also before the cap drop).
     *
     * TODO(student) Part II  - isolate the filesystem, pivoting into c->rootfs:
     *     1. make mount propagation private so your mounts don't leak to the
     *        host:  mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
     *     2. bind c->rootfs onto itself, then remount that bind read-only;
     *     3. mount a writable tmpfs on <rootfs>/tmp;
     *     4. mount a tmpfs on <rootfs>/dev and bind /dev/null and /dev/zero in
     *        (you cannot mknod(2) in a user namespace);
     *     5. mount a fresh /proc on <rootfs>/proc, BEFORE switching roots: a
     *        new /proc can only be mounted in a user namespace while another
     *        /proc is still visible, so doing it after detaching the old root
     *        fails with EPERM;
     *     6. pivot_root(2) into c->rootfs and detach the old root, chdir("/").
     *
     * TODO(student) Part III - drop all capabilities so container-root is
     *     powerless: empty the bounding set (prctl PR_CAPBSET_DROP for every cap
     *     0..CAP_LAST_CAP), clear the permitted/effective/inheritable sets
     *     (capset(2)), and set PR_SET_NO_NEW_PRIVS. Do this near-last, so the
     *     steps above still have the privileges they need.
     *
     * TODO(student) Part III - then call container_seccomp() to install the
     *     syscall filter (do it last of all).
     *
     * Return 0 on success, -1 to abort. */

    if (sethostname(c->hostname, strlen(c->hostname)) == -1) return -1;
    if (container_network() == -1) return -1;
    if (c->net_enabled && container_net_config(c) == -1) return -1;

    // Part II
    mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);

    // bind c->rootfs onto itself
    if (mount(c->rootfs, c->rootfs, NULL, MS_BIND | MS_REC, NULL) == -1) return -1;

    // then remount that bind read-only
    if (mount(NULL, c->rootfs, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == -1) return -1;


    // mounting writable temp fs onto root/tmpfs
    char tmp_path[64];
    snprintf(tmp_path, sizeof(tmp_path), "%s/tmp", c->rootfs);

    char dev_path[64];
    snprintf(dev_path, sizeof(dev_path), "%s/dev", c->rootfs);

    char dev_null_path[64];
    snprintf(dev_null_path, sizeof(dev_null_path), "%s/dev/null", c->rootfs);

    char dev_zero_path[64];
    snprintf(dev_zero_path, sizeof(dev_zero_path), "%s/dev/zero", c->rootfs);

    char proc_path[64];

    snprintf(proc_path, sizeof(proc_path), "%s/proc", c->rootfs);

    if (mount("tmpfs", tmp_path, "tmpfs", 0, NULL) == -1) return -1; 
    if (mount("tmpfs", dev_path, "tmpfs", 0, NULL) == -1) return -1; 

    // create dev/null and dev/zero files (?)
    int fd;
    if ((fd = open(dev_null_path, O_CREAT | O_WRONLY, 0666)) == -1) return -1;
    close(fd);
    if ((fd = open(dev_zero_path, O_CREAT | O_WRONLY, 0666)) == -1) return -1;
    close(fd);

    // mounting (spec part II)
    if (mount("/dev/null", dev_null_path, NULL, MS_BIND, NULL) == -1) return -1;
    if (mount("dev/zero", dev_zero_path, NULL, MS_BIND, NULL) == -1) return -1;
    if (mount("proc", proc_path, "proc", 0, NULL) == -1) return -1;

    //detach root
    if (chdir(c->rootfs) == -1) return -1;
    if (syscall(SYS_pivot_root, ".", ".") == -1) return -1;
    if (umount2(".", MNT_DETACH) == -1) return -1;
    if (chdir("/") == -1) return -1;

    // Part III
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == -1) return -1;
    }

    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct data[2] = {0};

    if (syscall(SYS_capset, &hdr, data) == -1) return -1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) return -1;

    
    return 0;
}

int container_network(void)
{
    /* TODO(student) Part I: the container has its own NET namespace, so it starts
     * with only a `lo` interface that is DOWN. Bring it UP so localhost works:
     * open an AF_INET SOCK_DGRAM socket, fill a `struct ifreq` with ifr_name
     * "lo", ioctl(SIOCGIFFLAGS) to read its flags, OR in IFF_UP | IFF_RUNNING,
     * and ioctl(SIOCSIFFLAGS) to set them. Best-effort: this needs CAP_NET_ADMIN,
     * so call it before dropping capabilities. */

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, "lo", sizeof("lo"));
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) {
        close(fd);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int container_net_config(struct container *c)
{
    /* TODO(student) Part I (--net only): the provided container_net_host_setup()
     * has put an interface named c->net_ifname in this namespace. Configure it
     * (same ioctls as loopback, plus an address and a route):
     *   - ioctl(SIOCSIFADDR)   with c->net_ip;
     *   - ioctl(SIOCSIFNETMASK) with the mask for c->net_prefix;
     *   - ioctl(SIOCSIFFLAGS)  with IFF_UP | IFF_RUNNING;
     *   - add a default route via c->net_gw: fill a `struct rtentry`
     *     (rt_dst/rt_genmask 0.0.0.0, rt_gateway = c->net_gw,
     *     rt_flags = RTF_UP | RTF_GATEWAY) and ioctl(SIOCADDRT).
     * Needs CAP_NET_ADMIN, so container_setup() calls this before the cap drop. */
    if (!c || !c->net_ifname || !c->net_ip || !c->net_gw ||
        c->net_prefix < 0 || c->net_prefix > 32) {
        errno = EINVAL;
        return -1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    size_t ifname_len = strlen(c->net_ifname);
    if (ifname_len == 0 || ifname_len >= sizeof(ifr.ifr_name)) {
        errno = ENAMETOOLONG;
        goto fail;
    }
    memcpy(ifr.ifr_name, c->net_ifname, ifname_len + 1);

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, c->net_ip, &address.sin_addr) != 1) {
        errno = EINVAL;
        goto fail;
    }
    memcpy(&ifr.ifr_addr, &address, sizeof(address));
    if (ioctl(fd, SIOCSIFADDR, &ifr) == -1) goto fail;

    memset(&address.sin_addr, 0, sizeof(address.sin_addr));
    uint32_t mask = c->net_prefix == 0
        ? 0
        : UINT32_MAX << (32 - c->net_prefix);
    address.sin_addr.s_addr = htonl(mask);
    memcpy(&ifr.ifr_netmask, &address, sizeof(address));
    if (ioctl(fd, SIOCSIFNETMASK, &ifr) == -1) goto fail;

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) == -1) goto fail;
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) == -1) goto fail;

    struct rtentry route;
    memset(&route, 0, sizeof(route));
    struct sockaddr_in route_address;
    memset(&route_address, 0, sizeof(route_address));
    route_address.sin_family = AF_INET;
    route_address.sin_addr.s_addr = INADDR_ANY;
    memcpy(&route.rt_dst, &route_address, sizeof(route_address));
    memcpy(&route.rt_genmask, &route_address, sizeof(route_address));

    if (inet_pton(AF_INET, c->net_gw, &route_address.sin_addr) != 1) {
        errno = EINVAL;
        goto fail;
    }
    memcpy(&route.rt_gateway, &route_address, sizeof(route_address));
    route.rt_flags = RTF_UP | RTF_GATEWAY;
    route.rt_dev = (char *)c->net_ifname;
    if (ioctl(fd, SIOCADDRT, &route) == -1) goto fail;

    close(fd);
    return 0;

fail:
    {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return -1;
}

int container_seccomp(void)
{
    /* TODO(student) Part III: install a seccomp-BPF filter that blocks a
     * denylist of dangerous syscalls (ptrace, mount, umount2, pivot_root,
     * chroot, setns, unshare, reboot, swapon/swapoff, kexec_load, and the
     * *_module calls) by returning EPERM, and allows everything else.
     *
     * Build a `struct sock_filter[]` with <linux/filter.h> / <linux/seccomp.h>:
     *   1. load seccomp_data.arch and reject a foreign ABI (compare against
     *      AUDIT_ARCH_X86_64 or AUDIT_ARCH_AARCH64 for your build arch);
     *   2. load seccomp_data.nr and, for each denied __NR_*, return
     *      SECCOMP_RET_ERRNO | EPERM;
     *   3. otherwise return SECCOMP_RET_ALLOW.
     * Then prctl(PR_SET_NO_NEW_PRIVS, 1, ...) and
     * syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog). */

    struct sock_filter filter[] = {
        // Checking architecture and rejecting mismatched option
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,
                 CONTAINER_AUDIT_ARCH, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),

        // Checking syscalls
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        DENY_SYSCALL(ptrace),
        DENY_SYSCALL(mount),
        DENY_SYSCALL(umount2),
        DENY_SYSCALL(pivot_root),
        DENY_SYSCALL(chroot),
        DENY_SYSCALL(setns),
        DENY_SYSCALL(unshare),
        DENY_SYSCALL(reboot),
        DENY_SYSCALL(swapon),
        DENY_SYSCALL(swapoff),
        DENY_SYSCALL(kexec_load),
        DENY_SYSCALL(init_module),
        DENY_SYSCALL(finit_module),
        DENY_SYSCALL(delete_module),

        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };

    struct sock_fprog prog = {
        .filter = filter,
        .len = (unsigned short)(sizeof(filter) / sizeof(filter[0]))
    };

    if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog) == -1) return -1;
 
    return 0;
}

int container_init(struct container *c)
{
    (void)c;
    /* TODO(student) Part IV: this is the container's init, PID 1 in a fresh PID
     * namespace. It runs in the cloned child. Do, in order:
     *   1. wait for the parent to release you: close c->sync[1], then read one
     *      byte from c->sync[0] (it blocks until main's parent writes id-maps
     *      and enters you in the cgroup), then close c->sync[0];
     *   2. call container_setup(c) to isolate this process;
     *   3. fork(). In the child, execvp(c->argv[0], c->argv) -- that is the
     *      command. The parent (you) STAYS as init;
     *   4. loop waitpid(-1, ...): reap every child that dies (adopted orphans
     *      included). Stop when the command itself is reaped; return its exit
     *      status (WEXITSTATUS, or 128+signal if it was killed).
     * The value you return here is what the container exits with. */

    if (close(c->sync[1]) == -1) return -1;
    if (read(c->sync[0], NULL, 1) == -1) return -1; // do we need to have buf
    if (close(c->sync[0]) == -1) return -1;

    container_setup(c);

    pid_t fork_ret = fork();
    if (fork_ret == 0) {
        // child 
        execvp(c->argv[0], c->argv);
        exit(-1);
    } else {
        while (1) {
            int status;
            pid_t w = waitpid(-1, &status, 0);
            
            if (w == fork_ret) {
                if(WIFEXITED(status)) {
                    return WEXITSTATUS(status);
                } else if (WIFSIGNALED(status)) {
                    return 128 + WTERMSIG(status);
                }
            }
        }
    }


    return 0;
}

/* ---- the whole lifecycle: main.c calls only this ----------------------- */

int container_run(struct container *c)
{
    (void)c;
    /* TODO(student): drive the container's whole lifecycle and return the
     * command's exit status. In order:
     *   1. container_cgroup_init(c)                      (Part V);
     *   2. pipe(c->sync)                                 (the release pipe);
     *   3. clone() a child into fresh namespaces: allocate a stack of
     *      CONTAINER_STACK_SIZE bytes, and clone a small trampoline that calls
     *      container_init(c), with flags container_namespaces() | SIGCHLD.
     *      (clone wants an int(*)(void*); the stack grows down, so pass the
     *      TOP of the buffer: stack + CONTAINER_STACK_SIZE.);
     *   4. container_write_idmaps(c, child)              (Part I);
     *   5. container_cgroup_enter(c, child)              (Part V);
     *   6. if c->net_enabled, call the PROVIDED container_net_host_setup(c, child)
     *      here (after the cgroup step, before releasing the child): it sets up
     *      the bridge + veth and moves one end into the child's netns;
     *   7. release the child: close c->sync[0], write a byte to c->sync[1];
     *   8. waitpid(child): the child (your init) exits with the command's
     *      status; turn that into a 0-255 return value;
     *   9. if c->net_enabled, call container_net_host_teardown(c), then
     *      container_cleanup(c)                          (Part VI);
     *  10. return the status.
     *
     * As shipped this returns 1 and nothing runs. Start here. */

    /* Keep the "container: " prefix on anything you print here: the test
     * harness reads the container's output and skips lines starting with it. */
    fprintf(stderr, "container: container_run() is not implemented yet, "
                    "so nothing ran. See SPEC.md.\n");
    return 1;
}

/* ---- Part VI: teardown ------------------------------------------------- */

int container_cleanup(struct container *c)
{
    (void)c;
    /* TODO(student): the child (and its whole subtree) is already reaped, so its
     * cgroup is empty and its mount namespace is gone. Remove the cgroup
     * directory you created (rmdir c->cg_path). Tolerate it already being gone. */
    if (rmdir(c->cg_path) == -1 && errno != ENOENT) return -1;
    
    return 0;
}
