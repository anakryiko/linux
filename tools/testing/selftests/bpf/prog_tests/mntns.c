// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Meta Platforms, Inc. and affiliates. */
#define _GNU_SOURCE
#include <test_progs.h>
#include <bpf/btf.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/unistd.h>
//#include <linux/mount.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/un.h>

enum fsconfig_command {
        FSCONFIG_SET_FLAG       = 0,    /* Set parameter, supplying no value */
        FSCONFIG_SET_STRING     = 1,    /* Set parameter, supplying a string value */
        FSCONFIG_SET_BINARY     = 2,    /* Set parameter, supplying a binary blob value */
        FSCONFIG_SET_PATH       = 3,    /* Set parameter, supplying an object by path */
        FSCONFIG_SET_PATH_EMPTY = 4,    /* Set parameter, supplying an object by (empty) path */
        FSCONFIG_SET_FD         = 5,    /* Set parameter, supplying an object by fd */
        FSCONFIG_CMD_CREATE     = 6,    /* Invoke superblock creation */
        FSCONFIG_CMD_RECONFIGURE = 7,   /* Invoke superblock reconfiguration */
};


__attribute__((unused))
static inline int sys_fsopen(const char *fsname, unsigned flags)
{
	return syscall(__NR_fsopen, fsname, flags);
}

__attribute__((unused))
static inline int sys_fsconfig(int fs_fd, unsigned cmd, const char *key, const void *val, int aux)
{
	return syscall(__NR_fsconfig, fs_fd, cmd, key, val, aux);
}

__attribute__((unused))
static inline int sys_fsmount(int fs_fd, unsigned flags, unsigned ms_flags)
{
	return syscall(__NR_fsmount, fs_fd, flags, ms_flags);
}

__attribute__((unused))
static inline int sys_move_mount(int from_dfd, const char *from_path,
			         int to_dfd, const char *to_path,
			         unsigned int ms_flags)
{
	return syscall(__NR_move_mount, from_dfd, from_path, to_dfd, to_path, ms_flags);
}

__attribute__((unused))
static inline int sys_open_tree(int dfd, const char *filename, unsigned flags)
{
	return syscall(__NR_open_tree, dfd, filename, flags);
}

#define TDIR "/sys/kernel/debug"

static char tname[32];

static int sendfd(int sockfd, int fd)
{
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	int fds[1] = { fd };
	char iobuf[1];
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf),
	};
	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);
	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(fds));
	memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

	if (sendmsg(sockfd, &msg, 0) < 0) {
		fprintf(stderr, "%s: failed to send fd %d over sock %d: %d\n", tname, fd, sockfd, -errno);
		return -errno;
	}

	fprintf(stderr, "%s: SENT FD %d to SOCK %d\n", tname, fd, sockfd);

	return 0;
}

static int recvfd(int sockfd, int *fd)
{
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg;
	int fds[1];
	char iobuf[1];
	struct iovec io = {
		.iov_base = iobuf,
		.iov_len = sizeof(iobuf),
	};
	union {
		char buf[CMSG_SPACE(sizeof(fds))];
		struct cmsghdr align;
	} u;

	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	if (recvmsg(sockfd, &msg, 0) < 0) {
		fprintf(stderr, "%s: failed to recv fd from sock %d: %d\n", tname, sockfd, -errno);
		return -errno;
	}

	cmsg = CMSG_FIRSTHDR(&msg);
	if (cmsg == NULL
	    || cmsg->cmsg_len != CMSG_LEN(sizeof(fds))
	    || cmsg->cmsg_level != SOL_SOCKET
	    || cmsg->cmsg_type != SCM_RIGHTS) {
		fprintf(stderr, "%s: invalid cmsg received!\n", tname);
		return -EINVAL;
	}

	memcpy(fds, CMSG_DATA(cmsg), sizeof(fds));
	*fd = fds[0];

	fprintf(stderr, "%s: GOT FD %d from SOCK %d\n", tname, *fd, sockfd);

	return 0;
}


int fsfd1, fsfd2;
int mntfd1, mntfd2;
int sockfds[2];

static int create_bpffs(void)
{
	fsfd1 = sys_fsopen("bpf", 0);
	sys_fsconfig(fsfd1, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	mntfd1 = sys_fsmount(fsfd1, 0, 0);
	if (mntfd1 < 0) {
		fprintf(stderr, "%s: failed to create fs1: %d\n", tname, -errno);
		return -errno;
	}
	fprintf(stderr, "Mount FD1: %d\n", mntfd1);

	fsfd2 = sys_fsopen("bpf", 0);
	sys_fsconfig(fsfd2, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
	mntfd2 = sys_fsmount(fsfd2, 0, 0);
	if (mntfd2 < 0) {
		fprintf(stderr, "%s: failed to create fs2: %d\n", tname, -errno);
		return -errno;
	}
	fprintf(stderr, "Mount FD2: %d\n", mntfd2);
	return 0;
}

#define FSPICK_CLOEXEC          0x00000001
#define FSPICK_SYMLINK_NOFOLLOW 0x00000002
#define FSPICK_NO_AUTOMOUNT     0x00000004
#define FSPICK_EMPTY_PATH       0x00000008

#define MOVE_MOUNT_F_SYMLINKS           0x00000001 /* Follow symlinks on from path */
#define MOVE_MOUNT_F_AUTOMOUNTS         0x00000002 /* Follow automounts on from path */
#define MOVE_MOUNT_F_EMPTY_PATH         0x00000004 /* Empty from path permitted */
#define MOVE_MOUNT_T_SYMLINKS           0x00000010 /* Follow symlinks on to path */
#define MOVE_MOUNT_T_AUTOMOUNTS         0x00000020 /* Follow automounts on to path */
#define MOVE_MOUNT_T_EMPTY_PATH         0x00000040 /* Empty to path permitted */
#define MOVE_MOUNT_SET_GROUP            0x00000100 /* Set sharing group instead */
#define MOVE_MOUNT__MASK                0x00000177

#define OPEN_TREE_CLONE         1               /* Clone the target tree and attach the clone */
#define OPEN_TREE_CLOEXEC       O_CLOEXEC       /* Close the file on execve() */


__attribute__((unused))
static void rdlink(const char *path)
{
	char buf[256];

	snprintf(buf, sizeof(buf), "readlink %s | sed -e 's/^/%s: /'", path, tname);
	system(buf);
}

__attribute__((unused))
static void cat(const char *path)
{
	char buf[256];

	snprintf(buf, sizeof(buf), "cat %s | sed -e 's/^/%s: /'", path, tname);
	system(buf);
}

__attribute__((unused))
static void cmd(const char *cmd, ...)
{
	va_list args;
	char buf[512], tmp[256];

	va_start(args, cmd);
	vsnprintf(tmp, sizeof(tmp), cmd, args);
	va_end(args);

	snprintf(buf, sizeof(buf), "%s | sed -e 's/^/%s: /'", tmp, tname);
	system(buf);
}

static int prep_mntns(bool first)
{
	int err, mntfd, clonefd = -1;

	err = unshare(CLONE_NEWNS);
	if (err) {
		fprintf(stderr, "%s: Failed to unshare mnt\n", tname);
		return -EINVAL;
	}
	err = mount("", "/", "", MS_REC | MS_PRIVATE, NULL);
	if (err) {
		fprintf(stderr, "%s: Failed to remount\n", tname);
		return -EINVAL;
	}
	err = umount(TDIR);
	if (err) {
		fprintf(stderr, "%s: Failed to umount /tmp\n", tname);
		return -EINVAL;
	}
	err = err ?: mount("none", TDIR, "tmpfs", 0, NULL);
	if (err) {
		fprintf(stderr, "%s: Failed to mount tmpfs\n", tname);
		return -EINVAL;
	}
	if (first) {
		err = err ?: mkdir(TDIR "/A", 0777);
	} else {
		err = err ?: mkdir(TDIR "/B", 0777);
	}
	if (err) {
		fprintf(stderr, "%s: Failed mkdir tmp subdir\n", tname);
		return -EINVAL;
	}
	if (first) {
		err = sys_move_mount(mntfd1, "", -EBADF, TDIR "/A", MOVE_MOUNT_F_EMPTY_PATH);
		if (err) fprintf(stderr, "%s: Failed to move_mount %s: %d\n", tname, TDIR "/A", -errno);
	} else {
		err = sys_move_mount(mntfd2, "", -EBADF, TDIR "/B", MOVE_MOUNT_F_EMPTY_PATH);
		if (err) fprintf(stderr, "%s: Failed to move_mount %s: %d\n", tname, TDIR "/B", -errno);
	}
	if (first) {
		clonefd = sys_open_tree(-EBADF, TDIR "/A", OPEN_TREE_CLONE);
		if (clonefd < 0) {
			fprintf(stderr, "%s: Failed to open_tree() %d: %d\n", tname, mntfd1, -errno);
			return -EINVAL;
		}
	}
	sleep(1);
	err = unshare(CLONE_NEWUSER);
	if (err) {
		fprintf(stderr, "%s: Failed to unshare user\n", tname);
		return -EINVAL;
	}
	if (first) {
		err = err ?: mkdir(TDIR "/A/SUBA", 0777);
		err = err ?: mkdirat(mntfd1, "SUBAA", 0777);
		err = err ?: mkdirat(mntfd2, "SUBAAA", 0777);
	} else {
		err = err ?: mkdir(TDIR "/B/SUBB", 0777);
		err = err ?: mkdirat(mntfd2, "SUBBB", 0777);
		err = err ?: mkdirat(mntfd1, "SUBBBB", 0777);
	}
	if (err) {
		fprintf(stderr, "%s: Failed mkdir inside BPFFS\n", tname);
		return -EINVAL;
	}

	sendfd(first ? sockfds[0] : sockfds[1], first ? mntfd1 : mntfd2);
	recvfd(first ? sockfds[0] : sockfds[1], &mntfd);
	
	err = mkdirat(mntfd, first ? "UDS_AAAA" : "UDS_BBBB", 0777);
	if (err)
		fprintf(stderr, "%s: Failed mkdir inside BPFFS received from UDS: %d\n", tname, -errno);

	if (first) {
		/* this WILL FAIL */
		err = sys_move_mount(clonefd, "", mntfd, "UDS_AAAA", MOVE_MOUNT_F_EMPTY_PATH);
		if (err) fprintf(stderr, "%s: Failed to move_mount into %s: %d\n", tname, "UDS_AAAA", -errno);
	}

	sleep(first ? 0 : 1);

	rdlink("/proc/self/ns/mnt");
	rdlink("/proc/self/ns/user");
	cmd("cat /proc/self/mountinfo | grep " TDIR);
	cmd("echo %d vs %d; cat /proc/self/fdinfo/%d; cat /proc/self/fdinfo/%d",
	    first ? mntfd1 : mntfd2, mntfd, first ? mntfd1 : mntfd2, mntfd);
	//cmd("tree " TDIR);
	if (first)
		cmd("ls -la " TDIR "/A");
	else
		cmd("ls -la " TDIR "/B");

	return 0;
}

static int child1_main(void)
{
	int err;

	sprintf(tname, "child1(%d)", getpid());
	printf("%s STARTED\n", tname);

	err = prep_mntns(true);
	if (err) {
		fprintf(stderr, "%s: Failed to prep mount namespace\n", tname);
		return 1;
	}


	printf("%s EXITING\n", tname);
	return 0;
}

static int child2_main(void)
{
	int err;

	sprintf(tname, "child2(%d)", getpid());
	printf("%s STARTED\n", tname);

	err = prep_mntns(false);
	if (err) {
		fprintf(stderr, "%s: Failed to prep mount namespace\n", tname);
		return 1;
	}

	printf("%s EXITING\n", tname);
	return 0;
}

void test_mntns()
{
	int pid1, pid2;
	int status, err;

	sprintf(tname, "main(%d)", getpid());
	rdlink("/proc/self/ns/mnt");

	if (create_bpffs()) {
		fprintf(stderr, "Failed to prep BPFFSs\n");
		return;
	}

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, sockfds);
	if (err) {
		fprintf(stderr, "Failed to create UDS socket pair: %d\n", -errno);
		return;
	}

	pid1 = fork();
	if (pid1 == 0)
		exit(child1_main());
	pid2 = fork();
	if (pid2 == 0)
		exit(child2_main());

	printf("WAITING FOR CHILDREN...\n");

	err = waitpid(pid1, &status, 0);
	if (err < 0 && errno != ECHILD)
		fprintf(stderr, "waitpid1 failed\n");
	else if (WEXITSTATUS(status) != 0)
		fprintf(stderr, "child1 failed: %d\n", WEXITSTATUS(status));

	err = waitpid(pid2, &status, 0);
	if (err < 0 && errno != ECHILD)
		fprintf(stderr, "waitpid2 failed\n");
	else if (WEXITSTATUS(status) != 0)
		fprintf(stderr, "child2 failed: %d\n", WEXITSTATUS(status));

	printf("MAIN EXITING...\n");
}
