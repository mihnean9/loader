/*
 * Loader Implementation
 *
 * 2018, Operating Systems
 */
#include <signal.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "exec_parser.h"

static so_exec_t *exec;
static struct sigaction old_action;
static int fd;
static int pageSize;

/* return index of segment containing addr */
static int getSegmentIndex(uintptr_t addr)
{
	int i;
	uintptr_t seg_addr;

	for (i = 0; i < exec->segments_no; i++) {
		seg_addr = exec->segments[i].vaddr;
		if (seg_addr <= addr && addr < seg_addr +
				exec->segments[i].mem_size)
			return i;
	}

	return -1;
}

/* return index of page inside segment */
static int getPageIndex(int seg_idx, uintptr_t addr)
{
	/* make the addr relative to the start of segmet */
	addr -= exec->segments[seg_idx].vaddr;
	return addr / pageSize;
}

/* fill memory between seg.file_size and seg.mem_size with 0s */
static void setZero(void)
{
	int i, zero_size;
	void *zero_start;

	for (i = 0; i < exec->segments_no; i++) {
		zero_start = (void *)exec->segments[i].vaddr +
					exec->segments[i].file_size;
		zero_size = exec->segments[i].mem_size -
					exec->segments[i].file_size;
		memset(zero_start, 0, zero_size);
	}
}

/* custom SIGSEGV handler */
static void segv_handler(int signal_number, siginfo_t *info, void *context)
{
	uintptr_t addr;
	int page_idx, seg_idx, page_offset, offset, prot, flags;
	char *start;

	if (signal_number != SIGSEGV)
		return;

	addr = (uintptr_t)info->si_addr;
	seg_idx = getSegmentIndex(addr);

	/* check for access w/o permission or unknown segment */
	if (info->si_code == SEGV_ACCERR || seg_idx == -1) {
		old_action.sa_sigaction(signal_number, info, context);
		return;
	}

	page_idx = getPageIndex(seg_idx, addr);
	page_offset = page_idx * pageSize;
	start = (char *)(exec->segments[seg_idx].vaddr + page_offset);
	offset = exec->segments[seg_idx].offset + page_offset;

	prot = exec->segments[seg_idx].perm;

	flags = MAP_FIXED | MAP_PRIVATE;

	/* check if segment has size in file */
	if (exec->segments[seg_idx].file_size == 0)
		flags = MAP_ANONYMOUS | MAP_PRIVATE;

	/* map page to memory; exit if failed */
	if (start != mmap(start, pageSize, prot, flags, fd, offset))
		exit(1);
}

/* set custom handler for SIGSEGV */
int so_init_loader(void)
{
	struct sigaction action;

	action.sa_sigaction = segv_handler;
	sigemptyset(&action.sa_mask);
	sigaddset(&action.sa_mask, SIGSEGV);
	action.sa_flags = SA_SIGINFO;

	return sigaction(SIGSEGV, &action, &old_action);
}

/* execute file */
int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return fd;

	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	pageSize = getpagesize();

	setZero();

	so_start_exec(exec, argv);

	close(fd);

	return 0;
}
