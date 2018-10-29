/*
** EPITECH PROJECT, 2018
** pid
** File description:
** pid
*/

#include "strace.h"

int	attach_pid(t_strace *st)
{
	if ((ptrace(PTRACE_ATTACH, st->tp, NULL, NULL)) < 0) {
		fprintf(stderr, "strace: attach: ptrace(PTRACE_SEIZE, %d): ",
			st->tp);
		perror("");
		return (84);
	} else {
		fprintf(stdout, "strace: Process %d attached\n",
			st->tp);
	}
	printf("+ Waiting for process...\n");
	waitpid(st->tp, &st->wstatus, 0);
	st->pid = st->tp;
	return (0);
}

int	detach_pid(t_strace *st)
{
	if ((ptrace(PTRACE_DETACH, st->tp, NULL, NULL)) < 0) {
		fprintf(stderr, "strace: Process %d detached\n", st->tp);
		perror("");
		return (84);
	} else {
		fprintf(stdout, "strace: Process %d detached\n", st->tp);
		fprintf(stdout, "<detached ...>\n");
		return (0);
	}
	return (0);
}
