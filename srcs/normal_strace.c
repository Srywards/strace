/*
** EPITECH PROJECT, 2018
** PSU_strace_2017
** File description:
** normal_strace.c
*/

#include "strace.h"

int	normal_call_parent(t_strace *st)
{
	int	i = 0;

	waitpid(st->pid, &st->wstatus, 0);
	while ((!WIFEXITED(st->wstatus))) {
		if ((ptrace(PTRACE_GETREGS, st->pid, 0, &st->reg)) == -1)
			return (my_error("GETREGS parent failed\n"));
		i = get_interrupt(st);
		if ((ptrace(PTRACE_SINGLESTEP, st->pid, 0, 0)) == -1)
			return (my_error("SINGLESTEP parent failed\n"));
		waitpid(st->pid, &st->wstatus, 0);
		if (i != 0)
			if (normal_display_syscall(st) == 1)
				return (my_error("Failed to find sys id\n"));
	}
	return (0);
}

int	normal_fork_strace(t_strace *st, char **ae)
{
	pid_t	pid = fork();

	if (pid == -1)
		return (my_error("pid failed\n"));
	st->pid = pid;
	if (st->pid == 0) {
		if ((ptrace(PTRACE_TRACEME, 0, 0, 0)) == -1)
			return (my_error("TRACEME child failed\n"));
		kill(getpid(), SIGSTOP);
		return (execve(st->cp_av[0], st->cp_av, ae));
	}
	else
		return (normal_call_parent(st));
	return (0);
}
