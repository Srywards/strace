/*
** EPITECH PROJECT, 2018
** PSU_strace_2017
** File description:
** strace.c
*/

#include "strace.h"

int     init_struct(t_strace **val)
{
	t_strace	*st;

	st = malloc(sizeof(*st));
	if (st == NULL)
		return (84);
	st->cp_av = NULL;
	st->pid = 0;
	st->wstatus = 0;
	st->tp = 0;
	st->retval = 0;
	st->launch = 0;
	st->disp_val = 0;
	*val = st;
	return (0);
}

int	loading_strace(t_strace *st, char **ae)
{
	if (st->launch == 0)
		return (fork_child_and_parent(st, ae));
	if (st->launch == 1)
		return (normal_fork_strace(st, ae));
	if (st->launch == 2) {
		if (attach_pid(st) == 84)
			return (84);
		if (normal_fork_strace(st, ae) == 84)
			return (84);
		if (detach_pid(st) == 84)
			return (84);
	}
	return (0);
}

int	main(int ac , char **av, char **ae)
{
	t_strace	*st = NULL;

	if (init_struct(&st) == 84)
		return (xfree(st));
	if (ac == 2 && strcmp(av[1], "--help") == 0)
		return (usage(st));
	if (error_handling(ac, av, st) == 84)
		return (xfree(st));
	if (loading_strace(st, ae) == 84)
		return (xfree(st));
	printf("+++ exited with %d +++\n", st->retval);
	clear_end(st);
	return (st->retval);
}
