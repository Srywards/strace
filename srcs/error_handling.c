/*
** EPITECH PROJECT, 2018
** PSU_strace_2017
** File description:
** error_handling.c
*/

#include "strace.h"

int	my_error(char *str)
{
	fprintf(stderr, str);
	return (84);
}

int	str_isnum(char *str)
{
	int	i = 0;

	while (str[i])
		if (str[i] >= '0' && str[i] <= '9')
			i++;
		else
			return (84);
	return (0);
}

int	get_av(int ac, char **av, t_strace *st)
{
	int	i = 0;
	int	j = 0;

	st->cp_av = calloc((ac), (sizeof(char *)));
	if (st->cp_av == NULL)
		return (my_error("calloc failed\n"));
	while (av[++i] && av[i] && av[i][0] == '-');
	while (av[i])
		st->cp_av[j++] = av[i++];
	return (0);
}

int	check_flags(char **av, t_strace *st)
{
	if (strcmp(av[1], "-p") == 0) {
		if (str_isnum(av[2]) == 84)
			return (my_error("You must add a correct PID (0-9)\n"));
		st->launch = 2;
		st->tp = atoi(av[2]);
	}
	if (strcmp(av[1], "-s") == 0)
		st->launch = 1;
	return (0);
}

int	error_handling(int ac, char **av, t_strace *st)
{
	if (ac < 2 || ac > 3)
		return (error_usage(st));
	if (ac == 2) {
		if ((strcmp(av[1], "-s") == 0) || (strcmp(av[1], "-p") == 0))
			return (my_error("You can't strace a flag\n"));
		get_av(ac, av, st);
	}
	if (ac == 3) {
		if ((strcmp(av[1], "-s") != 0) && (strcmp(av[1], "-p") != 0))
			return (my_error("You can't add multiple flags\n"));
		if (check_flags(av, st) == 84)
			return (84);
		get_av(ac, av, st);
	}
	return (0);
}
