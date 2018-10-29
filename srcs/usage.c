/*
** EPITECH PROJECT, 2018
** PSU_strace_2017
** File description:
** usage.c
*/

#include "strace.h"

int	usage(t_strace *st)
{
	printf("USAGE: ./strace [-s] [-p <pid>|<command>]\n");
	free(st);
	exit(0);
}

int	error_usage(t_strace *st)
{
	my_error("USAGE: ./strace [-s] [-p <pid>|<command>]\n");
	free(st);
	exit(1);
}
