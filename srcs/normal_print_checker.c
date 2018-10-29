/*
** EPITECH PROJECT, 2018
** PSU_strace_2017
** File description:
** normal_print_checker.c
*/

#include "strace.h"

int		check_first_display(int param, long long int reg)
{
	if (param == INT || param == SIZE_T)
		printf("%d", (int)reg);
	else {
		if (param == VOID_P && reg == 0)
			printf("NULL");
		else
			printf("0x%llx", reg);
	}
	return (0);
}

int		check_other_display(int param, long long int reg)
{
	if (param == INT || param == SIZE_T)
		printf(", %d", (int)reg);
	else {
		if ((param == VOID_P || param == OFF_T) && reg == 0)
			printf(", NULL");
		else
			printf(", 0x%llx", reg);
	}
	return (0);
}
