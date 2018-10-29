/*
** EPITECH PROJECT, 2018
** PSU_strace_2017
** File description:
** strace.h
*/

#ifndef	STRACE_H
#define	STRACE_H
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include "syscall.h"

typedef struct	user_regs_struct	t_pt_reg;

typedef struct	s_strace
{
	pid_t			tp;
	int			launch;
	char			**cp_av;
	pid_t			pid;
	int			wstatus;
	int			retval;
	int			disp_val;
	t_syscall	const	*sys;
	t_pt_reg		reg;
}		t_strace;

int	main(int, char **, char **);
int	my_error(char *);
int	str_isnum(char *);
int	get_av(int, char **, t_strace *);
int	check_flags(char **, t_strace *);
int	error_handling(int, char **, t_strace *);
int	usage(t_strace *);
int	error_usage(t_strace *);
int	xfree(t_strace *);
int	clear_end(t_strace *);
int	fork_child_and_parent(t_strace *, char **);
int	call_parent(t_strace *);
t_syscall	const	*get_id_syscall(int);
long long int	neg_to_pos_number(long long int);
int	display_only_regs(t_strace *);
int	display_return_type(t_strace *);
int	display_syscall(t_strace *);
int	get_interrupt(t_strace *);
int	conv_decimal(t_strace *, long long int);
int	attach_pid(t_strace *);
int	detach_pid(t_strace *);
int	normal_fork_strace(t_strace *, char **);
int	normal_call_parent(t_strace *);
int	normal_display_syscall(t_strace *);
int	normal_display_only_regs(t_strace *);
int	normal_display_return_type(t_strace *);
int	normal_is_adress(t_strace *, int, long long int);
int	check_first_display(int, long long int);
int	check_other_display(int, long long int);

#endif	/* !STRACE_H */
