/*
** EPITECH PROJECT, 2018
** PSU_strace_2017
** File description:
** normal_display_syscalls.c
*/

#include "strace.h"

int		normal_display_only_regs(t_strace *st)
{
	if (st->sys->nb_params > 0) {
		check_first_display(st->sys->p1, st->reg.rdi);
		if (st->sys->id == 231)
			st->retval = conv_decimal(st, st->reg.rdi);
	}
	if (st->sys->nb_params > 1)
		check_other_display(st->sys->p2, st->reg.rsi);
	if (st->sys->nb_params > 2)
		check_other_display(st->sys->p3, st->reg.rdx);
	if (st->sys->nb_params > 3)
		check_other_display(st->sys->p4, st->reg.r8);
	if (st->sys->nb_params > 4)
		check_other_display(st->sys->p5, st->reg.r10);
	if (st->sys->nb_params > 5)
		check_other_display(st->sys->p6, st->reg.r9);
	return (0);
}

int		normal_is_adress(t_strace *st, int new_nb,
				long long int hex_val)
{
	if (st->disp_val == 1) {
		hex_val = neg_to_pos_number(st->reg.rax);
		printf(") = 0x%llx\n", hex_val);
	} else {
		new_nb = neg_to_pos_number(st->reg.rax);
		printf(") = %d\n", new_nb);
	}
	return (0);
}

int		normal_display_return_type(t_strace *st)
{
	int			new_nb = 0;
	long	long	int	hex_val = 0;

	if (st->sys->return_type == 0)
		printf(") = ?\n");
	else {
		if ((ptrace(PTRACE_SINGLESTEP, st->pid, 0, 0)) == -1)
			return (my_error("SINGLESTEP failed\n"));
		waitpid(st->pid, &st->wstatus, 0);
		if ((ptrace(PTRACE_GETREGS, st->pid, 0, &st->reg)) == -1)
			return (my_error("GETREGS failed\n"));
		normal_is_adress(st, new_nb, hex_val);
	}
	return (0);
}

int		normal_display_syscall(t_strace *st)
{
	st->disp_val = 0;
	st->sys = get_id_syscall(st->reg.rax);
	if (st->sys == NULL)
		return (1);
	if (st->sys->id == 12 || st->sys->id == 9)
		st->disp_val = 1;
	printf("%s(", st->sys->name);
	normal_display_only_regs(st);
	normal_display_return_type(st);
	return (0);
}
