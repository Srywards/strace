##
## EPITECH PROJECT, 2018
## PSU_strace_2017
## File description:
## Makefile
##

NAME    =      	strace

SRC     =	srcs/strace.c			\
		srcs/get_syscall.c		\
		srcs/detect_interrupt.c		\
		srcs/display_syscalls.c		\
		srcs/error_handling.c		\
		srcs/usage.c			\
		srcs/free_struct.c		\
		srcs/hexa_strace.c		\
		srcs/pid.c			\
		srcs/normal_strace.c		\
		srcs/normal_display_syscalls.c	\
		srcs/normal_print_checker.c

OBJ     =       $(SRC:.c=.o)

CC      =       gcc

CFLAGS  =       -I./include -W -Werror -Wall -Wextra -g

RM      =       rm -rf

all:    $(NAME)

$(NAME):$(OBJ)
	$(CC) -o $(NAME) $(OBJ) $(CFLAGS)

clean:
	$(RM) $(OBJ)

fclean: clean
	$(RM) $(NAME)

re:     fclean all
