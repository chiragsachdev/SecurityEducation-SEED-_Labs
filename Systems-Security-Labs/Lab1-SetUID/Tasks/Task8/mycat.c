#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int ac, char *av[])
{
	char *v[3];
	char *command;

	if(ac < 2)
	{
		printf("Enter file name\n");
		return (1);
	}

	v[0] = "/bin/cat";
	v[1] = av[1];
	v[2] = NULL;
	command = malloc(strlen(v[0]) + strlen(v[1]) + 2);
	sprintf(command, "%s %s", v[0], v[1]);

//	system(command);
	execve(v[0], v, NULL);

	return (0);
}

