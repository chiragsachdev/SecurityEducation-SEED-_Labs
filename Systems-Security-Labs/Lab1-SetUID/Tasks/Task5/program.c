#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern char **environ;

int main()
{
	int i;

	i = -1;
	while (environ[++i] != NULL)
		printf("%s\n",environ[i]);

	return (0);
}

