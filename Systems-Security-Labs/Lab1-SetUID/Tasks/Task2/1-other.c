#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

extern char	**environ;

void	printenv()
{
	int i;

	i = -1;
	while (environ[++i] != NULL)
		printf("%s\n",environ[i]);
}

int	main()
{
	pid_t childPid;
	switch(childPid = fork())
	{
		case 0:
		printenv();
		exit (0);
		default:
		printenv();
		exit (0);
	}
	return (0);
}
