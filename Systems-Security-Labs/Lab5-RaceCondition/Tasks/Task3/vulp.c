/*vulp.c*/
#include <stdio.h>
#include <unistd.h>
#include <string.h>
int main()
{
	char *fn = "/tmp/XYZ";
	char buffer[60];
	FILE *fp;
	/*get user input*/
	scanf("%50s", buffer );

	uid_t uid = getuid();
	uid_t euid = geteuid(); 

	if(!access(fn, W_OK))
	{
		setuid(uid);
		fp = fopen(fn, "a+");
		fwrite("\n", sizeof(char), 1, fp);
		fwrite(buffer, sizeof(char), strlen(buffer), fp);
		fclose(fp);
		setuid(euid);
	}
	else 
		printf("No permission \n");

	return (0);
}

