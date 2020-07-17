#include <stdio.h>
int main()
{
	char *kernel_data_addr = (char *)0xf9fa2000;
	char kernel_data = *kernel_data_addr;
	printf("I have reached here");

	return (0);
}
