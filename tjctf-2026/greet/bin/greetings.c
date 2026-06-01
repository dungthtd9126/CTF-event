#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greetUser() {
	int uname_size;
	char uname[64];
	printf("Enter the size of your username: ");
	scanf("%d", &uname_size);
	getchar();
	uname_size += 2;
	printf("Enter username (start with @): ");
	fgets(uname, uname_size, stdin);
	if (*(char *) uname == '@') {
		printf("Greetings to you: %s!", uname);
	}
}

int main() {
	setbuf(stdout, NULL);
  	greetUser();
  	return 0;
}
