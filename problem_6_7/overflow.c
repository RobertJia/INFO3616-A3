#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/*
Note: this must be compiled with the flags -fno-stack-protector -g
*/

unsigned int getClearance(char* password) {
    char pwd[128]; // ultra-long passwords are super-secure
    unsigned int level = 0; // default level

    strcpy(pwd, password);
    
    int checkPwd = strcmp(pwd, "bertie4ever");

    if ( checkPwd == 0 ) {
	printf("Authentication correct.\n");
        level = 100;
    }
    return level;
}


void decryptSecret(void) {
    char x[30] = "cPVGSCzJMaMRPYKxJWmA^[@e]RPSGO";
    char y[30] = "055567396293328982443696333842";
    char z[30];
    for (int i = 0; i < 30; i++) {
        z[i] = x[i] ^ y[i];
        printf("%c", z[i]);
    }
    printf("\n");
    return;
}


// Function never called in main - therefore inaccessible
void superSecret(void) {
    printf("Welcome to the Centre for National Operations in Blatant Reductionist AI Nonsense.");
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
    system("/bin/sh -i");
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
	printf("Enter your password as argument to view the SECRET!!!1!!!\n");
	printf("./overflow PASSWORD\n");
	return -1;
    }
    unsigned int clearance = getClearance(argv[1]);
    if (clearance >= 100) {
        printf("%s has clearance level: %d. Access granted...\n", argv[1], clearance);
        decryptSecret();
    } else {
        printf("%s: Access Denied. Need clearance level over 100.\n", argv[1]);
    }
    return 0;
};
