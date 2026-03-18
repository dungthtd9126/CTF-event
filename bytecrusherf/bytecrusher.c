#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void admin_portal() {
    puts("Welcome dicegang admin!");
    FILE *f = fopen("flag.txt", "r");
    if (f) {
        char read;
        while ((read = fgetc(f)) != EOF) {
            putchar(read);
        }
        fclose(f);
    } else {
        puts("flag file not found");
    }
}

void crush_string(char *input, char *output, int rate, int output_max_len) {
    if (rate < 1) rate = 1;
    int out_idx = 0;
    for (int i = 0; input[i] != '\0' && out_idx < output_max_len - 1; i += rate) {
        output[out_idx++] = input[i];
    }
    output[out_idx] = '\0';
}

void free_trial() {
    char input_buf[32];
    char crushed[32];

    for (int i=0; i<16; i++) {
        printf("Trial %d/16:\n", i+1);
        printf("Enter a string to crush:\n");
        fgets(input_buf, sizeof(input_buf), stdin);


        printf("Enter crush rate:\n");
        int rate;
        scanf("%d", &rate);

        if (rate < 1) {
            printf("Invalid crush rate, using default of 1.\n");
            rate = 1;
        }

        printf("Enter output length:\n");
        int output_len;
        scanf("%d", &output_len);

        if (output_len > sizeof(crushed)) {
            printf("Output length too large, using max size.\n");
            output_len = sizeof(crushed);
        }

        // read until newline or eof
        int c;
        while ((c = getchar()) != '\n' && c != EOF);

        crush_string(input_buf, crushed, rate, output_len);


        printf("Crushed string:\n");
        puts(crushed);
    }
}

void get_feedback() {
    char buf[16];
    printf("Enter some text:\n");
    gets(buf);
    printf("Your feedback has been recorded and totally not thrown away.\n");
}


#define COMPILE_ADMIN_MODE 0

int main() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("Welcome to ByteCrusher, dicegang's new proprietary text crusher!\n");
    printf("We are happy to offer sixteen free trials of our premium service.\n");

    free_trial();
    get_feedback();
    
    printf("\nThank you for trying ByteCrusher! We hope you enjoyed it.\n");

    if (COMPILE_ADMIN_MODE) {
        admin_portal();
    }
    
    return 0;
}
