#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int service_initialized = 0;

void win(void) {
    FILE *fp;
    char flag_buf[128];

    puts("Master Builder status unlocked!");

    fp = fopen("flag.txt", "r");
    if (fp == NULL) {
        puts("flag.txt is missing. Ask an admin to deploy the real flag.");
        exit(1);
    }

    if (fgets(flag_buf, sizeof(flag_buf), fp) != NULL) {
        printf("%s", flag_buf);
    } else {
        puts("Failed to read flag.txt");
    }

    fclose(fp);
    exit(0);
}

static void banner(void) {
    puts("=== Bad Eraser Brick Workshop ===");
    puts("1) Preview a custom brick");
    puts("2) Use eraser tool");
    puts("3) Enter clutch-power diagnostics");
    puts("4) Close workshop");
    printf("> ");
}

static void preview_brick(void) {
    char model[48];

    printf("Model name: ");
    if (scanf("%47s", model) != 1) {
        exit(0);
    }
    printf("Built preview for %s with 8 studs.\n", model);
}

static void erase_station(void) {
    char note[96];

    printf("What should the eraser remove from your notes? ");
    if (scanf("%95s", note) != 1) {
        exit(0);
    }
    printf("Eraser scrubbed: %s\n", note);
}

static unsigned int clutch_score(unsigned int mold_id, unsigned int pigment_code) {
    return (((mold_id >> 2) & 0x43u) | pigment_code) + (pigment_code << 1);
}

static void diagnostics_bay(unsigned int mold_id, unsigned int pigment_code) {
    puts("Running clutch-power diagnostics...");
    if (clutch_score(mold_id, pigment_code) == 0x23ccdu) {
        win();
    }

    puts("Result: unstable clutch fit. Send batch back to sorting.");
    exit(0);
}

static void workshop_turn(void) {
    int choice;
    unsigned int mold_id;
    unsigned int pigment_code;

    banner();
    if (scanf("%d", &choice) != 1) {
        exit(0);
    }

    if (choice == 1) {
        preview_brick();
        return;
    }

    if (choice == 2) {
        erase_station();
        return;
    }

    if (choice == 4) {
        puts("Workshop closed. See you next build day.");
        exit(0);
    }

    if (choice != 3) {
        puts("Unknown action. Pick 1-4.");
        return;
    }

    if (!service_initialized) {
        puts("First-time calibration required.");
        puts("Enter mold id and pigment code.");
        if (scanf("%u %u", &mold_id, &pigment_code) != 2) {
            exit(0);
        }

        puts("Calibration saved. Re-enter diagnostics for clutch validation.");
        service_initialized = 1;
        return;
    }

    diagnostics_bay(mold_id, pigment_code);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    while (1) {
        workshop_turn();
    }

    return 0;
}
