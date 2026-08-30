#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* The recovery routine is deliberately not referenced by main(). */
static void recover_signal(void) {
    char flag[128] = {0};
    const char *flag_path = getenv("FLAG_PATH");
    if (flag_path == NULL) {
        flag_path = "/app/flag";
    }
    FILE *fp = fopen(flag_path, "r");

    if (fp == NULL) {
        puts("recovery storage unavailable");
        return;
    }

    if (fgets(flag, sizeof(flag), fp) != NULL) {
        printf("Recovered signal: %s", flag);
    }
    fclose(fp);
}

static void receive_packet(void) {
    char packet[64];

    puts("=== relay packet receiver ===");
    puts("The relay is listening for one diagnostic packet.");
    printf("packet> ");
    fflush(stdout);

    /* The relay firmware trusts the packet length supplied by its peer. */
    ssize_t length = read(STDIN_FILENO, packet, 256);
    if (length > 0) {
        puts("packet stored");
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    receive_packet();
    return 0;
}
