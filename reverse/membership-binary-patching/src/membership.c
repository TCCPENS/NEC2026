#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum membership_tier {
    NON_VIP = 0,
    VIP = 1
};

typedef struct {
    char username[32];
    int tier;
    uint32_t points;
} User;

static uint32_t stir(uint32_t value) {
    value ^= value >> 16;
    value *= 0x7feb352dU;
    value ^= value >> 15;
    value *= 0x846ca68bU;
    return value ^ (value >> 16);
}

/* Kept out-of-line so the membership state has a stable patchable instruction. */
__attribute__((noinline, used))
static void seed_account(User *user) {
    user->tier = NON_VIP;
    user->points = 100U;
}

static void prepare_account(User *user) {
    memset(user, 0, sizeof(*user));
    memcpy(user->username, "guest", 6);
    seed_account(user);
}

static int is_vip(const User *user) {
    return user->tier == VIP;
}

static void make_badge(const User *user, uint8_t badge[16]) {
    uint32_t state = 0x51a7c3e9U;

    for (size_t i = 0; i < sizeof(user->username); ++i) {
        state = stir(state ^ (uint8_t)user->username[i] ^ (uint32_t)(i * 0x31U));
    }
    state = stir(state ^ ((uint32_t)user->tier * 0x9e3779b9U));
    state = stir(state ^ user->points);

    for (size_t i = 0; i < 16; ++i) {
        state = stir(state + (uint32_t)(i * 0x45d9f3bU));
        badge[i] = (uint8_t)(state >> ((i & 3U) * 8U));
    }
}

static int verify_badge(const User *user, const uint8_t badge[16]) {
    uint8_t expected[16];
    make_badge(user, expected);
    return is_vip(user) && memcmp(expected, badge, sizeof(expected)) == 0;
}

static void derive_reward_key(const User *user, const uint8_t badge[16], uint8_t key[16]) {
    uint32_t state = 0x243f6a88U ^ (uint32_t)user->tier;

    for (size_t i = 0; i < 16; ++i) {
        state = stir(state ^ badge[i] ^ (uint8_t)user->username[(i * 7U) & 31U]);
        key[i] = (uint8_t)(state >> ((i & 3U) * 8U));
    }
}

/* This is ciphertext only; the reward text is never present in the ELF. */
static const uint8_t encrypted_reward[] = {
    0xad, 0xc4, 0x00, 0x7e, 0xda, 0x66, 0x2d, 0x19,
    0x2f, 0xec, 0xf2, 0xed, 0x93, 0xd9, 0x0d, 0x53,
    0x91, 0xde, 0x34, 0x31, 0xd3, 0x0d, 0x2d, 0x4a,
    0x18, 0xab, 0xad, 0xfa, 0xb1
};

static void unlock_reward(const User *user, const uint8_t badge[16]) {
    uint8_t key[16];
    uint8_t reward[sizeof(encrypted_reward)];

    derive_reward_key(user, badge, key);
    for (size_t i = 0; i < sizeof(encrypted_reward); ++i) {
        reward[i] = encrypted_reward[i] ^ key[i & 15U];
    }
    printf("[+] Exclusive reward unlocked.\n\n%.*s\n", (int)sizeof(reward), reward);
}

static void show_profile(const User *user) {
    printf("\nUsername       : %s\n", user->username);
    printf("Account Status : %s\n", is_vip(user) ? "VIP" : "NON-VIP");
    printf("Points         : %u\n", user->points);
}

static void vip_lounge(const User *user) {
    uint8_t badge[16];

    if (!is_vip(user)) {
        puts("\n[!] VIP membership required.");
        return;
    }

    puts("\n[+] VIP Lounge access granted.");
    make_badge(user, badge);
    if (!verify_badge(user, badge)) {
        puts("[-] Invalid VIP badge.");
        puts("[-] Reward unavailable.");
        return;
    }

    puts("[+] VIP badge verified.");
    unlock_reward(user, badge);
}

static void print_menu(void) {
    puts("\n╔════════════════════════════════╗");
    puts("          NEC MEMBERSHIP");
    puts("╚════════════════════════════════╝");
    puts("\n[1] View Profile");
    puts("[2] Regular Reward");
    puts("[3] VIP Lounge");
    puts("[4] Exit");
    printf("\n> ");
}

int main(void) {
    User user;
    int choice;

    prepare_account(&user);
    show_profile(&user);

    for (;;) {
        print_menu();
        if (scanf("%d", &choice) != 1) {
            return EXIT_FAILURE;
        }

        switch (choice) {
            case 1:
                show_profile(&user);
                break;
            case 2:
                puts("\n[+] Regular reward: 10 bonus points.");
                break;
            case 3:
                vip_lounge(&user);
                break;
            case 4:
                puts("\nGoodbye.");
                return EXIT_SUCCESS;
            default:
                puts("\n[!] Unknown selection.");
                break;
        }
    }
}
