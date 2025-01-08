#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctype.h>

#define MAX_PATH 260
#define PROGRESS_BAR_WIDTH 50
#define XOR_KEY 0xAA

// Function Prototypes
void init_ui();
void display_menu();
void browse_directory(char *selected_file);
void generate_shellcode(const char *input_file, const char *output_format);
void xor_encrypt(unsigned char *data, size_t size);
void display_progress_bar(const char *message, int percentage);
void show_error(const char *error_message);
void show_success(const char *success_message);
void show_help();

// Colors for ncurses UI
enum { COLOR_HEADER = 1, COLOR_MENU = 2, COLOR_FOOTER = 3, COLOR_ERROR = 4, COLOR_SUCCESS = 5 };

void init_ui() {
    initscr();
    start_color();
    use_default_colors();
    init_pair(COLOR_HEADER, COLOR_CYAN, -1);
    init_pair(COLOR_MENU, COLOR_GREEN, -1);
    init_pair(COLOR_FOOTER, COLOR_YELLOW, -1);
    init_pair(COLOR_ERROR, COLOR_RED, -1);
    init_pair(COLOR_SUCCESS, COLOR_GREEN, -1);
    curs_set(0);
    noecho();
    keypad(stdscr, TRUE);
}

void show_error(const char *error_message) {
    attron(COLOR_PAIR(COLOR_ERROR));
    mvprintw(LINES / 2, (COLS - strlen(error_message)) / 2, "%s", error_message);
    attroff(COLOR_PAIR(COLOR_ERROR));
    getch();
}

void show_success(const char *success_message) {
    attron(COLOR_PAIR(COLOR_SUCCESS));
    mvprintw(LINES / 2, (COLS - strlen(success_message)) / 2, "%s", success_message);
    attroff(COLOR_PAIR(COLOR_SUCCESS));
    getch();
}

void show_help() {
    clear();
    mvprintw(0, 0, "Help - EXE to Shellcode Converter");
    mvprintw(2, 0, "1. Use the menu to navigate through options.");
    mvprintw(3, 0, "2. Select 'Browse File' to choose an executable.");
    mvprintw(4, 0, "3. Choose the desired output format to generate shellcode.");
    mvprintw(5, 0, "4. Options include Byte Array and Hex.");
    mvprintw(6, 0, "5. Use arrow keys to navigate and Enter to select.");
    mvprintw(7, 0, "6. XOR encryption is applied for obfuscation.");
    mvprintw(8, 0, "7. Logs are created for each session in the current directory.");
    mvprintw(LINES - 2, 0, "Press any key to return to the main menu.");
    getch();
}

void display_menu() {
    char *menu_items[] = {
        "Browse File",
        "Generate Byte Array",
        "Generate Hex Format",
        "Help",
        "Exit"
    };
    int choice = 0;
    int highlight = 0;
    int menu_size = sizeof(menu_items) / sizeof(menu_items[0]);

    while (1) {
        clear();

        // Header
        attron(COLOR_PAIR(COLOR_HEADER));
        mvprintw(0, 0, "EXE to Shellcode Converter");
        attroff(COLOR_PAIR(COLOR_HEADER));

        // Menu
        for (int i = 0; i < menu_size; i++) {
            if (i == highlight) {
                attron(A_REVERSE);
            }
            mvprintw(i + 2, 2, menu_items[i]);
            if (i == highlight) {
                attroff(A_REVERSE);
            }
        }

        // Footer
        attron(COLOR_PAIR(COLOR_FOOTER));
        mvprintw(LINES - 2, 0, "Use arrow keys to navigate, Enter to select");
        attroff(COLOR_PAIR(COLOR_FOOTER));

        choice = getch();
        switch (choice) {
            case KEY_UP:
                highlight = (highlight == 0) ? menu_size - 1 : highlight - 1;
                break;
            case KEY_DOWN:
                highlight = (highlight == menu_size - 1) ? 0 : highlight + 1;
                break;
            case 10: // Enter key
                if (highlight == 0) {
                    char selected_file[MAX_PATH] = "";
                    browse_directory(selected_file);
                } else if (highlight == 1 || highlight == 2) {
                    char input_file[MAX_PATH] = "";
                    char *output_formats[] = {"Byte Array", "Hex"};
                    browse_directory(input_file);
                    if (strlen(input_file) > 0) {
                        generate_shellcode(input_file, output_formats[highlight - 1]);
                    }
                } else if (highlight == 3) {
                    show_help();
                } else if (highlight == 4) {
                    endwin();
                    exit(0);
                }
                break;
        }
    }
}

void browse_directory(char *selected_file) {
    char cwd[MAX_PATH];
    DIR *dir;
    struct dirent *entry;
    int highlight = 0;
    int choice;

    getcwd(cwd, sizeof(cwd));
    while (1) {
        clear();

        dir = opendir(cwd);
        if (!dir) {
            show_error("Error: Unable to open directory");
            return;
        }

        mvprintw(0, 0, "Current Directory: %s", cwd);

        int file_count = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (file_count == highlight) {
                attron(A_REVERSE);
            }
            mvprintw(file_count + 1, 2, "%s", entry->d_name);
            if (file_count == highlight) {
                attroff(A_REVERSE);
            }
            file_count++;
        }
        closedir(dir);

        choice = getch();
        if (choice == KEY_UP) {
            highlight = (highlight == 0) ? file_count - 1 : highlight - 1;
        } else if (choice == KEY_DOWN) {
            highlight = (highlight == file_count - 1) ? 0 : highlight + 1;
        } else if (choice == 10) { // Enter key
            dir = opendir(cwd);
            for (int i = 0; i <= highlight; i++) {
                entry = readdir(dir);
            }
            closedir(dir);
            if (entry) {
                if (entry->d_type == DT_DIR) {
                    chdir(entry->d_name);
                    getcwd(cwd, sizeof(cwd));
                } else {
                    snprintf(selected_file, MAX_PATH, "%s/%s", cwd, entry->d_name);
                    return;
                }
            }
        } else if (choice == 27) { // Escape key
            return;
        }
    }
}

void xor_encrypt(unsigned char *data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        data[i] ^= XOR_KEY;
    }
}

void generate_shellcode(const char *input_file, const char *output_format) {
    FILE *file = fopen(input_file, "rb");
    if (!file) {
        show_error("Error: Unable to open file");
        return;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    unsigned char *buffer = malloc(file_size);
    if (!buffer) {
        fclose(file);
        show_error("Error: Memory allocation failed");
        return;
    }

    fread(buffer, 1, file_size, file);
    fclose(file);

    xor_encrypt(buffer, file_size);

    clear();
    mvprintw(0, 0, "Generating %s shellcode...", output_format);

    char output_file[MAX_PATH];
    snprintf(output_file, MAX_PATH, "%s_shellcode.txt", input_file);
    FILE *output = fopen(output_file, "w");
    if (!output) {
        free(buffer);
        show_error("Error: Unable to create output file");
        return;
    }

    if (strcmp(output_format, "Byte Array") == 0) {
        fprintf(output, "unsigned char shellcode[] = {\n");
        for (long i = 0; i < file_size; i++) {
            fprintf(output, "0x%02x, ", buffer[i]);
            if ((i + 1) % 16 == 0) {
                fprintf(output, "\n");
            }
        }
        fprintf(output, "\n};");
    } else if (strcmp(output_format, "Hex") == 0) {
        for (long i = 0; i < file_size; i++) {
            fprintf(output, "%02x", buffer[i]);
        }
    }

    fclose(output);
    free(buffer);

    show_success("Shellcode generated successfully!");
}

int main() {
    init_ui();
    display_menu();
    return 0;
}
