#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_ARGS 6
#define MAX_CMD_LEN 1024

int dangerous_cmd_blocked = 0;
char ***dangerous_commands = NULL;
int danger_count = 0;

void print_command(char **cmd_args, FILE *output) {
    fprintf(output, "(\"");
    for (int i = 0; cmd_args[i] != NULL; i++) {
        fprintf(output, "%s", cmd_args[i]);
        if (cmd_args[i + 1] != NULL) {
            fprintf(output, " ");
        }
    }
    fprintf(output, "\")");
}

void load_dangerous_commands(char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening dangerous commands file");
        exit(EXIT_FAILURE);
    }

    char line[MAX_CMD_LEN];
    while (fgets(line, MAX_CMD_LEN, file)) {
        line[strcspn(line, "\n")] = 0;

        dangerous_commands = realloc(dangerous_commands, (danger_count + 1) * sizeof(char **));
        if (!dangerous_commands) {
            perror("Memory allocation error");
            exit(EXIT_FAILURE);
        }

        dangerous_commands[danger_count] = malloc((MAX_ARGS + 1) * sizeof(char *));
        if (!dangerous_commands[danger_count]) {
            perror("Memory allocation error");
            exit(EXIT_FAILURE);
        }

        int arg_idx = 0;
        char *token = strtok(line, " ");
        while (token != NULL && arg_idx < MAX_ARGS) {
            dangerous_commands[danger_count][arg_idx++] = strdup(token);
            token = strtok(NULL, " ");
        }
        dangerous_commands[danger_count][arg_idx] = NULL;
        danger_count++;
    }

    fclose(file);
}

int validate_spaces(char *input) {
    int space_count = 0;
    for (size_t i = 0; i < strlen(input); i++) {
        if (input[i] == ' ') {
            space_count++;
            if (space_count > 1) {
                printf("ERR_SPACE\n");
                return 0;
            }
        } else {
            space_count = 0;
        }
    }
    return 1;
}

int check_dangerous_command(char **cmd_args, int *warning_cmd_count) {
    for (int i = 0; i < danger_count; i++) {
        int match_full = 1;
        int match_partial = 0;

        for (int j = 0; dangerous_commands[i][j] != NULL; j++) {
            if (cmd_args[j] == NULL || strcmp(cmd_args[j], dangerous_commands[i][j]) != 0) {
                match_full = 0;
            }
            if (j == 0 && strcmp(cmd_args[0], dangerous_commands[i][0]) == 0) {
                match_partial = 1;
            }
        }

        if (match_full) {
            printf("ERR: Dangerous command detected ");
            print_command(cmd_args, stdout);
            printf(". Execution prevented.\n");
            return -1;
        } else if (match_partial) {
            printf("WARNING: Command similar to dangerous command ");
            print_command(dangerous_commands[i], stdout);
            printf(". Proceed with caution.\n");
            (*warning_cmd_count)++;
            return 1;
        }
    }
    return 0;
}

char **parse_command(char *input) {
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }

    char *start = input;
    while (*start == ' ') start++;

    char *end = start + strlen(start) - 1;
    while (end > start && *end == ' ') {
        *end = '\0';
        end--;
    }

    if (strlen(start) == 0) {
        return NULL;
    }

    if (!validate_spaces(start)) {
        return NULL;
    }

    char **args = malloc((MAX_ARGS + 2) * sizeof(char *));
    if (!args) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    int arg_count = 0;
    char *token = strtok(start, " ");
    while (token != NULL) {
        if (arg_count >= MAX_ARGS) {
            printf("ERR_ARGS\n");
            free(args);
            return NULL;
        }
        args[arg_count++] = strdup(token);
        token = strtok(NULL, " ");
    }

    args[arg_count] = NULL;
    return args;
}

void execute_command(char **cmd_args, FILE *output_file, int *cmd_count, double *last_cmd_time, double *avg_time, double *min_time, double *max_time) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        return;
    } else if (pid == 0) {
        execvp(cmd_args[0], cmd_args);
        perror("Execution failed");
        exit(EXIT_FAILURE);
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS) {
            clock_gettime(CLOCK_MONOTONIC, &end);

            double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

            *last_cmd_time = elapsed_time;
            *cmd_count += 1;
            *avg_time = ((*avg_time) * (*cmd_count - 1) + elapsed_time) / (*cmd_count);
            if (*min_time == 0.0 || elapsed_time < *min_time) {
                *min_time = elapsed_time;
            }
            if (elapsed_time > *max_time) {
                *max_time = elapsed_time;
            }

            fprintf(output_file, "Command: ");
            for (int i = 0; cmd_args[i] != NULL; i++) {
                fprintf(output_file, "%s ", cmd_args[i]);
            }
            fprintf(output_file, ": %.5f sec\n", elapsed_time);
            fflush(output_file);
        } else {
            fprintf(output_file, "Command failed: ");
            for (int i = 0; cmd_args[i] != NULL; i++) {
                fprintf(output_file, "%s ", cmd_args[i]);
            }
            fprintf(output_file, "\n");
            fflush(output_file);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <dangerous_commands_file> <output_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    load_dangerous_commands(argv[1]);

    FILE *output_file = fopen(argv[2], "a");
    if (!output_file) {
        perror("Error opening output file");
        return EXIT_FAILURE;
    }

    char input[MAX_CMD_LEN];
    int cmd_count = 0;
    double last_cmd_time = 0.0, avg_time = 0.0, min_time = 0.0, max_time = 0.0;

    int warning_cmd_count = 0;


    while (1) {
        printf("#cmd:%d|#dangerous_cmd_blocked:%d|warning_cmd:%d|last_cmd_time:%.5f|avg_time:%.5f|min_time:%.5f|max_time:%.5f>> ",
               cmd_count, dangerous_cmd_blocked, warning_cmd_count, last_cmd_time, avg_time, min_time, max_time);

        if (!fgets(input, MAX_CMD_LEN, stdin)) {
            printf("\nExiting shell...\n");
            break;
        }

        if (input[0] == '\n') {
            continue;
        }

        char **args = parse_command(input);
        if (args == NULL) {
            continue;
        }

        if (strcmp(args[0], "done") == 0) {
            int illegal_cmd_count = dangerous_cmd_blocked + warning_cmd_count;
            printf(" %d\n", illegal_cmd_count);
            free(args);
            break;
        }

        int danger_check = check_dangerous_command(args, &warning_cmd_count);
        if (danger_check == -1) {
            dangerous_cmd_blocked++;
            free(args);
            continue;
        }

        execute_command(args, output_file, &cmd_count, &last_cmd_time, &avg_time, &min_time, &max_time);

        free(args);

    }
    fclose(output_file);
    return 0;
}