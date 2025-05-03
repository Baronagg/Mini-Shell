#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>

#define MAX_ARGS 6
#define MAX_CMD_LEN 1024
#define MAX_BG_PROCESSES 100

pid_t bg_pids[MAX_BG_PROCESSES];
int bg_count = 0;

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

void free_command_args(char **args) {
    if (args == NULL) {
        return;
    }
    for (int i = 0; args[i] != NULL; i++) {
        free(args[i]);
    }
    free(args);
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
    if (!cmd_args || !cmd_args[0]) {
        return 0;
    }

    for (int i = 0; i < danger_count; i++) {
        int match_full = 1;
        int match_partial = 0;

        if (strcmp(cmd_args[0], dangerous_commands[i][0]) == 0) {
            match_partial = 1;
        }

        for (int j = 0; dangerous_commands[i][j] != NULL; j++) {
            if (cmd_args[j] == NULL) {
                match_full = 0;
                break;
            }

            if (strcmp(cmd_args[j], dangerous_commands[i][j]) != 0) {
                match_full = 0;
                break;
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

char **parse_command(char *input, int *run_in_background) {
    *run_in_background = 0;
    size_t len = strlen(input);
    if (len > 0 && input[len - 1] == '\n') {
        input[len - 1] = '\0';
    }

    // Skip leading whitespace
    char *start = input;
    while (*start == ' ' || *start == '\t') start++;

    // Skip trailing whitespace
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\t')) {
        *end = '\0';
        end--;
    }

    // Return NULL for empty/whitespace-only commands
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
            free_command_args(args);
            return NULL;
        }
        args[arg_count++] = strdup(token);
        token = strtok(NULL, " ");
    }

    args[arg_count] = NULL;

    if (arg_count > 0 && strcmp(args[arg_count - 1], "&") == 0) {
        *run_in_background = 1;
        free(args[arg_count - 1]);
        args[arg_count - 1] = NULL;
    }

    return args;
}

int handle_stderr_redirection_input(char *input) {
    char *redir_pos = strstr(input, "2>");
    if (!redir_pos) return -1;

    *redir_pos = '\0';
    redir_pos += 2;
    while (*redir_pos == ' ') redir_pos++;

    char *filename = redir_pos;
    while (*redir_pos && *redir_pos != ' ') redir_pos++;
    *redir_pos = '\0';

    int fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        perror("Failed to open stderr file");
        return -1;
    }
    return fd;
}

int handle_stderr_redirection_args(char **args, int *stderr_fd) {
    for (int i = 0; args[i]; i++) {
        if (strcmp(args[i], "2>") == 0 && args[i + 1]) {
            *stderr_fd = open(args[i + 1], O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (*stderr_fd < 0) {
                perror("Failed to open stderr file");
                return -1;
            }

            free(args[i]);
            free(args[i + 1]);

            int j;
            for (j = i; args[j + 2]; j++) {
                args[j] = args[j + 2];
            }
            args[j] = NULL;
            return 0;
        }
    }
    return -1;
}

void update_statistics(double elapsed_time, int *cmd_count, double *last_cmd_time,
                      double *avg_time, double *min_time, double *max_time, int success) {
    if (!success) return;

    (*cmd_count)++;
    *last_cmd_time = elapsed_time;

    if (*cmd_count == 1) {
        *avg_time = elapsed_time;
        *min_time = elapsed_time;
        *max_time = elapsed_time;
    } else {
        *avg_time = ((*avg_time) * (*cmd_count - 1) + elapsed_time) / (*cmd_count);
        if (elapsed_time < *min_time) {
            *min_time = elapsed_time;
        }
        if (elapsed_time > *max_time) {
            *max_time = elapsed_time;
        }
    }
}

void execute_command(char **cmd_args, int run_in_background, FILE *output_file,
                    int *cmd_count, double *last_cmd_time, double *avg_time,
                    double *min_time, double *max_time) {
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int stderr_fd = -1;
    if (handle_stderr_redirection_args(cmd_args, &stderr_fd) == -1 && stderr_fd != -1) {
        close(stderr_fd);
        stderr_fd = -1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("Fork failed");
        if (stderr_fd != -1) close(stderr_fd);
        return;
    } else if (pid == 0) {
        if (stderr_fd != -1) {
            dup2(stderr_fd, STDERR_FILENO);
            close(stderr_fd);
        }
        execvp(cmd_args[0], cmd_args);
        perror("Execution failed");
        _exit(EXIT_FAILURE);
    } else {
        if (stderr_fd != -1) close(stderr_fd);

        if (run_in_background) {
            if (bg_count < MAX_BG_PROCESSES) {
                bg_pids[bg_count++] = pid;
            }
            printf("Started background process with PID %d\n", pid);
            fflush(stdout);

            clock_gettime(CLOCK_MONOTONIC, &end);
            double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            update_statistics(elapsed_time, cmd_count, last_cmd_time, avg_time, min_time, max_time, 1);
            return;
        }

        int status;
        if (waitpid(pid, &status, 0) == -1) {
            if (errno != ECHILD) {
                perror("waitpid failed");
            }
            return;
        }

        clock_gettime(CLOCK_MONOTONIC, &end);
        double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

        int success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
        update_statistics(elapsed_time, cmd_count, last_cmd_time, avg_time, min_time, max_time, success);

        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) == 0) {
                printf("Process exited successfully\n");
            } else {
                printf("Process exited with error code %d\n", WEXITSTATUS(status));
            }
        } else if (WIFSIGNALED(status)) {
            printf("Process terminated by signal %d\n", WTERMSIG(status));
        }

        fprintf(output_file, "Command: ");
        for (int i = 0; cmd_args[i] != NULL; i++) {
            fprintf(output_file, "%s ", cmd_args[i]);
        }
        fprintf(output_file, ": %.5f sec\n", elapsed_time);
        fflush(output_file);
    }
}

void sigchld_handler(int signum) {
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (int i = 0; i < bg_count; i++) {
            if (bg_pids[i] == pid) {
                if (WIFEXITED(status)) {
                    printf("Background process %d exited with status %d\n",
                           pid, WEXITSTATUS(status));
                } else if (WIFSIGNALED(status)) {
                    printf("Background process %d killed by signal %d\n",
                           pid, WTERMSIG(status));
                }

                for (int j = i; j < bg_count - 1; j++) {
                    bg_pids[j] = bg_pids[j + 1];
                }
                bg_count--;
                break;
            }
        }
    }
}

void handle_pipe(char *input, FILE *output_file, int *cmd_count, double *last_cmd_time,
                double *avg_time, double *min_time, double *max_time) {
    int stderr_fd = handle_stderr_redirection_input(input);
    char *pipe_pos = strchr(input, '|');
    if (!pipe_pos) {
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    *pipe_pos = '\0';
    char *left = input;
    char *right = pipe_pos + 1;

    while (*left == ' ') left++;
    while (*right == ' ') right++;
    while (strlen(left) > 0 && left[strlen(left) - 1] == ' ') left[strlen(left) - 1] = '\0';
    while (strlen(right) > 0 && right[strlen(right) - 1] == ' ') right[strlen(right) - 1] = '\0';

    int dummy_bg1 = 0, dummy_bg2 = 0;
    char **left_args = parse_command(left, &dummy_bg1);
    char **right_args = parse_command(right, &dummy_bg2);

    if (!left_args || !right_args) {
        printf("Error: Invalid commands in pipe.\n");
        if (left_args) free_command_args(left_args);
        if (right_args) free_command_args(right_args);
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("Error creating pipe");
        free_command_args(left_args);
        free_command_args(right_args);
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    pid_t left_pid = fork();
    if (left_pid == -1) {
        perror("Error creating left process");
        close(pipefd[0]);
        close(pipefd[1]);
        free_command_args(left_args);
        free_command_args(right_args);
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    if (left_pid == 0) {
        if (stderr_fd != -1) {
            dup2(stderr_fd, STDERR_FILENO);
            close(stderr_fd);
        }
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execvp(left_args[0], left_args);
        perror("Execution failed for left command");
        _exit(EXIT_FAILURE);
    }

    pid_t right_pid = fork();
    if (right_pid == -1) {
        perror("Error creating right process");
        close(pipefd[0]);
        close(pipefd[1]);
        free_command_args(left_args);
        free_command_args(right_args);
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    if (right_pid == 0) {
        if (stderr_fd != -1) {
            dup2(stderr_fd, STDERR_FILENO);
            close(stderr_fd);
        }
        close(pipefd[1]);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
        execvp(right_args[0], right_args);
        perror("Execution failed for right command");
        _exit(EXIT_FAILURE);
    }

    if (stderr_fd != -1) close(stderr_fd);
    close(pipefd[0]);
    close(pipefd[1]);

    int left_status, right_status;
    waitpid(left_pid, &left_status, 0);
    waitpid(right_pid, &right_status, 0);

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    int success = WIFEXITED(left_status) && WEXITSTATUS(left_status) == 0 &&
                 WIFEXITED(right_status) && WEXITSTATUS(right_status) == 0;
    update_statistics(elapsed_time, cmd_count, last_cmd_time, avg_time, min_time, max_time, success);

    fprintf(output_file, "Pipe: \"%s\" | \"%s\" : %.5f sec\n", left, right, elapsed_time);
    fflush(output_file);

    if (!success) {
        if (WIFEXITED(left_status) && WEXITSTATUS(left_status) != 0) {
            printf("Left command failed with exit code %d\n", WEXITSTATUS(left_status));
        } else if (WIFSIGNALED(left_status)) {
            printf("Left command terminated by signal %d\n", WTERMSIG(left_status));
        }

        if (WIFEXITED(right_status) && WEXITSTATUS(right_status) != 0) {
            printf("Right command failed with exit code %d\n", WEXITSTATUS(right_status));
        } else if (WIFSIGNALED(right_status)) {
            printf("Right command terminated by signal %d\n", WTERMSIG(right_status));
        }
    }

    free_command_args(left_args);
    free_command_args(right_args);
}

void handle_pipe_with_my_tee(char *input, int *cmd_count, double *last_cmd_time,
                            double *avg_time, double *min_time, double *max_time) {
    int stderr_fd = handle_stderr_redirection_input(input);
    char *pipe_pos = strchr(input, '|');
    if (!pipe_pos) {
        printf("Error: Pipe not found.\n");
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    *pipe_pos = '\0';
    char *left_cmd = input;
    char *my_tee_cmd = pipe_pos + 1;

    while (*left_cmd == ' ') left_cmd++;
    while (*my_tee_cmd == ' ') my_tee_cmd++;
    while (strlen(left_cmd) > 0 && left_cmd[strlen(left_cmd) - 1] == ' ') {
        left_cmd[strlen(left_cmd) - 1] = '\0';
    }
    while (strlen(my_tee_cmd) > 0 && my_tee_cmd[strlen(my_tee_cmd) - 1] == ' ') {
        my_tee_cmd[strlen(my_tee_cmd) - 1] = '\0';
    }

    int original_stdin = dup(STDIN_FILENO);
    if (original_stdin == -1) {
        perror("dup failed");
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    int dummy_bg1 = 0, dummy_bg2 = 0;
    char **left_args = parse_command(left_cmd, &dummy_bg1);
    char **my_tee_args = parse_command(my_tee_cmd, &dummy_bg2);

    if (!left_args || !my_tee_args) {
        printf("Error: Invalid commands in pipe with my_tee.\n");
        if (left_args) free_command_args(left_args);
        if (my_tee_args) free_command_args(my_tee_args);
        close(original_stdin);
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    int append_mode = 0;
    int file_start = 1;
    if (my_tee_args[1] && strcmp(my_tee_args[1], "-a") == 0) {
        append_mode = 1;
        file_start = 2;
    }

    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("Error creating pipe");
        free_command_args(left_args);
        free_command_args(my_tee_args);
        close(original_stdin);
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("Error creating process");
        close(pipefd[0]);
        close(pipefd[1]);
        free_command_args(left_args);
        free_command_args(my_tee_args);
        close(original_stdin);
        if (stderr_fd != -1) close(stderr_fd);
        return;
    }

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    if (pid == 0) {
        if (stderr_fd != -1) {
            dup2(stderr_fd, STDERR_FILENO);
            close(stderr_fd);
        }
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[1]);
        execvp(left_args[0], left_args);
        perror("Execution failed for left command");
        _exit(EXIT_FAILURE);
    }

    if (stderr_fd != -1) close(stderr_fd);
    close(pipefd[1]);
    dup2(pipefd[0], STDIN_FILENO);
    close(pipefd[0]);

    int file_count = 0;
    if (my_tee_args[file_start]) {
        for (int i = file_start; my_tee_args[i] != NULL; i++) {
            file_count++;
        }
    }

    int *file_fds = NULL;
    if (file_count > 0) {
        file_fds = malloc(file_count * sizeof(int));
        if (!file_fds) {
            perror("Error allocating memory for file descriptors");
            dup2(original_stdin, STDIN_FILENO);
            close(original_stdin);
            free_command_args(left_args);
            free_command_args(my_tee_args);
            return;
        }

        for (int i = 0; i < file_count; i++) {
            int flags = O_WRONLY | O_CREAT | (append_mode ? O_APPEND : O_TRUNC);
            file_fds[i] = open(my_tee_args[file_start + i], flags, 0644);
            if (file_fds[i] < 0) {
                perror("Error opening file");
            }
        }
    }

    char buffer[1024];
    ssize_t bytes_read;
    while ((bytes_read = read(STDIN_FILENO, buffer, sizeof(buffer))) > 0) {
        if (write(STDOUT_FILENO, buffer, bytes_read) < 0) {
            perror("Error writing to stdout");
        }

        for (int i = 0; i < file_count; i++) {
            if (file_fds[i] >= 0) {
                if (write(file_fds[i], buffer, bytes_read) < 0) {
                    perror("Error writing to file");
                }
            }
        }
    }

    dup2(original_stdin, STDIN_FILENO);
    close(original_stdin);

    if (file_fds) {
        for (int i = 0; i < file_count; i++) {
            if (file_fds[i] >= 0) {
                close(file_fds[i]);
            }
        }
        free(file_fds);
    }

    int status;
    if (waitpid(pid, &status, 0) == -1 && errno != ECHILD) {
        perror("waitpid failed");
    }

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed_time = (end_time.tv_sec - start_time.tv_sec) +
                         (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    int success = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    update_statistics(elapsed_time, cmd_count, last_cmd_time, avg_time, min_time, max_time, success);

    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            printf("Process exited successfully\n");
        } else {
            printf("Process exited with error code %d\n", WEXITSTATUS(status));
        }
    } else if (WIFSIGNALED(status)) {
        printf("Process terminated by signal %d\n", WTERMSIG(status));
    }

    free_command_args(left_args);
    free_command_args(my_tee_args);
}

void free_dangerous_commands() {
    if (dangerous_commands) {
        for (int i = 0; i < danger_count; i++) {
            if (dangerous_commands[i]) {
                for (int j = 0; dangerous_commands[i][j] != NULL; j++) {
                    free(dangerous_commands[i][j]);
                }
                free(dangerous_commands[i]);
            }
        }
        free(dangerous_commands);
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
        free_dangerous_commands();
        return EXIT_FAILURE;
    }

    char input[MAX_CMD_LEN];
    int cmd_count = 0;
    double last_cmd_time = 0.0, avg_time = 0.0, min_time = 0.0, max_time = 0.0;
    int warning_cmd_count = 0;

    struct sigaction sa;
    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("Error setting up SIGCHLD handler");
        fclose(output_file);
        free_dangerous_commands();
        return EXIT_FAILURE;
    }

    while (1) {
        printf("#cmd:%d|#dangerous_cmd_blocked:%d|warning_cmd:%d|last_cmd_time:%.5f|avg_time:%.5f|min_time:%.5f|max_time:%.5f>> ",
               cmd_count, dangerous_cmd_blocked, warning_cmd_count, last_cmd_time, avg_time, min_time, max_time);

        if (!fgets(input, MAX_CMD_LEN, stdin)) {
            printf("\nExiting shell...\n");
            break;
        }

        // Check for empty or whitespace-only input
        int all_spaces = 1;
        for (char *p = input; *p && *p != '\n'; p++) {
            if (*p != ' ' && *p != '\t') {
                all_spaces = 0;
                break;
            }
        }
        if (all_spaces || input[0] == '\n') {
            continue;
        }

        if (strstr(input, "my_tee") && strchr(input, '|')) {
            handle_pipe_with_my_tee(input, &cmd_count, &last_cmd_time, &avg_time, &min_time, &max_time);
            continue;
        }

        if (strchr(input, '|')) {
            handle_pipe(input, output_file, &cmd_count, &last_cmd_time, &avg_time, &min_time, &max_time);
            continue;
        }

        int run_in_background = 0;
        char **args = parse_command(input, &run_in_background);
        if (args == NULL) {
            continue;
        }

        if (strcmp(args[0], "done") == 0) {
            int illegal_cmd_count = dangerous_cmd_blocked + warning_cmd_count;
            printf(" %d\n", illegal_cmd_count);
            free_command_args(args);
            break;
        }

        int danger_check = check_dangerous_command(args, &warning_cmd_count);
        if (danger_check == -1) {
            dangerous_cmd_blocked++;
            free_command_args(args);
            continue;
        }

        execute_command(args, run_in_background, output_file, &cmd_count,
                      &last_cmd_time, &avg_time, &min_time, &max_time);

        free_command_args(args);
    }

    fclose(output_file);



    free_dangerous_commands();

    return 0;
}
