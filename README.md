**Mini Shell – Enhanced UNIX Shell Implementation**
Authored by Ahmad
Student ID: 325007433

---

### ==Description==

This program is a complete simulation of an enhanced command-line shell in C. It allows users to interactively execute system-level commands with advanced features such as:

* Pipe support (`|`)
* Custom implementation of `tee` as `my_tee`
* Background process execution (`&`)
* Error redirection (`2>`)
* Resource limits using the custom command `rlimit`
* Detection and prevention of dangerous commands
* Enhanced error reporting using `waitpid` and related macros

In addition to executing commands, the shell tracks execution times and maintains runtime statistics including: last, average, minimum, and maximum execution durations.

---

### ==Program DATABASE==

The program uses several core data structures and system-level constructs:

1. **`dangerous_commands`**:
   An array of string arrays. Each inner array represents a dangerous command split into its arguments. Full matches are blocked, and partial matches trigger warnings.

2. **`output_file`**:
   A file descriptor used to log execution times, command stats, and system feedback.

3. **`statistics`**:
   Variables used to track execution duration for each command (last, average, min, max).

4. **`pipe_fds`**:
   File descriptors used to handle pipe-based communication between commands.

5. **`input_buffer`**:
   A char array used to read user input.

---

### ==Functions Overview==

| Function Name             | Purpose                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `load_dangerous_commands` | Loads dangerous commands from a given text file.                                                                   |
| `parse_command`           | Parses user input and tokenizes it into an array of arguments.                                                     |
| `check_dangerous_command` | Checks if a command matches or partially matches any dangerous command.                                            |
| `execute_command`         | Runs commands with support for redirection, background mode, and pipes.                                            |
| `pipe_command`            | Connects the output of one command to the input of another using pipes.                                            |
| `my_tee`                  | Internal implementation of the `tee` command. Writes to stdout and one or more files. Supports append mode (`-a`). |
| `rlimit_command`          | Parses and applies resource limits (CPU, memory, file size, open files). Also prints current limits.               |
| `handle_exit_status`      | Interprets status codes returned by `waitpid`, distinguishing between normal exits and signals.                    |
| `main`                    | Main shell loop: reads input, processes command logic, handles statistics, and prints output.                      |

---

### ==Program Files==

* `ex2.c` – Contains all logic and functions, including `main()`.
* `dangerous_commands.txt` – List of commands that are considered dangerous (e.g., `rm -rf /`).
* `output.txt` – File where logs of executed commands and performance stats are saved.

---

### ==How to Compile==

```bash
gcc ex2.c -o mini_shell -Wall
```

To run the program:

```bash
./mini_shell dangerous_commands.txt output.txt
```

---

### ==Input==

* User input is read line-by-line interactively via the terminal.
* Commands can include pipes (`|`), background execution (`&`), internal commands like `my_tee` or `rlimit`, and error redirection (`2>`).

---

### ==Output==

* **Shell Prompt**: Interactive shell that shows execution timing statistics.
* **Standard Output**: Output of system commands is printed to terminal unless redirected.
* **Logs**: All commands and timing data are logged to `output.txt`.
* **Warnings/Errors**:

  * Attempt to run dangerous commands (full match) is blocked.
  * Partial matches produce a warning.
  * Exceeding a resource limit (e.g., `CPU time`) shows appropriate error messages.
  * If a command fails due to signals (e.g., segmentation fault), the signal name is printed.

---

### ==Usage Examples==

```bash
$ ls | grep txt
$ echo "hello" | my_tee file1.txt file2.txt
$ echo "line" | my_tee -a file1.txt
$ rlimit set cpu=1:2 mem=50M ./heavy_program
$ rlimit show
$ ./loop &   # runs in background
$ invalid_command 2> error_log.txt
```

---

### ==Notes==

* All system operations rely on **low-level system calls** (`fork`, `execvp`, `waitpid`, `open`, `read`, `write`, etc.).
* `my_tee` uses only system calls (not stdio).
* Resource limits are implemented via `setrlimit()` and `getrlimit()`.
* Memory is freed properly and file descriptors are closed.
* Checked with **Valgrind** for memory leaks.

---

هل بدك أطلعلك هاي النسخة كـ `README.md` ملف جاهز؟ أو بدك ترجمتها للعربي كمان؟
