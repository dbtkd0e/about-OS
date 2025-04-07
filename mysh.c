/* Simple shell, Yusang Oh(dbtkd0e@gmail.com)*/
/* mysh.c */
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

#define MAX_TOKEN 50
#define MAX_REDIRECTION 30

char** parsing(const char* line, const char* delimiter, int* count) {
    char* lineCopy = strdup(line); //line의 원본을 수정하지 않기 위한 copy
    char* token = strtok(lineCopy, delimiter); 
    int tokenCount = 0;

    while (token != NULL) { // 토큰 개수 세기
        token = strtok(NULL, delimiter);
        tokenCount++;
    }

    *count = tokenCount;
    char** result = (char**)malloc((tokenCount + 1) * sizeof(char*));

    // line 토큰화 / result 배열에 저장 
    token = strtok(strdup(line), delimiter);
    int i;
    for (i = 0; i < tokenCount; i++) {
        result[i] = strdup(token);
        token = strtok(NULL, delimiter);
    }
    result[tokenCount] = NULL; // result 배열의 끝에 null 추가
    free(lineCopy);
    return result;
}

// output redirection 처리 함수
void redirection(char* output_file, int redirection_type) {
    int fd;
    if (redirection_type == 1) {
        fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    } else if (redirection_type == 2) {
        fd = open(output_file, O_WRONLY | O_CREAT | O_APPEND, 0644);
    }

    if (fd == -1) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    dup2(fd, fileno(stdout)); // 표준 출력을 output_file로 redirection
    close(fd);
}

// command 실행 
int run(char** tokens, char* cwd) {
    pid_t fork_return;
    //int status = -1;

    if (strcmp(tokens[0], "exit") == 0)
        return 0;
    else if (strcmp(tokens[0], "cd") == 0) {
        chdir(tokens[1]); //디렉토리 변경
        return 1; 
    }

    int redirection_count = 0;
    int redirection_types[MAX_REDIRECTION]; // 0: redirectionion X, 1: '>', 2: '>>'
    char* output_files[MAX_REDIRECTION];

    // Redirection 체크
    int i;
    for (i = 0; tokens[i] != NULL; i++) {
        if (strcmp(tokens[i], ">") == 0 || strcmp(tokens[i], ">>") == 0) {
            redirection_types[redirection_count] = (strcmp(tokens[i], ">") == 0) ? 1 : 2;
            output_files[redirection_count] = tokens[i + 1];
            tokens[i] = NULL; // '>', '>>' 를 NULL로
            redirection_count++;
        }
    }


    int original_stdout = dup(fileno(stdout)); // 표준출력 fd 저장해두기


    if (redirection_count > 0) {
        // redirection이 필요할 경우 각각의 경우마다 자식 process 생성
        for (i = 0; i < redirection_count; i++) {
            if ((fork_return = fork()) < 0) {
                perror("fork error");
            } else if (fork_return == 0) {
                redirection(output_files[i], redirection_types[i]);
                execvp(tokens[0], tokens);
                perror("execvp failed");
                exit(EXIT_FAILURE);
            } else {
                waitpid(fork_return, NULL, 0);
            }
        }
        dup2(original_stdout, fileno(stdout)); // 재지정된 표준입출력 복구
        close(original_stdout);
        return 1;
    } 
    else {
        // redirection이 필요하지 않은 경우 
        if ((fork_return = fork()) < 0) {
            perror("fork error");
        } 
        else if (fork_return == 0) {
            execvp(tokens[0], tokens);
            perror("execvp failed");
            exit(EXIT_FAILURE);
        } 
        else {
            waitpid(fork_return, NULL, 0);
        }
    }
    close(original_stdout);

    return 1;
}

int main() {
    char line[1024];
    char* delimiter = " ";
    while (1) {
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
            printf("[%s]\n$ ", cwd);
        } else {
            perror("getcwd() error");
            return 1;
        }

        fgets(line, sizeof(line) - 1, stdin);
        line[strcspn(line, "\n")] = '\0';

        int count;
        char** tokens = parsing(line, delimiter, &count);

        if (run(tokens, cwd) == 0)
            break;

        // 메모리 해제
        int i;
        for (i = 0; i < count; i++) {
            free(tokens[i]);
        }
        free(tokens);
    }
    return 0;
}
