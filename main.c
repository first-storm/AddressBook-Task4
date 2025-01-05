#include <stdio.h>
#include "entry.h"

int main(void) {
    const int exit_code = entry_main();
    if (exit_code != 0) {
        printf("出现未预期的错误，程序退出。错误码：%d\n", exit_code);
    }
    return 0;
}
