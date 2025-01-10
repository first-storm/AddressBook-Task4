#ifndef ENTRY_H
#define ENTRY_H
#include "encryption.h"
#include "menu.h"
#include <signal.h>

// 程序入口（代替main，可读性更好点）
int entry_main();

// 主菜单
int menu_main();

// 菜单功能函数
void addContactMenu(void);
void findContactMenu(void);
void modifyContactMenu(void);
void deleteContactMenu(void);
void displayAllContactsMenu(void);

int safe_exit();
void handle_exit_signal(int signal);
void handle_exit();

#endif