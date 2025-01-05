#ifndef MENU_H
#define MENU_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_MENU_ITEMS 20
#define MAX_ITEM_LENGTH 50
#define MAX_INPUT_LENGTH 100

// 菜单项结构体
typedef struct {
    char text[MAX_ITEM_LENGTH];
    void (*action)(void);
} MenuItem;

// 菜单结构体
typedef struct {
    char title[MAX_ITEM_LENGTH];
    MenuItem items[MAX_MENU_ITEMS];
    int itemCount;
} Menu;

// 菜单函数声明
Menu* createMenu(const char* title);
void addMenuItem(Menu* menu, const char* text, void (*action)(void));
void displayMenu(Menu* menu);
int getMenuChoice(Menu* menu);
void destroyMenu(Menu* menu);

// 安全输入函数声明
void clearInputBuffer(void);
int safeInputInt(const char* prompt);
void safeInputString(const char* prompt, char* buffer, size_t size);
double safeInputDouble(const char* prompt);

#endif
