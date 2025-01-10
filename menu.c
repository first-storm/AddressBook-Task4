#include "menu.h"

// 创建菜单
Menu *createMenu(const char *title)
{
    Menu *menu = (Menu *)malloc(sizeof(Menu));
    if (menu == NULL)
    {
        return NULL;
    }
    strncpy(menu->title, title, MAX_ITEM_LENGTH - 1);
    menu->title[MAX_ITEM_LENGTH - 1] = '\0';
    menu->itemCount = 0;
    return menu;
}

// 添加菜单项
void addMenuItem(Menu *menu, const char *text, void (*action)(void))
{
    if (menu->itemCount >= MAX_MENU_ITEMS)
    {
        return;
    }

    strncpy(menu->items[menu->itemCount].text, text, MAX_ITEM_LENGTH - 1);
    menu->items[menu->itemCount].text[MAX_ITEM_LENGTH - 1] = '\0';
    menu->items[menu->itemCount].action = action;
    menu->itemCount++;
}

// 显示菜单
void displayMenu(Menu *menu)
{
    printf("\n=== %s ===\n", menu->title);
    for (int i = 0; i < menu->itemCount; i++)
    {
        printf("%d. %s\n", i + 1, menu->items[i].text);
    }
}

// 获取用户选择
int getMenuChoice(Menu *menu)
{
    int choice;
    do
    {
        choice = safeInputInt("输入你的选择: ");
    } while (choice < 1 || choice > menu->itemCount);

    menu->items[choice - 1].action();
    return choice;
}

// 销毁菜单
void destroyMenu(Menu *menu)
{
    free(menu);
}

// 清除输入缓冲区
void clearInputBuffer(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;
}

// 安全整数输入
int safeInputInt(const char *prompt)
{
    int value;
    char input[MAX_INPUT_LENGTH];

    do
    {
        printf("%s", prompt);
        if (fgets(input, sizeof(input), stdin) != NULL)
        {
            char *endptr;
            value = strtol(input, &endptr, 10);
            if (*endptr == '\n')
            {
                return value;
            }
        }
        printf("Invalid input. Please enter a number.\n");
        clearInputBuffer();
    } while (1);
}

// 安全字符串输入
void safeInputString(const char *prompt, char *buffer, size_t size)
{
    printf("%s", prompt);
    if (fgets(buffer, size, stdin) != NULL)
    {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n')
        {
            buffer[len - 1] = '\0';
        }
    }
}

// 安全浮点数输入
double safeInputDouble(const char *prompt)
{
    double value;
    char input[MAX_INPUT_LENGTH];

    do
    {
        printf("%s", prompt);
        if (fgets(input, sizeof(input), stdin) != NULL)
        {
            char *endptr;
            value = strtod(input, &endptr);
            if (*endptr == '\n')
            {
                return value;
            }
        }
        printf("Invalid input. Please enter a number.\n");
        clearInputBuffer();
    } while (1);
}
