#include "entry.h"
#include "menu.h"
#include "contacts.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 全局变量
ContactList contacts;
char password[64];

void addContactMenu(void)
{
    char name[50], gender[10], phone[20], workplace[100], address[100];

    printf("\n=== 添加联系人 ===\n");
    safeInputString("请输入姓名: ", name, sizeof(name));
    safeInputString("请输入性别: ", gender, sizeof(gender));
    safeInputString("请输入电话: ", phone, sizeof(phone));
    safeInputString("请输入工作单位: ", workplace, sizeof(workplace));
    safeInputString("请输入家庭住址: ", address, sizeof(address));

    add_contact(&contacts, name, gender, phone, workplace, address);
    printf("联系人添加成功！\n\n");
}

void findContactMenu(void)
{
    Menu *findMenu = createMenu("查找联系人");
    addMenuItem(findMenu, "按姓名查找", NULL);
    addMenuItem(findMenu, "按电话查找", NULL);
    addMenuItem(findMenu, "按工作单位查找", NULL);
    addMenuItem(findMenu, "按住址查找", NULL);

    int choice;
    char searchValue[100];
    Contact *result = NULL;

    displayMenu(findMenu);
    choice = safeInputInt("请输入查找选项: ");

    if (choice != 0)
    {
        safeInputString("请输入搜索关键词: ", searchValue, sizeof(searchValue));

        switch (choice)
        {
        case 1: // 按姓名
            result = find_contact_by_name(&contacts, searchValue);
            break;
        case 2: // 按电话
            result = find_contact_by_field(&contacts, "phone", searchValue);
            break;
        case 3: // 按工作单位
            result = find_contact_by_field(&contacts, "workplace", searchValue);
            break;
        case 4: // 按住址
            result = find_contact_by_field(&contacts, "address", searchValue);
            break;
        }

        if (result)
        {
            printf("\n找到联系人：\n");
            printf("姓名: %s\n", result->name);
            printf("性别: %s\n", result->gender);
            printf("电话: %s\n", result->phone);
            printf("工作单位: %s\n", result->workplace);
            printf("住址: %s\n", result->address);
        }
        else
        {
            printf("\n未找到相关联系人。\n");
        }
    }

    destroyMenu(findMenu);
}

void modifyContactMenu(void)
{
    char name[50];
    printf("\n=== 修改联系人 ===\n");
    safeInputString("请输入要修改的联系人姓名: ", name, sizeof(name));

    Contact *contact = find_contact_by_name(&contacts, name);
    if (!contact)
    {
        printf("未找到该联系人！\n");
        return;
    }

    Menu *modifyMenu = createMenu("修改选项");
    addMenuItem(modifyMenu, "修改性别", NULL);
    addMenuItem(modifyMenu, "修改电话", NULL);
    addMenuItem(modifyMenu, "修改工作单位", NULL);
    addMenuItem(modifyMenu, "修改住址", NULL);

    int choice;
    displayMenu(modifyMenu);
    choice = safeInputInt("请输入修改选项: ");

    switch (choice)
    {
    case 1:
        safeInputString("请输入新的性别: ", contact->gender, sizeof(contact->gender));
        break;
    case 2:
        safeInputString("请输入新的电话: ", contact->phone, sizeof(contact->phone));
        break;
    case 3:
        safeInputString("请输入新的工作单位: ", contact->workplace, sizeof(contact->workplace));
        break;
    case 4:
        safeInputString("请输入新的住址: ", contact->address, sizeof(contact->address));
        break;
    }

    if (choice != 0)
    {
        printf("修改成功！\n");
    }

    destroyMenu(modifyMenu);
}

void deleteContactMenu(void)
{
    char name[50];
    printf("\n=== 删除联系人 ===\n");
    safeInputString("请输入要删除的联系人姓名: ", name, sizeof(name));

    Contact *contact = find_contact_by_name(&contacts, name);
    if (!contact)
    {
        printf("未找到该联系人！\n");
        return;
    }

    char confirm[10];
    printf("确认删除联系人 %s？(yes/no): ", name);
    safeInputString("", confirm, sizeof(confirm));

    if (strcmp(confirm, "yes") == 0)
    {
        delete_contact(&contacts, name);
        printf("联系人已删除！\n");
    }
    else
    {
        printf("已取消删除操作。\n");
    }
}

void displayAllContactsMenu(void)
{
    printf("\n=== 所有联系人 ===\n");
    if (contacts.size == 0)
    {
        printf("通讯录为空！\n");
        return;
    }

    for (size_t i = 0; i < contacts.size; i++)
    {
        printf("\n联系人 %zu:\n", i + 1);
        printf("姓名: %s\n", contacts.contacts[i].name);
        printf("性别: %s\n", contacts.contacts[i].gender);
        printf("电话: %s\n", contacts.contacts[i].phone);
        printf("工作单位: %s\n", contacts.contacts[i].workplace);
        printf("住址: %s\n", contacts.contacts[i].address);
        printf("------------------------\n");
    }
}

int entry_main()
{
    signal(SIGINT, handle_exit_signal);
    signal(SIGTERM, handle_exit_signal);
    init_contact_list(&contacts);

    safeInputString("请输入密码: ", password, sizeof(password));
    FILE *file = fopen("database.dat", "r");
    if (!file)
    {
        file = fopen("database.dat", "w");
        if (!file)
        {
            fprintf(stderr, "无法创建数据库文件\n");
            return 1;
        }
    }
    else
    {
        char encrypted[8192];
        char *decrypted = malloc(sizeof(encrypted));
        size_t bytes_read = fread(encrypted, 1, sizeof(encrypted), file);
        if (bytes_read == 0)
        {
            fprintf(stderr, "无法读取数据库文件\n");
            free(decrypted);
            fclose(file);
            return 1;
        }
        int decrypted_len = decrypt_string(encrypted, password, &decrypted);
        if (decrypted_len < 0)
        {
            fprintf(stderr, "无法解密数据库文件，可能是密码错误。\n");
            free(decrypted);
            fclose(file);
            return 1;
        }
        load_from_json_string(&contacts, decrypted);
        free(decrypted);
    }
    fclose(file);

    if (menu_main() != 0)
    {
        fprintf(stderr, "程序发生错误\n");
        return 1;
    }

    return 0;
}

int menu_main()
{
    Menu *mainMenu = createMenu("主菜单");

    addMenuItem(mainMenu, "添加联系人", addContactMenu);
    addMenuItem(mainMenu, "查找联系人", findContactMenu);
    addMenuItem(mainMenu, "修改联系人信息", modifyContactMenu);
    addMenuItem(mainMenu, "删除联系人", deleteContactMenu);
    addMenuItem(mainMenu, "显示所有联系人", displayAllContactsMenu);
    addMenuItem(mainMenu, "退出", handle_exit);

    int choice;
    do
    {
        displayMenu(mainMenu);
        choice = getMenuChoice(mainMenu);

        // 如果用户选择了退出（0），在退出前保存数据
        if (choice == 0)
        {
            safe_exit();
        }
    } while (choice != 0);

    destroyMenu(mainMenu);
    return 0;
}

void handle_exit()
{
    safe_exit();
    exit(0);
}

void handle_exit_signal(int signal)
{
    fprintf(stderr, "\n退出: %d\n", signal);
    safe_exit();
    exit(signal);
}

int safe_exit()
{
    FILE *file = fopen("database.dat", "w+");
    if (!file)
    {
        fprintf(stderr, "无法打开数据库文件\n");
        return 1;
    }

    char *json_str = convert_to_json(&contacts);
    if (!json_str)
    {
        fprintf(stderr, "无法转换为JSON\n");
        fclose(file);
        return 1;
    }

    char *encrypted = malloc(8192); // 使用动态分配内存
    if (!encrypted)
    {
        fprintf(stderr, "内存分配失败\n");
        free(json_str);
        fclose(file);
        return 1;
    }
    encrypt_string(json_str, password, &encrypted);
    int encrypted_len = strlen(encrypted);
    if (encrypted_len < 0)
    {
        fprintf(stderr, "无法加密数据\n");
        free(json_str);
        fclose(file);
        return 1;
    }

    size_t bytes_written = fwrite(encrypted, 1, encrypted_len, file);
    if (bytes_written != encrypted_len)
    {
        fprintf(stderr, "无法写入数据库文件\n");
        free(json_str);
        fclose(file);
        return 1;
    }

    free(encrypted);
    free(json_str);
    fclose(file);
    free_contact_list(&contacts);
    return 0;
}