#ifndef CONTACTS_H
#define CONTACTS_H

#include <stddef.h>  // 要size_t类型(AI教的)
#include <jansson.h>

// 联系人结构
typedef struct {
    char name[50];       // 姓名
    char gender[10];     // 性别
    char phone[20];      // 联系方式
    char workplace[100]; // 工作单位
    char address[100];   // 家庭住址
} Contact;

typedef struct {
    Contact *contacts; // 动态数组存储联系人
    size_t size;       // 当前联系人数量
    size_t capacity;   // 动态数组容量
} ContactList;

void init_contact_list(ContactList *list);

void add_contact(ContactList *list, const char *name, const char *gender,
                 const char *phone, const char *workplace, const char *address);

Contact *find_contact_by_name(const ContactList *list, const char *name);

Contact *find_contact_by_field(const ContactList *list, const char *field, const char *value);

void delete_contact(ContactList *list, const char *name);

char *convert_to_json(const ContactList *list);

void load_from_json_string(ContactList *list, const char *json_str);

void free_contact_list(ContactList *list);

#endif // CONTACTS_H
