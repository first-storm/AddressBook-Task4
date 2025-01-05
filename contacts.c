#include "contacts.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>

void init_contact_list(ContactList *list) {
    list->contacts = NULL;
    list->size = 0;
    list->capacity = 0;
}

void add_contact(ContactList *list, const char *name, const char *gender,
                 const char *phone, const char *workplace, const char *address) {
    if (list->size == list->capacity) {
        list->capacity = list->capacity == 0 ? 10 : list->capacity * 2;
        list->contacts = realloc(list->contacts, list->capacity * sizeof(Contact));
    }

    Contact *contact = &list->contacts[list->size++];
    strncpy(contact->name, name, sizeof(contact->name) - 1);
    strncpy(contact->gender, gender, sizeof(contact->gender) - 1);
    strncpy(contact->phone, phone, sizeof(contact->phone) - 1);
    strncpy(contact->workplace, workplace, sizeof(contact->workplace) - 1);
    strncpy(contact->address, address, sizeof(contact->address) - 1);
}

Contact *find_contact_by_name(const ContactList *list, const char *name) {
    for (size_t i = 0; i < list->size; i++) {
        if (strcmp(list->contacts[i].name, name) == 0) {
            return &list->contacts[i];
        }
    }
    return NULL;
}

Contact *find_contact_by_field(const ContactList *list, const char *field, const char *value) {
    for (size_t i = 0; i < list->size; i++) {
        Contact *contact = &list->contacts[i];
        if ((strcmp(field, "name") == 0 && strcmp(contact->name, value) == 0) ||
            (strcmp(field, "gender") == 0 && strcmp(contact->gender, value) == 0) ||
            (strcmp(field, "phone") == 0 && strcmp(contact->phone, value) == 0) ||
            (strcmp(field, "workplace") == 0 && strcmp(contact->workplace, value) == 0) ||
            (strcmp(field, "address") == 0 && strcmp(contact->address, value) == 0)) {
            return contact;
        }
    }
    return NULL;
}

void delete_contact(ContactList *list, const char *name) {
    for (size_t i = 0; i < list->size; i++) {
        if (strcmp(list->contacts[i].name, name) == 0) {
            for (size_t j = i; j < list->size - 1; j++) {
                list->contacts[j] = list->contacts[j + 1];
            }
            list->size--;
            return;
        }
    }
}

char *convert_to_json(const ContactList *list) {
    json_t *json_array_new = json_array();

    for (size_t i = 0; i < list->size; i++) {
        const Contact *contact = &list->contacts[i];
        json_t *json_contact = json_object();
        json_object_set_new(json_contact, "name", json_string(contact->name));
        json_object_set_new(json_contact, "gender", json_string(contact->gender));
        json_object_set_new(json_contact, "phone", json_string(contact->phone));
        json_object_set_new(json_contact, "workplace", json_string(contact->workplace));
        json_object_set_new(json_contact, "address", json_string(contact->address));
        json_array_append_new(json_array_new, json_contact);
    }

    char *json_str = json_dumps(json_array_new, JSON_INDENT(4));

    json_decref(json_array_new);

    return json_str;
}

void load_from_json_string(ContactList *list, const char *json_str) {
    json_error_t error;
    json_t *json_array = json_loads(json_str, 0, &error);

    if (!json_array) {
        fprintf(stderr, "Error loading JSON: %s\n", error.text);
        return;
    }

    if (!json_is_array(json_array)) {
        fprintf(stderr, "Error: JSON is not an array\n");
        json_decref(json_array);
        return;
    }

    list->size = 0;
    list->capacity = json_array_size(json_array);
    list->contacts = realloc(list->contacts, list->capacity * sizeof(Contact));

    for (size_t i = 0; i < list->capacity; i++) {
        json_t *json_contact = json_array_get(json_array, i);
        if (!json_is_object(json_contact)) continue;

        Contact *contact = &list->contacts[list->size++];
        strncpy(contact->name, json_string_value(json_object_get(json_contact, "name")), sizeof(contact->name) - 1);
        strncpy(contact->gender, json_string_value(json_object_get(json_contact, "gender")), sizeof(contact->gender) - 1);
        strncpy(contact->phone, json_string_value(json_object_get(json_contact, "phone")), sizeof(contact->phone) - 1);
        strncpy(contact->workplace, json_string_value(json_object_get(json_contact, "workplace")), sizeof(contact->workplace) - 1);
        strncpy(contact->address, json_string_value(json_object_get(json_contact, "address")), sizeof(contact->address) - 1);
    }

    json_decref(json_array);
}

void free_contact_list(ContactList *list) {
    free(list->contacts);
    list->contacts = NULL;
    list->size = 0;
    list->capacity = 0;
}
