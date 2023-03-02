#ifndef CONFIG_H
#define CONFIG_H

#include <stdio.h>
#include <stdlib.h>

#define MAX_SECTION_LEN 256
#define MAX_OPTION_LEN 256
#define MAX_VALUE_LEN 1024

typedef struct {
    char section[MAX_SECTION_LEN];
    char option[MAX_OPTION_LEN];
    char value[MAX_VALUE_LEN];
} ConfigOption;

typedef struct {
    ConfigOption *options;
    size_t num_options;
} ConfigSection;

typedef struct {
    ConfigSection *sections;
    size_t num_sections;
} Config;

int parse_config(const char *file_path, Config *config);
void free_config(Config *config);

#endif
