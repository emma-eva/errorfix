#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

ConfigOption *find_option(ConfigSection *section, const char *option) {
    for (size_t i = 0; i < section->num_options; i++) {
        if (strcmp(section->options[i].option, option) == 0) {
            return &section->options[i];
        }
    }
    return NULL;
}

char *get_option_value(ConfigSection *section, const char *option) {
    ConfigOption *config_option = find_option(section, option);
    if (config_option) {
        return config_option->value;
    } else {
        return NULL;
    }
}

ConfigSection *find_section(Config *config, const char *section) {
    for (size_t i = 0; i < config->num_sections; i++) {
        if (strcmp(config->sections[i].section, section) == 0) {
            return &config->sections[i];
        }
    }
    return NULL;
}

int parse_config(const char *file_path, Config *config) {
    // Open file for reading
    FILE *fp = fopen(file_path, "r");
    if (!fp) {
        printf("Error: failed to open file for reading.\n");
        return 1;
    }

    // Parse file
    char line[MAX_VALUE_LEN];
    ConfigSection *current_section = NULL;
    while (fgets(line, MAX_VALUE_LEN, fp)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == ';' || line[0] == '\0') {
            continue;
        }

        // Parse section
        if (line[0] == '[' && line[len - 1] == ']') {
            char *section_name = &line[1];
            section_name[len - 2] = '\0';
            current_section = find_section(config, section_name);
            if (!current_section) {
                config->num_sections++;
                config->sections = realloc(config->sections, config->num_sections * sizeof(ConfigSection));
                ConfigSection *new_section = &config->sections[config->num_sections - 1];
                strcpy(new_section->section, section_name);
                new_section->num_options = 0;
                new_section->options = NULL;
                current_section = new_section;
            }
        }

        // Parse option and value
        if (current_section && strchr(line, '=')) {
            char *option_name = strtok(line, "=");
            char *option_value = strtok(NULL, "=");
            if (option_name && option_value) {
                ConfigOption *config_option = find_option(current_section, option_name);
                if (!config_option) {
                    current_section->num_options++;
                    current_section->options = realloc(current_section->options, current_section->num_options * sizeof(ConfigOption));
                    config_option = &current_section->options[current_section->num_options - 1];
                                        config_option->option, option_name);
                    strcpy(config_option->value, option_value);
                } else {
                    strcpy(config_option->value, option_value);
                }
            }
        }
    }

    // Close file
    fclose(fp);

    return 0;
}

void free_config(Config *config) {
    for (size_t i = 0; i < config->num_sections; i++) {
        ConfigSection *section = &config->sections[i];
        for (size_t j = 0; j < section->num_options; j++) {
            ConfigOption *option = &section->options[j];
            // Clear sensitive data from memory
            memset(option->value, 0, strlen(option->value));
        }
        free(section->options);
    }
    free(config->sections);
}

int main(int argc, char *argv[]) {

    // Read configuration file
    Config config = {0};
    int ret = parse_config(argv[1], &config);
    if (ret != 0) {
        return ret;
    }

    // Print configuration data
    for (size_t i = 0; i < config.num_sections; i++) {
        ConfigSection *section = &config.sections[i];
        printf("[%s]\n", section->section);
        for (size_t j = 0; j < section->num_options; j++) {
            ConfigOption *option = &section->options[j];
            printf("%s = %s\n", option->option, option->value);
        }
        printf("\n");
    }

    // Free memory
    free_config(&config);

    return 0;
}

