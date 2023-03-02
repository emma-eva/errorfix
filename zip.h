#ifndef ZIP_H
#define ZIP_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define ZIP_LOCAL_FILE_HEADER_SIGNATURE 0x04034b50
#define ZIP_CENTRAL_DIRECTORY_SIGNATURE 0x02014b50
#define ZIP_END_OF_CENTRAL_DIRECTORY_SIGNATURE 0x06054b50

typedef struct {
    uint32_t signature;
    uint16_t version_needed;
    uint16_t general_purpose_bit_flag;
    uint16_t compression_method;
    uint16_t last_mod_file_time;
    uint16_t last_mod_file_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
    char *file_name;
    unsigned char *extra_field;
} ZipLocalFileHeader;

typedef struct {
    uint32_t signature;
    uint16_t version_made_by;
    uint16_t version_needed;
    uint16_t general_purpose_bit_flag;
    uint16_t compression_method;
    uint16_t last_mod_file_time;
    uint16_t last_mod_file_date;
    uint32_t crc32;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint16_t file_name_length;
    uint16_t extra_field_length;
    uint16_t file_comment_length;
    uint16_t disk_number_start;
    uint16_t internal_file_attributes;
    uint32_t external_file_attributes;
    uint32_t relative_offset_of_local_header;
    char *file_name;
    unsigned char *extra_field;
    char *file_comment;
} ZipCentralDirectoryRecord;

typedef struct {
    uint32_t signature;
    uint16_t number_of_this_disk;
    uint16_t number_of_disk_with_start_of_central_directory;
    uint16_t total_number_of_entries_in_central_directory_on_this_disk;
    uint16_t total_number_of_entries_in_central_directory;
    uint32_t size_of_central_directory;
    uint32_t offset_of_start_of_central_directory;
    uint16_t comment_length;
    char *comment;
} ZipEndOfCentralDirectoryRecord;

typedef struct {
    FILE *fp;
    uint32_t central_directory_offset;
} ZipFile;

int zip_file_open(ZipFile *zip, const char *filename);
int zip_file_close(ZipFile *zip);
int zip_file_get_num_entries(ZipFile *zip);
int zip_file_get_entry_names(ZipFile *zip, char ***names);
int zip_file_get_entry_data(ZipFile *zip, const char *entry_name, unsigned char **data, size_t *size);
int zip_file_add_entry(ZipFile *zip, const char *entry_name, const unsigned char *data, size_t size);
int zip_file_remove_entry(ZipFile *zip, const char *entry_name);
int zip_compute_hash(ZipFile *zip, unsigned char *hash);
int zip_add_signature(ZipFile *zip, const unsigned char *signature_data, size_t signature_size, const unsigned char *keystore_hash);
int zip_save(ZipFile *zip, const char *filename);

#endif
