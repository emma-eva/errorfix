#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "hash.h"
#include "pkcs7.h"
#include "zip.h"

#define MAX_KEYSTORE_PASSWORD_LENGTH 1024

int zip_read_local_file_header(ZipFile *zip, LocalFileHeader *header, unsigned char **filename, unsigned char **extra_field) {
    if (zip->offset + sizeof(LocalFileHeader) > zip->size) {
        return 0;
    }
    memcpy(header, zip->data + zip->offset, sizeof(LocalFileHeader));
    zip->offset += sizeof(LocalFileHeader);
    if (header->signature != LOCAL_FILE_HEADER_SIGNATURE) {
        return 0;
    }
    *filename = (unsigned char *)(zip->data + zip->offset);
    zip->offset += header->filename_length;
    *extra_field = (unsigned char *)(zip->data + zip->offset);
    zip->offset += header->extra_field_length;
    return 1;
}

int zip_read_central_directory_header(ZipFile *zip, CentralDirectoryHeader *header, unsigned char **filename) {
    if (zip->offset + sizeof(CentralDirectoryHeader) > zip->size) {
        return 0;
    }
    memcpy(header, zip->data + zip->offset, sizeof(CentralDirectoryHeader));
    zip->offset += sizeof(CentralDirectoryHeader);
    if (header->signature != CENTRAL_DIRECTORY_SIGNATURE) {
        return 0;
    }
    *filename = (unsigned char *)(zip->data + zip->offset);
    zip->offset += header->filename_length;
    return 1;
}

int zip_find_central_directory_end(ZipFile *zip, CentralDirectoryEnd *end) {
    if (zip->size < sizeof(CentralDirectoryEnd)) {
        return 0;
    }
    unsigned char *p = zip->data + zip->size - sizeof(CentralDirectoryEnd);
    while (p >= zip->data) {
        if (*(uint32_t *)p == CENTRAL_DIRECTORY_END_SIGNATURE) {
            memcpy(end, p, sizeof(CentralDirectoryEnd));
            return 1;
        }
        p--;
    }
    return 0;
}

int zip_file_open(ZipFile *zip, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        printf("Error: failed to open ZIP file for reading.\n");
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    zip->size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    zip->data = malloc(zip->size);
    if (!zip->data) {
        printf("Error: failed to allocate memory for ZIP file data.\n");
        fclose(fp);
        return 0;
    }
    fread(zip->data, zip->size, 1, fp);
    fclose(fp);
    zip->offset = 0;
    return 1;
}

void zip_file_close(ZipFile *zip) {
    free(zip->data);
    zip->size = 0;
    zip->offset = 0;
}

int zip_compute_hash(ZipFile *zip, unsigned char *hash) {
    CentralDirectoryEnd end;
    if (!zip_find_central_directory_end(zip, &end)) {
        printf("Error: failed to find ZIP central directory end.\n");
        return 1;
    }
    unsigned char *p = zip->data + end.central_directory_offset;
    for (int i = 0; i < end.num_entries; i++) {
        CentralDirectoryFileHeader header;
        unsigned char *filename;
        unsigned char *extra_field;
        int ret = zip_read_central_directory_file_header(p, &header, &filename, &extra_field);
        if (!ret) {
            printf("Error: failed to read ZIP central directory file header.\n");
            return 1;
        }
        if (header.signature != CENTRAL_DIRECTORY_FILE_HEADER_SIGNATURE) {
            printf("Error: invalid ZIP central directory file header signature.\n");
            return 1;
        }
        if (header.compression_method != 0 && header.compression_method != 8) {
            printf("Error: ZIP entry uses unsupported compression method %u.\n", header.compression_method);
            return 1;
        }
        unsigned char *entry_data = zip->data + header.relative_offset_of_local_header;
        if (entry_data + sizeof(LocalFileHeader) > zip->data + zip->size) {
            printf("Error: ZIP entry extends beyond end of file.\n");
            return 1;
        }
        LocalFileHeader local_header;
        memcpy(&local_header, entry_data, sizeof(LocalFileHeader));
        if (local_header.signature != LOCAL_FILE_HEADER_SIGNATURE) {
            printf("Error: invalid ZIP local file header signature.\n");
            return 1;
        }
        if (local_header.compression_method != 0 && local_header.compression_method != 8) {
            printf("Error: ZIP entry uses unsupported compression method %u.\n", local_header.compression_method);
            return 1;
        }
        if (local_header.filename_length > MAX_FILENAME_LENGTH) {
            printf("Error: ZIP entry filename too long.\n");
            return 1;
        }
        if (entry_data + sizeof(LocalFileHeader) + local_header.filename_length + local_header.extra_field_length > zip->data + zip->size) {
            printf("Error: ZIP entry extends beyond end of file.\n");
            return 1;
        }
        unsigned char *entry_filename = entry_data + sizeof(LocalFileHeader);
        unsigned char *entry_extra_field = entry_filename + local_header.filename_length;
        if (header.compression_method == 0) {
            unsigned char *entry_data_start = entry_extra_field + local_header.extra_field_length;
            unsigned long entry_data_length = local_header.compressed_size;
            if (entry_data_start + entry_data_length > zip->data + zip->size) {
                printf("Error: ZIP entry extends beyond end of file.\n");
                return 1;
            }
            sha256(entry_data_start, entry_data_length, hash);
        } else {
            printf("Error: compressed ZIP entries not yet supported.\n");
            return 1;
        }
        p += sizeof(CentralDirectoryFileHeader) + header.filename_length + header.extra_field_length + header.file_comment_length;
    }
    return 0;
}
