/**
 * Copyright (C) 2019 Muhammed Ziad
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <sys/types.h>
#include <memory.h>

#define DEFAULT_DUMP_FILE "procmem.dmp"

/**
 * The region struct later unpacked by roach.
 */
typedef struct mem_region_entry {
    unsigned long long addr;
    unsigned int size;
    unsigned int state;
    unsigned int type;
    unsigned int protect;
} mem_region_entry;

void
print_usage (char *bin_name)
{
    printf("\n%s <pid> [dump_path]\n", bin_name);
    printf("\nDump process memory on Linux/ Android to be read by roch.\n");
    printf("project @ https://github.com/hatching/roach\n");
    printf("\narguments:\n");
    printf("\tpid\t\tTarget process id.\n");
    printf("\tdump_path\tPath to the output dump file.");
    printf("\noptions:\n");
    printf("\t--help, -h\tShow this help text.\n");
}

/**
 * Dump memory region with its memory info header to dump file.
 */
void
dump_mem_region (mem_region_entry region, FILE *mem_fp, FILE *dump_fp)
{
    /* Dump the info header */
    fwrite(&region.addr, sizeof(unsigned long long), 1, dump_fp);
    fwrite(&region.size, sizeof(unsigned int), 1, dump_fp);
    fwrite(&region.state, sizeof(unsigned int), 1, dump_fp);
    fwrite(&region.type, sizeof(unsigned int), 1, dump_fp);
    fwrite(&region.protect, sizeof(unsigned int), 1, dump_fp);

    /* Dump memory region data */
    unsigned long current_address = region.addr;
    unsigned long end_address = region.addr + region.size;
    unsigned char page[PAGE_SIZE];

    fseeko(mem_fp, region.addr, SEEK_SET);

    for (; current_address < end_address; current_address += PAGE_SIZE) {
        fread(page, 1, PAGE_SIZE, mem_fp);

        int res;
        res = fwrite(page, 1, PAGE_SIZE, dump_fp);
        if (res != PAGE_SIZE) {
            printf("Error writing to dump file.");
            exit(1);
        }
    }
}

/**
 * Read the memory map info header obtained from maps file: /proc/<pid>/maps.
 * @param map_str a string map of process memory.
 * @param region struct for storing the results.
 */
void
read_proc_map_info_header (char *map_str, mem_region_entry *region)
{
    char *start_addr = strtok(map_str, "-");
    char *end_addr = strtok(NULL, " ");
    char *protection = strtok(NULL, " ");

    region->addr = strtoull(start_addr, NULL, 16);
    region->size = strtoull(end_addr, NULL, 16) - region->addr;
    region->type = 0;
    region->state = 0;
    region->protect = 0;

    if (*(protection) == 'r') {
        region->protect |= PROT_READ;
    }

    if (*(protection + 1) == 'w') {
        region->protect |= PROT_WRITE;
    }

    if (*(protection + 2) == 'x') {
        region->protect |= PROT_EXEC;
    }

    if (*(protection + 3) == 's') {
        region->type |= MAP_SHARED;
    } else {
        region->type |= MAP_PRIVATE;
    }
}

int
main (int argc, char **argv)
{
    char *dump_filepath = DEFAULT_DUMP_FILE;
    pid_t pid = 0;

    /* Parse command-line options */
    int arg_index = 1;
    if (strcmp("--help", argv[arg_index]) == 0 ||
        strcmp("-h", argv[arg_index]) == 0) {
        print_usage(argv[0]);
        return 0;
    }

    /* Parse arguments */
    int remaining_args = argc - arg_index;
    if (remaining_args > 0 && remaining_args < 3) {
        pid = atoi(argv[arg_index]);
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
            printf("Failed to attach to pid: %d\n", pid);
            return 1;
        }
        wait(NULL);

        if (--remaining_args != 0) {
            dump_filepath = argv[++arg_index];
        }
    } else {
        print_usage(argv[0]);
        return 1;
    }

    char maps_filepath[20];
    char mem_filepath[20];

    sprintf(maps_filepath, "/proc/%d/maps", pid);
    sprintf(mem_filepath, "/proc/%d/mem", pid);

    FILE *maps_fp = fopen(maps_filepath, "r");
    if (!maps_fp) {
        printf("Error opening maps file for pid: %d\n", pid);
        return 1;
    }

    FILE *mem_fp = fopen(mem_filepath, "r");
    if (!mem_fp) {
        printf("Error opening mem file for pid: %d\n", pid);
        return 1;
    }

    FILE *dump_fp = fopen(dump_filepath, "wb");
    if (!dump_fp) {
        printf("Error opening output dump file with path: %s\n", dump_filepath);
        return 1;
    }

    char *mem_map_str = NULL;
    size_t str_size = 0;
    while (getline(&mem_map_str, &str_size, maps_fp) != -1) {
        mem_region_entry region;
        read_proc_map_info_header(mem_map_str, &region);

        dump_mem_region(region, mem_fp, dump_fp);
    }

    if (mem_map_str) {
        free(mem_map_str);
    }

    fclose(maps_fp);
    fclose(mem_fp);
    fclose(dump_fp);

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
