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
#include <string.h>
#include <arpa/inet.h>
#include <netdb.h>

#define FILE_PROTO_HEADER "FILE\n"
#define FILE_PROTO_HEADER_SIZE 5

/**
 * Initialize FILE connection with cuckoo's resultserver.
 */
FILE*
init_connection (char* ip, int port, char* filepath) {
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd == -1) {
        fprintf(stderr, "Failed to create socket.\n");
        exit(1);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Could not connect to remote server.\n");
        exit(1);
    }

    FILE *sockfp = fdopen(sockfd, "wb");
    fwrite(FILE_PROTO_HEADER, 1, FILE_PROTO_HEADER_SIZE, sockfp);
    fwrite(filepath, 1, strlen(filepath), sockfp);
    fwrite("\n", 1, 1, sockfp);

    return sockfp;
}

