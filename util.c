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

#include <ctype.h>

char*
ltrim(char *s)
{
    while (isspace(*s)) {
        s++;
    }
    return s;
}

char*
rtrim(char *s)
{
    char *back = s + strlen(s);
    while(isspace(*(--back)));
    *(back + 1) = '\0';
    return s;
}

char*
trim(char *s)
{
    return rtrim(ltrim(s)); 
}

int
startswith(const char *a, const char *b)
{
    if(strncmp(a, b, strlen(b)) == 0) {
        return 1;
    }
    return 0;
}