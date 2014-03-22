// Copyright (C) 2014       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

typedef unsigned long long u64;

// ECC/EDC lookup tables.
static unsigned char ecc_table_f[256];
static unsigned char ecc_table_b[256];
static unsigned int edc_table[256];

// ECC P/Q values.
static unsigned int major_count_p = 86;
static unsigned int minor_count_p = 24;
static unsigned int major_mult_p = 2;
static unsigned int minor_inc_p = 86;
static unsigned int major_count_q = 52;
static unsigned int minor_count_q = 43;
static unsigned int major_mult_q = 86;
static unsigned int minor_inc_q = 88;

void generate_edc_ecc_tables();
void calculate_edc(unsigned char* block, unsigned int size, unsigned char* edc);
void calculate_ecc(unsigned char* block, unsigned char* ecc);
unsigned char* strip_utf8(unsigned char *src, int size);
bool isEmpty(unsigned char* buf, int buf_size);
int se32(int i);
u64 se64(u64 i);