// Copyright (C) 2014       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#include "utils.h"

void generate_edc_ecc_tables()
{
    unsigned int i;
    for(i = 0; i < 256; i++) 
	{
        unsigned int edc = i;
        unsigned int ii = (i << 1) ^ (i & 0x80 ? 0x11D : 0);
		ecc_table_f[i] = ii;
		ecc_table_b[i ^ ii] = i;
        
		for(ii = 0; ii < 8; ii++)
			edc = (edc >> 1) ^ (edc & 1 ? 0xD8018001 : 0);
        
        edc_table[i] = edc;
    }
}

void calculate_edc(unsigned char* block, unsigned int size, unsigned char* edc)
{
	unsigned int i;
	unsigned int edc_n = 0;
    for(i = size; i > 0; i--)
		edc_n = (edc_n >> 8) ^ edc_table[(edc_n ^ (*block++)) & 0xFF];
    
	edc[0] = edc_n & 0xFF;
	edc[1] = (edc_n >> 8) & 0xFF;
	edc[2] = (edc_n >> 16) & 0xFF;
	edc[3] = (edc_n >> 24) & 0xFF;
}

void calculate_ecc(unsigned char* block, unsigned char* ecc)
{
	unsigned int size_p = major_count_p * minor_count_p;
    unsigned int size_q = major_count_q * minor_count_q;
    unsigned int major_p;
	unsigned int major_q;
	unsigned int minor_p;
	unsigned int minor_q;

	// Calculate ECC P codes.
	for(major_p = 0; major_p < major_count_p; major_p++)
	{
        unsigned int index = (major_p >> 1) * major_mult_p + (major_p & 1);
        unsigned char ecc_a = 0;
        unsigned char ecc_b = 0;

        for(minor_p = 0; minor_p < minor_count_p; minor_p++)
		{
            unsigned char tmp;
            if (index < 4)
				tmp = 0;
			else
				tmp = block[index - 4];
           
            index += minor_inc_p;
            
			if(index >= size_p)
				index -= size_p;
            
			ecc_a ^= tmp;
            ecc_b ^= tmp;
            ecc_a = ecc_table_f[ecc_a];
        }
        ecc_a = ecc_table_b[ecc_table_f[ecc_a] ^ ecc_b];

		ecc[major_p] = ecc_a;
		ecc[major_p + major_count_p] = ecc_a ^ ecc_b;
    }

	// Calculate ECC Q codes.
    for(major_q = 0; major_q < major_count_q; major_q++)
	{
        unsigned int index = (major_q >> 1) * major_mult_q + (major_q & 1);
        unsigned char ecc_a = 0;
        unsigned char ecc_b = 0;

        for(minor_q = 0; minor_q < minor_count_q; minor_q++)
		{
            unsigned char tmp;
            if (index < 4)
				tmp = 0;
			else
				tmp = block[index - 4];
           
            index += minor_inc_q;
            
			if(index >= size_q)
				index -= size_q;
            
			ecc_a ^= tmp;
            ecc_b ^= tmp;
            ecc_a = ecc_table_f[ecc_a];
        }
        ecc_a = ecc_table_b[ecc_table_f[ecc_a] ^ ecc_b];

		ecc[0xAC + major_q] = ecc_a;
		ecc[0xAC + major_q + major_count_q] = ecc_a ^ ecc_b;
    }
}

unsigned char* strip_utf8(unsigned char *src, int size)
{
	unsigned char* ret = new unsigned char[size];
	int index = 0;

    for (int i = 0; i < size; i++)
	{
		if (src[i] == 0)
		{
			ret[index++] = '\0';
			break;
		}
		else if (src[i] <= 0x80)
			ret[index++] = src[i];
	}

    return ret;
}

bool isEmpty(unsigned char* buf, int buf_size)
{
	if (buf != NULL)
	{
		int i;
		for(i = 0; i < buf_size; i++)
		{
			if (buf[i] != 0) return false;
		}
	}
	return true;
}

int se32(int i)
{
	return ((i & 0xFF000000) >> 24) | ((i & 0xFF0000) >>  8) | ((i & 0xFF00) <<  8) | ((i & 0xFF) << 24);
}

u64 se64(u64 i)
{
	return ((i & 0x00000000000000ff) << 56) | ((i & 0x000000000000ff00) << 40) |
		((i & 0x0000000000ff0000) << 24) | ((i & 0x00000000ff000000) <<  8) |
		((i & 0x000000ff00000000) >>  8) | ((i & 0x0000ff0000000000) >> 24) |
		((i & 0x00ff000000000000) >> 40) | ((i & 0xff00000000000000) >> 56);
}