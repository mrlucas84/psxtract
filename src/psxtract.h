// Copyright (C) 2014       Hykem <hykem@hotmail.com>
// Licensed under the terms of the GNU GPL, version 3
// http://www.gnu.org/licenses/gpl-3.0.txt

#define _CRT_SECURE_NO_WARNINGS

#include <direct.h>

#include "lz.h"
#include "crypto.h"

// ISO image signature.
char iso_magic[0xC] = {
	0x50,  // P
	0x53,  // S
	0x49,  // I
	0x53,  // S
	0x4F,  // O
	0x49,  // I
	0x4D,  // M
	0x47,  // G
	0x30,  // 0
	0x30,  // 0
	0x30,  // 0
	0x30   // 0
};

// ISO table entry structure.
typedef struct {
	unsigned int     offset;
	unsigned short   size;
	unsigned short   marker;
	unsigned char	 checksum[0x10];
	unsigned char	 padding[0x8];
} ISO_ENTRY;

// STARTDAT header structure.
typedef struct {
	unsigned char    magic[8];
	unsigned int	 unk1;
	unsigned int	 unk2;
	unsigned int	 header_size;
	unsigned int	 data_size;
} STARTDAT_HEADER;