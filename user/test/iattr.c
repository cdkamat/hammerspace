/*
 * Inode table attributes
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Portions copyright (c) 2006-2008 Google Inc.
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include "hexdump.c"
#include "tux3.h"

enum {
	CTIME_OWNER_ATTR = 7,
	MTIME_SIZE_ATTR = 8,
	DATA_BTREE_ATTR = 9,
};

unsigned atsize[16] = {
	[CTIME_OWNER_ATTR] = 20,
	[MTIME_SIZE_ATTR] = 14,
	[DATA_BTREE_ATTR] = 8,
};

struct size_mtime_attr { u64 size:60, mtime:54; };
struct data_btree_attr { struct root root; };

struct iattrs {
	struct root root;
	u64 mtime, ctime, isize;
	u32 mode, uid, gid;
} iattrs;

char *decode_two(SB, void *attr, unsigned *val)
{
	*val = be_to_u16(*(be_u16 *)attr);
	return attr + 2;
}

char *decode_four(SB, char *attr, unsigned *val)
{
	*val = be_to_u32(*(be_u32 *)attr);
	return attr + 4;
}

char *decode_eight(SB, char *attr, u64 *val)
{
	*val = be_to_u64(*(be_u64 *)attr);
	return attr + 8;
}

char *decode_six(SB, char *attr, u64 *val)
{
	unsigned part1, part2;
	attr = decode_two(sb, attr, &part1);
	attr = decode_four(sb, attr, &part2);
	*val = (u64)part1 << 32 | part2;
	return attr;
}

int decode_attrs(SB, void *attr, unsigned size)
{
	printf("decode %u attr bytes\n", size);
	struct iattrs iattrs = { };
	void *limit = attr + size;
	u64 v64;
	while (attr < limit - 1) {
		unsigned head, kind, version;
		attr = decode_two(sb, attr, &head);
		if ((version = head & 0xfff))
			continue;
		switch (kind = (head >> 12)) {
		case MTIME_SIZE_ATTR:
			attr = decode_eight(sb, attr - 2, &v64);
			attr = decode_eight(sb, attr, &iattrs.isize);
			iattrs.mtime = v64 & (-1ULL >> 16);
			printf("mtime = %Lx, isize = %Lx\n", (L)iattrs.mtime, (L)iattrs.isize);
			break;
		case DATA_BTREE_ATTR:
			attr = decode_eight(sb, attr, &v64);
			iattrs.root = (struct root){
				.block = v64 & (-1ULL >> 16),
				.depth = v64 >> 48 };
			printf("btree block = %Lx, depth = %u\n", (L)iattrs.root.block, iattrs.root.depth);
			break;
		case CTIME_OWNER_ATTR:
			attr = decode_six(sb, attr, &iattrs.ctime);
			attr = decode_four(sb, attr, &iattrs.mode);
			attr = decode_four(sb, attr, &iattrs.uid);
			attr = decode_four(sb, attr, &iattrs.gid);
			printf("ctime = %Lx, mode = %x\n", (L)iattrs.ctime, iattrs.mode);
			printf("uid = %x, gid = %x\n", iattrs.uid, iattrs.gid);
			break;
		default:
			warn("unknown attribute kind %i", kind);
			return 0;
		}
	}
	return 0;
}

char *encode_two(SB, char *attr, unsigned val)
{
	*(be_u16 *)attr = u16_to_be(val);
	return attr + 2;
}

char *encode_four(SB, char *attr, unsigned val)
{
	*(be_u32 *)attr = u32_to_be(val);
	return attr + 4;
}

char *encode_eight(SB, char *attr, u64 val)
{
	*(be_u64 *)attr = u64_to_be(val);
	return attr + 8;
}

char *encode_six(SB, char *attr, u64 val)
{
	attr = encode_two(sb, attr, val >> 32);
	return encode_four(sb, attr, val);
}

char *encode_kind(SB, char *attr, unsigned kind)
{
	return encode_two(sb, attr, (kind << 12) | sb->version);
}

char *encode_btree(SB, char *attr, struct root *root)
{
	attr = encode_kind(sb, attr, DATA_BTREE_ATTR);
	return encode_eight(sb, attr, ((u64)root->depth) << 48 | root->block);
}

char *encode_msize(SB, char *attr, u64 mtime, u64 isize)
{
	attr = encode_kind(sb, attr, MTIME_SIZE_ATTR);
	attr = encode_six(sb, attr, mtime);
	return encode_eight(sb, attr, isize);
}

char *encode_owner(SB, char *attr, u64 ctime, u32 mode, u32 uid, u32 gid)
{
	attr = encode_kind(sb, attr, CTIME_OWNER_ATTR);
	attr = encode_six(sb, attr, ctime);
	attr = encode_four(sb, attr, mode);
	attr = encode_four(sb, attr, uid);
	return encode_four(sb, attr, gid);
}

unsigned howmuch(u8 kind[], unsigned howmany)
{
	unsigned need = 0;
	for (int i = 0; i < howmany; i++)
		need += 2 + atsize[kind[i]];
	return need;
}

#ifndef main
int main(int argc, char *argv[])
{
	SB = &(struct sb){ .version = 0 };
	char iattrs[1000] = { };
	memset(iattrs, 0, sizeof(iattrs));
	printf("need %i attr bytes\n", howmuch((u8[]){ DATA_BTREE_ATTR, MTIME_SIZE_ATTR, CTIME_OWNER_ATTR }, 3));
	char *attr = iattrs;
	attr = encode_msize(sb, attr, 0xdec0debead, 0x123456789);
	attr = encode_btree(sb, attr, &(struct root){ .block = 0xcaba1f00d, .depth = 3 });
	attr = encode_owner(sb, attr, 0xdeadfaced00d, 0x666, 0x12121212, 0x34343434);
	decode_attrs(sb, iattrs, attr - iattrs);
	return 0;
}
#endif
