/*
 * Tux3 versioning filesystem in user space
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"

#ifndef main
#define main notmain0
#include "balloc.c"
#undef main

#define main notmain3
#include "dir.c"
#undef main
#endif

#ifndef trace
#define trace trace_on
#endif

#include "kernel/xattr.c"

/* Xattr encode/decode */
#ifndef main
#define main notmain2
#include "ileaf.c"
#undef main
#endif

#ifndef main
#include <fcntl.h>

void change_begin(struct sb *sb) { };
void change_end(struct sb *sb) { };

int main(int argc, char *argv[])
{
	unsigned abits = DATA_BTREE_BIT|CTIME_SIZE_BIT|MODE_OWNER_BIT|LINK_COUNT_BIT|MTIME_BIT;
	struct dev *dev = &(struct dev){ .bits = 8, .fd = open(argv[1], O_CREAT|O_RDWR, S_IRWXU) };
	ftruncate(dev->fd, 1 << 24);
	init_buffers(dev, 1 << 20, 0);
	struct sb *sb = &(struct sb){
		RAPID_INIT_SB(dev),
		.version = 0,
		.atomref_base = 1 << 10,
		.unatom_base = 1 << 11,
		.atomgen = 1,
	};
	struct inode *inode = &(struct inode){
		.i_sb = sb,
		.i_mode = S_IFDIR | 0x666,
		.present = abits, .i_uid = 0x12121212, .i_gid = 0x34343434,
		.btree = { .root = { .block = 0xcaba1f00dULL, .depth = 3 } },
		.i_ctime = spectime(0xdec0debeadULL),
		.i_mtime = spectime(0xbadfaced00dULL) };
	inode->map = new_map(dev, NULL);
	inode->map->inode = inode;
	sb->atable = inode;

	for (int i = 0; i < 2; i++) {
		struct buffer_head *buffer = blockget(mapping(inode), tux_sb(inode->i_sb)->atomref_base + i);
		memset(bufdata(buffer), 0, sb->blocksize);
		brelse_dirty(buffer);
	}

	if (1) {
		warn("---- test positive and negative refcount carry ----");
		use_atom(inode, 6, 1 << 15);
		use_atom(inode, 6, (1 << 15));
		use_atom(inode, 6, -(1 << 15));
		use_atom(inode, 6, -(1 << 15));
	}

	warn("---- test atom table ----");
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "bar", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "foo", 3));
	printf("atom = %Lx\n", (L)make_atom(inode, "bar", 3));

	warn("---- test inode xattr cache ----");
	int err = 0;
	err = xcache_update(inode, 0x666, "hello", 5, 0);
	err = xcache_update(inode, 0x777, "world!", 6, 0);
	xcache_dump(inode);
	struct xattr *xattr = xcache_lookup(tux_inode(inode)->xcache, 0x777);
	if (!IS_ERR(xattr))
		printf("atom %x => %.*s\n", xattr->atom, xattr->size, xattr->body);
	err = xcache_update(inode, 0x111, "class", 5, 0);
	err = xcache_update(inode, 0x666, NULL, 0, 0);
	err = xcache_update(inode, 0x222, "boooyah", 7, 0);
	xcache_dump(inode);

	warn("---- test xattr inode table encode and decode ----");
	char attrs[1000] = { };
	char *top = encode_xattrs(inode, attrs, sizeof(attrs));
	hexdump(attrs, top - attrs);
	printf("predicted size = %x, encoded size = %Lx\n", encode_xsize(inode), (L)(top - attrs));
	inode->xcache->size = offsetof(struct xcache, xattrs);
	char *newtop = decode_attrs(inode, attrs, top - attrs);
	printf("predicted size = %x, xcache size = %x\n", decode_xsize(inode, attrs, top - attrs), inode->xcache->size);
	assert(top == newtop);
	xcache_dump(inode);
	free(inode->xcache);
	inode->xcache = NULL;
	warn("---- xattr update ----");
	set_xattr(inode, "hello", 5, "world!", 6, 0);
	set_xattr(inode, "empty", 5, "zot", 0, 0);
	set_xattr(inode, "foo", 3, "foobar", 6, 0);
	xcache_dump(inode);
	warn("---- xattr remove ----");
//	del_xattr(inode, "hello", 5);
	xcache_dump(inode);
	warn("---- xattr lookup ----");
	for (int i = 0, len; i < 3; i++) {
		char *namelist[] = { "hello", "foo", "world" }, *name = namelist[i];
		char data[100];
		int size = get_xattr(inode, name, len = strlen(name), data, sizeof(data));
		if (size < 0)
			printf("xattr %.*s not found (%s)\n", len, name, strerror(-size));
		else
			printf("found xattr %.*s => %.*s\n", len, name, size, data);
	}
	warn("---- list xattrs ----");
	int len = xattr_list(inode, attrs, sizeof(attrs));
	printf("xattr list length = %i\n", xattr_list(inode, NULL, 0));
	hexdump(attrs, len);

	warn("---- atom reverse map ----");
	for (int i = 0; i < 5; i++) {
		unsigned atom = i, offset;
		struct buffer_head *buffer = blockread_unatom(inode, atom, &offset);
		loff_t where = from_be_u64(((be_u64 *)bufdata(buffer))[offset]);
		brelse_dirty(buffer);
		buffer = blockread(mapping(inode), where >> sb->blockbits);
		printf("atom %.3Lx at dirent %.4Lx, ", (L)atom, (L)where);
		hexdump(bufdata(buffer) + (where & sb->blockmask), 16);
		brelse(buffer);
	}
	warn("---- atom recycle ----");
	set_xattr(inode, "hello", 5, NULL, 0, 0);
	show_freeatoms(sb);
	printf("got free atom %x\n", get_freeatom(inode));
	printf("got free atom %x\n", get_freeatom(inode));
	printf("got free atom %x\n", get_freeatom(inode));

	warn("---- dump atom table ----");
	dump_atoms(inode);
	show_buffers(inode->map);
	exit(0);
}
#endif
