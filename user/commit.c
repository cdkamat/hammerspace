/*
 * Commit log and replay
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#ifndef trace
#define trace trace_on
#endif

#include "inode.c"

void replay(struct sb *sb)
{
	//char *why = "something broke";
	// To do:
	// load commit blocks into map1
	// load log blocks into map2
	// scan for all fullfills
	// walk through block:
	//   if promise bread parent, apply
	//   if alloc update bitmap
	unsigned logblocks = sb->lognext, code;
	for (sb->lognext = 0; sb->lognext < logblocks;) {
		log_next(sb);
		struct logblock *log = bufdata(sb->logbuf);
		unsigned char *data = sb->logpos;
		while (data < log->data + from_be_u16(log->bytes)) {
			switch (code = *data++) {
			case LOG_ALLOC:
			case LOG_FREE:
			{
				u64 block;
				unsigned count = *data++;
				data = decode48(data, &block);
				trace("%s bits 0x%Lx/%x", code == LOG_ALLOC ? "set" : "clear", (L)block, count);
				update_bitmap(sb, block, count, code == LOG_ALLOC);
				break;
			}
			case LOG_UPDATE:
			{
				u64 child, parent, key;
				data = decode48(data, &child);
				data = decode48(data, &parent);
				data = decode48(data, &key);
				trace("child = 0x%Lx, parent = 0x%Lx, key = 0x%Lx", (L)child, (L)parent, (L)key);
				break;
			}
			default:
				break; //goto eek;
			}
		}
	}
}

static int need_delta(struct sb *sb)
{
	static unsigned crudehack;
	return !(++crudehack % 10);
};

int write_bitmap(struct buffer_head *buffer)
{
	struct sb *sb = tux_sb(buffer->map->inode->i_sb);
	struct seg seg;
	int err = map_region(buffer->map->inode, buffer->index, 1, &seg, 1, 2);
	if (err < 0)
		return err;
	assert(err == 1);
	if (buffer->state - BUFFER_DIRTY == (sb->delta & (BUFFER_DIRTY_STATES - 1)))
		return -EAGAIN;
	trace("write bitmap %Lx", (L)buffer->index);
	if (!(err = diskwrite(sb->dev->fd, buffer->data, sb->blocksize, seg.block)))
		set_buffer_clean(buffer);
	return 0;
}

static int stage_delta(struct sb *sb)
{
	assert(sb->dev->bits >= 8 && sb->dev->fd);
	struct buffer_head *buffer, *safe;
	struct list_head *head = &mapping(sb->bitmap)->dirty;
	list_for_each_entry_safe(buffer, safe, head, link) {
		int err = write_bitmap(buffer);
		if (err != -EAGAIN)
			return err;
	}
	return 0;
};

static int commit_delta(struct sb *sb)
{
	return flush_state(BUFFER_DIRTY + ((sb->delta - 1) & (BUFFER_DIRTY_STATES - 1)));
};

void change_begin(struct sb *sb)
{
	down_read(&sb->delta_lock);
}

void change_end(struct sb *sb)
{
	if (need_delta(sb)) {
		unsigned delta = sb->delta;
		up_read(&sb->delta_lock);
		down_write(&sb->delta_lock);
		if (sb->delta == delta) {
			trace("commit delta %u", sb->delta);
			++sb->delta;
			stage_delta(sb);
			commit_delta(sb);
		}
		up_write(&sb->delta_lock);
	} else
		up_read(&sb->delta_lock);
}

int bitmap_io(struct buffer_head *buffer, int write)
{
	return (write) ? write_bitmap(buffer) : filemap_extent_io(buffer, 0);
}

int main(int argc, char *argv[])
{
	struct dev *dev = &(struct dev){ .bits = 8, .fd = open(argv[1], O_CREAT|O_TRUNC|O_RDWR, S_IRWXU) };
	struct sb *sb = &(struct sb){ INIT_SB(dev), .volblocks = 100 };
	ftruncate(dev->fd, 1 << 24);
	sb->volmap = rapid_open_inode(sb, NULL, 0);
	sb->bitmap = rapid_open_inode(sb, bitmap_io, 0);
	sb->logmap = rapid_open_inode(sb, filemap_extent_io, 0);
	init_buffers(dev, 1 << 20, 0);
	assert(!new_btree(&sb->bitmap->btree, sb, &dtree_ops));

	if (0) {
		for (int block = 0; block < 10; block++) {
			struct buffer_head *buffer = blockget(mapping(sb->bitmap), block);
			memset(bufdata(buffer), 0, sb->blocksize);
			set_buffer_clean(buffer);
		}
	
		log_alloc(sb, 9, 6, 1);
		log_alloc(sb, 0x99, 3, 0);
		log_update(sb, 0xbabe, 0xd00d, 0x666);
		//hexdump(sb->logbuf->data, 0x40);
		log_finish(sb);
		replay(sb);
	}

	if (1) {
		for (int i = 0; i < 21; i++) {
			change_begin(sb);
			block_t block;
			assert(!balloc(sb, 1, &block));
			log_alloc(sb, block, 1, 1);
			change_end(sb);
		}
		log_finish(sb);
		replay(sb);
		show_buffers_state(BUFFER_DIRTY + 0);
		show_buffers_state(BUFFER_DIRTY + 1);
		show_buffers_state(BUFFER_DIRTY + 2);
		show_buffers_state(BUFFER_DIRTY + 3);
	}
	exit(0);
}
