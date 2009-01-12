#ifndef BUFFER_H
#define BUFFER_H

#include "list.h"

#define BUFFER_DIRTY_STATES 4

enum {
	BUFFER_FREED, BUFFER_EMPTY, BUFFER_CLEAN, BUFFER_DIRTY,
	BUFFER_STATES = BUFFER_DIRTY + BUFFER_DIRTY_STATES
};

#define BUFFER_BUCKETS 999

typedef loff_t block_t; // disk io address range

struct dev { unsigned fd, bits; };

struct buffer_head;

typedef int (blockio_t)(struct buffer_head *buffer, int write);

struct map {
#if 1 /* tux3 only */
	struct inode *inode;
#endif
	struct list_head dirty;
	struct dev *dev;
	blockio_t *io;
	struct hlist_head hash[BUFFER_BUCKETS];
};

typedef struct map map_t;

struct buffer_head {
	map_t *map;
	struct hlist_node hashlink;
	struct list_head link;
	struct list_head lru; /* used for LRU list and the free list */
	unsigned count, state;
	block_t index;
	void *data;
};

struct buffer_head *new_buffer(map_t *map);
void show_buffer(struct buffer_head *buffer);
void show_buffers(map_t *map);
void show_buffers_state(unsigned state);
struct buffer_head *mark_buffer_dirty(struct buffer_head *buffer);
struct buffer_head *set_buffer_uptodate(struct buffer_head *buffer);
struct buffer_head *set_buffer_empty(struct buffer_head *buffer);
void brelse(struct buffer_head *buffer);
void brelse_dirty(struct buffer_head *buffer);
unsigned buffer_hash(block_t block);
struct buffer_head *peekblk(map_t *map, block_t block);
struct buffer_head *blockget(map_t *map, block_t block);
struct buffer_head *blockread(map_t *map, block_t block);
int blockdirty(struct buffer_head *buffer, unsigned newdelta);
int flush_buffers(map_t *map);
void evict_buffers(map_t *map);
void init_buffers(struct dev *dev, unsigned poolsize, int debug);

static inline void *bufdata(struct buffer_head *buffer)
{
	return buffer->data;
}

static inline unsigned bufsize(struct buffer_head *buffer)
{
	return 1 << buffer->map->dev->bits;
}

static inline block_t bufindex(struct buffer_head *buffer)
{
	return buffer->index;
}

static inline void get_bh(struct buffer_head *buffer)
{
	buffer->count++;
}

static inline int bufcount(struct buffer_head *buffer)
{
	return buffer->count;
}

static inline int buffer_empty(struct buffer_head *buffer)
{
	return buffer->state == BUFFER_EMPTY;
}

static inline int buffer_uptodate(struct buffer_head *buffer)
{
	return buffer->state == BUFFER_CLEAN;
}

static inline int buffer_dirty(struct buffer_head *buffer)
{
	return buffer->state >= BUFFER_DIRTY;
}

map_t *new_map(struct dev *dev, blockio_t *io);
void free_map(map_t *map);
#endif
