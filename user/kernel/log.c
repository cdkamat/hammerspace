/*
 * Copyright (c) 2008, Daniel Phillips
 * Copyright (c) 2008, OGAWA Hirofumi
 */

#include "tux3.h"

void log_next(struct sb *sb)
{
	sb->logbuf = blockget(mapping(sb->logmap), sb->lognext++);
	sb->logpos = bufdata(sb->logbuf) + sizeof(struct logblock);
	sb->logtop = bufdata(sb->logbuf) + sb->blocksize;
}

void log_finish(struct sb *sb)
{
	struct logblock *log = bufdata(sb->logbuf);
	assert(sb->logtop >= sb->logpos);
	log->bytes = to_be_u16(sb->logpos - log->data);
	memset(sb->logpos, 0, sb->logtop - sb->logpos);
	brelse(sb->logbuf);
	sb->logbuf = NULL;
}

void *log_begin(struct sb *sb, unsigned bytes)
{
	mutex_lock(&sb->loglock);
	if (sb->logpos + bytes > sb->logtop) {
		if (sb->logbuf)
			log_finish(sb);
		log_next(sb);
		*(struct logblock *)bufdata(sb->logbuf) = (struct logblock){
			.magic = to_be_u16(0xc0de) };
	}
	return sb->logpos;
}

void log_end(struct sb *sb, void *pos)
{
	sb->logpos = pos;
	mutex_unlock(&sb->loglock);
}

void log_alloc(struct sb *sb, block_t block, unsigned count, unsigned alloc)
{
	unsigned char *data = log_begin(sb, 8);
	*data++ = alloc ? LOG_ALLOC : LOG_FREE;
	*data++ = count;
	log_end(sb, encode48(data, block));
}

void log_update(struct sb *sb, block_t child, block_t parent, tuxkey_t key)
{
	unsigned char *data = log_begin(sb, 19);
	*data++ = LOG_UPDATE;
	data = encode48(data, child);
	data = encode48(data, parent);
	log_end(sb, encode48(data, key));
}

void log_droot(struct sb *sb, block_t newroot, block_t oldroot, tuxkey_t key)
{
	unsigned char *data = log_begin(sb, 19);
	*data++ = LOG_IROOT;
	data = encode48(data, newroot);
	data = encode48(data, oldroot);
	log_end(sb, encode48(data, key));
}

void log_iroot(struct sb *sb, block_t newroot, block_t oldroot)
{
	unsigned char *data = log_begin(sb, 19);
	*data++ = LOG_IROOT;
	data = encode48(data, newroot);
	log_end(sb, encode48(data, oldroot));
}

void log_redirect(struct sb *sb, block_t newblock, block_t oldblock)
{
	unsigned char *data = log_begin(sb, 19);
	*data++ = LOG_REDIRECT;
	data = encode48(data, newblock);
	log_end(sb, encode48(data, oldblock));
}


/* Deferred free list */

int defer_free(struct sb *sb, block_t block, unsigned count)
{
	if (sb->defreepos == sb->defreetop) {
		struct page *page = alloc_page(GFP_NOFS);
		link_add(page_link(page), &sb->defree);
		sb->defreepos = page_address(page);
		sb->defreetop = page_address(page) + PAGE_SIZE;
	}
	*sb->defreepos++ = (extent_t){ .block = block, .count = count };
	return 0;
}

void retire_defree(struct sb *sb)
{
	struct link *head = &sb->defree;
	while (!link_empty(head)) {
		struct page *page = link_entry(head->next, struct page, private);
		extent_t *vec = page_address(page);
		printf("free extents: ");
		for (; vec < sb->defreepos; vec++)
			bfree(sb, vec->block, vec->count);
		printf("\n");
		link_del_next(head);
		__free_page(page);
	}
	sb->defreepos = sb->defreetop = NULL;
}

void init_defree(struct sb *sb)
{
	init_link_head(&sb->defree);
	sb->defreepos = sb->defreetop = NULL;
}

void destroy_defree(struct sb *sb)
{
	struct link *head = &sb->defree;
	if (!link_empty(head))
		warn("defree is not empty");
	/* Is this needed? */
	while (!link_empty(head)) {
		struct page *page = link_entry(head->next, struct page, private);
		link_del_next(head);
		__free_page(page);
	}
}
