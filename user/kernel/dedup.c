#include "tux3.h"
#include <openssl/sha.h>
#ifdef trace
#undef trace
#endif
#define trace trace_off

struct hleaf {
	u16 magic;
	u32 count;
	struct hleaf_entry { u64 key; block_t block; int offset; }entries[];
};

struct bucket {
	u16 count;
	struct bucket_entry { 
		unsigned char sha_hash[SHA_DIGEST_LENGTH];
		block_t block;
		int refcount;
	}entries[];
};

static inline struct hleaf *to_hleaf(vleaf *leaf)
{
	return leaf;
}

int hleaf_init(struct btree *btree,vleaf *leaf)
{
	*to_hleaf(leaf) = (struct hleaf){ .count = 0 , .magic = 0xdade };
	return 0;
}



static void hleaf_btree_init(struct btree *btree)
{
	struct sb *sb = btree->sb;
	btree->entries_per_leaf = (sb->blocksize - offsetof(struct hleaf,entries)) / sizeof(struct hleaf_entry);
}

int hleaf_sniff(struct btree *btree, vleaf *leaf)
{
	return to_hleaf(leaf)->magic == 0xdade;
}

tuxkey_t hleaf_split(struct btree *btree, tuxkey_t key, vleaf *from, vleaf *into)
{
	assert(hleaf_sniff(btree, from));
	struct hleaf *leaf = from;
	unsigned at = leaf->count / 2;
	if (leaf->count && key > leaf->entries[leaf->count - 1].key)
		at = leaf->count;
	unsigned tail = leaf->count - at;
	hleaf_init(btree, into);
	veccopy(to_hleaf(into)->entries, leaf->entries + at, tail);
	to_hleaf(into)->count = tail;
	leaf->count = at;
	return tail ? to_hleaf(into)->entries[0].key : key;
}

unsigned hleaf_free(struct btree *btree, vleaf *leaf)
{
	return btree->entries_per_leaf - to_hleaf(leaf)->count;
}

unsigned hleaf_seek(struct btree *btree, tuxkey_t key, struct hleaf *leaf)
{
	unsigned at = 0;
	while (at < leaf->count && leaf->entries[at].key < key)
		at++;
	return at;
}

void *hleaf_resize(struct btree *btree, tuxkey_t key, vleaf *data, unsigned one)
{
	assert(hleaf_sniff(btree, data));
	struct hleaf *leaf = data;
	unsigned at = hleaf_seek(btree, key, leaf);
	if (at < leaf->count && leaf->entries[at].key == key)
		goto out;
	if (hleaf_free(btree, leaf) < one)
		return NULL;
	vecmove(leaf->entries + at + one, leaf->entries + at, leaf->count++ - at);
out:
	return leaf->entries + at;
}

void hleaf_dump(struct btree *btree, vleaf *data)
{
	struct hleaf *leaf = data;
	struct hleaf_entry *entry, *limit = leaf->entries + leaf->count;
	for (entry = leaf->entries; entry < limit; entry++) {
		printf(" %llu", entry->key); 
		printf(" %llu", entry->block);
	}
	trace(" (%x free)\n", hleaf_free(btree, leaf));
}

block_t bucket_lookup(struct inode *inode, unsigned char *hash)
{
	int k;
	struct bucket_entry *entry;
	block_t block;
	if(inode->refbucket == 0)
		return -1;
	trace("In reference bucket %Lx",(L)inode->refbucket);
	struct buffer_head *buffer = sb_bread(inode->i_sb, inode->refbucket); 
	struct bucket *bck = (struct bucket *)bufdata(buffer);
	for (int i = 0;i < bck->count;i++) {
		entry = bck->entries + i;
		for(k = 0;k < 20;k++) {
			if (hash[k] == entry->sha_hash[k])
				continue;
			else 
				break;
		}
		
		if(k == 20) {
			entry->refcount++;
			block = entry->block;
			trace("Found block %Lx",(L)block);
			brelse_dirty(buffer);
			return block;
		}
		
	}      
	brelse(buffer);
	trace("Not found in reference bucket %Lx", (L)inode->refbucket);
	return -1;
}

void make_hash_entry(struct inode *inode, unsigned char *hash, block_t block)
{
	trace("Making hash entry for block %Lx in writebucket %Lx", (L)block, (L)inode->writebucket);
	struct buffer_head *buffer = sb_bread(inode->i_sb, inode->writebucket);
	struct bucket *bck = (struct bucket *)bufdata(buffer);
	struct bucket_entry *entry;
	entry = bck->entries + bck->count ;
 	entry->refcount = 1; 
 	entry->block = block; 
	memcpy(entry->sha_hash,hash,SHA_DIGEST_LENGTH); 
	bck->count ++; 
	brelse_dirty(buffer);
}

void init_writebucket(struct inode *inode)
{
	int err = inode->btree.ops->balloc(inode->i_sb, 1, &inode->writebucket);
	if(err){
		warn("Failed to initialize write bucket");
		exit(1);
	}
	trace("Initialised new write bucket %Lx", (L)inode->writebucket);
	struct buffer_head *buffer = sb_bread(inode->i_sb, inode->writebucket);
	memset(bufdata(buffer), 0, bufsize(buffer));
	struct bucket *bck = (struct bucket *)bufdata(buffer);
	bck->count = 0;
	brelse_dirty(buffer);
}

block_t handle_collision(struct inode* inode, struct bucket_entry* entry, struct hleaf_entry* temp ,unsigned char* hash, int first)
{
	if(first == 1){
		trace("********* Collision***********");
/* First collision found. */
/*	- Create a new collision bucket. */
/*	- Add the first entry and current entry to collision bucket. */
/*	- Make changes to hleaf_entry to point to collision bucket and offset = -1. */
		block_t col_bucket;
		struct bucket_entry* tmp_entry;
		int err = inode->btree.ops->balloc(inode->i_sb, 1, &col_bucket);
		if(err)
			warn("Collision bucket not initialized");
		trace("Collision bucket = %Lx",(L)col_bucket);
		struct buffer_head *buf = sb_bread(inode->i_sb, col_bucket);
		memset(bufdata(buf), 0, bufsize(buf));
		struct bucket *col_bck = (struct bucket *)bufdata(buf);
		col_bck->count = 2;
		/* Make entries for already present entry */
		tmp_entry = col_bck->entries;
		memcpy(tmp_entry->sha_hash,entry->sha_hash,SHA_DIGEST_LENGTH); 
		tmp_entry->block = temp->block;
		tmp_entry->refcount = temp->offset;/* Using the refcount field of the bucket entry for offsets in case of col. buckets */
		tmp_entry = col_bck->entries + 1;
		/* Making new entry */
		memcpy(tmp_entry->sha_hash,hash,SHA_DIGEST_LENGTH); 
		struct buffer_head *wb_buf = sb_bread(inode->i_sb, inode->writebucket);
		struct bucket *wb_bck = (struct bucket *)bufdata(wb_buf);
		u16 count = wb_bck->count;
		int flag = 0;
		if(count >= inode->i_sb->entries_per_bucket) {		
			brelse_dirty(wb_buf);
			init_writebucket(inode);
			count = 0;
			flag = 1;
		}
		tmp_entry->block = inode->writebucket; 
		tmp_entry->refcount = count;
		temp->block = col_bucket;
		temp->offset = -1;
		if (flag != 1)
			brelse(wb_buf);
		brelse_dirty(buf);
		return 0;
	}else{
		int k;
		trace("64bit match and offset == -1");
		block_t bckno = temp->block;
		struct buffer_head *buffer = sb_bread(inode->i_sb, bckno);
		struct bucket *bck =(struct bucket *) bufdata(buffer);
		struct bucket_entry *entry;
		for(int i = 0; i < bck->count; i++) {
			entry = bck->entries + i;
			for(k = 0;k < 20;k++) {
				if (hash[k] == entry->sha_hash[k])
					continue;
				else 
					break;
			}
			if (k == 20) {
				trace("64bit match and offset == -1 and match found in col bck");
				struct buffer_head *buf = sb_bread(inode->i_sb, entry->block);
				struct bucket *org_bck =(struct bucket *) bufdata(buf);
				struct bucket_entry *org_entry;
				block_t ret_blk;
				org_entry = org_bck->entries + entry->refcount;
				org_entry->refcount++;
				ret_blk = org_entry->block;
				brelse_dirty(buf);
				brelse(buffer);
				return ret_blk;
			}
		}
		trace("Inside - 64bit match and offset == -1 and no match in col bck");
		memcpy(entry->sha_hash,hash,SHA_DIGEST_LENGTH); 
		entry->block = inode->writebucket;
		bck->count++;
		struct buffer_head *wb_buf = sb_bread(inode->i_sb, inode->writebucket);
		struct bucket *wb_bck = (struct bucket *)bufdata(wb_buf);
		u16 count = wb_bck->count;
		int flag = 0;
		if(count >= inode->i_sb->entries_per_bucket) {		
			brelse_dirty(wb_buf);
			init_writebucket(inode);
			count = 0;
			flag = 1;
		}
		entry->refcount = wb_bck->count;
		brelse_dirty(buffer);
		if (flag != 1)
			brelse(wb_buf);
		return -1;
	}
	

}

block_t htree_lookup(struct inode *inode, struct btree *btree, unsigned char *hash)
{
	int k;
	u64 offset;
	block_t bckno;
	u64 sh;
	for(int k=0; k<8; k++) {
		sh = sh << 8;
		sh = sh | (hash[k]);
	}
	struct cursor *cursor = alloc_cursor(btree,20);
	if (!cursor)
		return -ENOMEM;
	down_write(&btree->lock);
	tuxkey_t key = sh;
	unsigned at;
	if (probe(btree, key, cursor))
		error("probe for %Lx failed", (L)key);
	
	at = hleaf_seek(btree, key, bufdata(cursor_leafbuf(cursor))); 

	struct hleaf *leaf = (struct hleaf *)bufdata(cursor_leafbuf(cursor));
	struct hleaf_entry *temp = leaf->entries + at;
	
	if(temp->key == sh && temp->offset != -1) {
		block_t block;
		offset = temp->offset;
		bckno = temp->block;
		struct buffer_head *buffer = sb_bread(inode->i_sb, bckno);
		struct bucket *bck =(struct bucket *) bufdata(buffer);
		struct bucket_entry *entry;
		entry = bck->entries + offset;
		for(k = 0;k < 20;k++) {
			if (hash[k] == entry->sha_hash[k])
				continue;
			else 
				break;
		}
		trace("64bit match and offset != -1");
		if (k == 20) {
			entry->refcount++;
			block = entry->block;
			inode->refbucket = bckno;
			trace("Found entry in tree");
			trace("Changed reference bucket to %Lx", (L)bckno);
			brelse_dirty(buffer);
			release_cursor(cursor);
			free(cursor);
			up_write(&btree->lock);
			trace("64bit match and offset != -1 and now complete 160bit match found");
			return block;
		} else {
			if(!handle_collision(inode, entry, temp, hash, 1)){
				brelse(buffer);
				mark_buffer_dirty(cursor_leafbuf(cursor));
				release_cursor(cursor);
				free_cursor(cursor);
				up_write(&btree->lock);
				return -1;
			}
		}
			
	     	
	}	
	else if (temp->key == sh && temp->offset == -1) {
		block_t coll;
		coll = handle_collision(inode, NULL, temp, hash, 0);
		mark_buffer_dirty(cursor_leafbuf(cursor));
		release_cursor(cursor);
		free_cursor(cursor);
		up_write(&btree->lock);
		return coll;	
	}    
	trace("Entry not found in tree");
	struct hleaf_entry *entry = (struct hleaf_entry *)tree_expand(btree, key, 1, cursor);
	if(inode->writebucket == 0)
		init_writebucket(inode);
	struct buffer_head *buffer = sb_bread(inode->i_sb, inode->writebucket);
        struct bucket *bck = (struct bucket *)bufdata(buffer);
        u16 count = bck->count;
	int flag = 0;
        if(count >= inode->i_sb->entries_per_bucket) {		
		brelse_dirty(buffer);
		init_writebucket(inode);
		count = 0;
		flag = 1;
       	}
	entry->block = inode->writebucket; 
	entry->key = key;
	entry->offset = count;
	if (flag != 1)
		brelse(buffer);
	mark_buffer_dirty(cursor_leafbuf(cursor));
	release_cursor(cursor);
	free_cursor(cursor);
	up_write(&btree->lock);
	return -1; 
}

/* ALGORITHM FOR DEDUPLICATION */
/* 1. Perform hash lookup in the current reference bucket. */
/* 2. If a match is found,  */
/*      -Increment refernce count for that entry */
/* 	-Return the duplicate block number to be mapped */
/* 3.Else, */
/* 	-Performed lookup in the hash tree to get the corresponding bucket number. */
/* 	-If an entry is found in the hash tree, then the current reference bucket is written back and */
/* 	 the bucket in the matched entry is loaded into memory as the current */
/* 	 read bucket.  */
/* 	-Else, */
/* 	     -an entry for the particular block is added to the hash tree */
/* 	      and an entry is added in the current writebucket with reference count as 1. */

block_t hash_lookup(struct inode *inode, unsigned char *hash)
{
	block_t block = -1;
	if((block = bucket_lookup(inode, hash)) == -1) {
		block = htree_lookup(inode, &inode->i_sb->htree, hash);
	}   
	return block;
}


struct btree_ops htree_ops = {
	.btree_init = hleaf_btree_init,
	.leaf_init = hleaf_init,
	.leaf_split = hleaf_split,
	.leaf_resize = hleaf_resize,
	.leaf_sniff = hleaf_sniff,
	.leaf_free = hleaf_free,
	.balloc = balloc,
};
