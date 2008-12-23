/*
 * File index btree leaf operations
 *
 * Original copyright (c) 2008 Daniel Phillips <phillips@phunq.net>
 * Licensed under the GPL version 3
 *
 * By contributing changes to this file you grant the original copyright holder
 * the right to distribute those changes under any license.
 */

#include "tux3.h"

#ifndef trace
#define trace trace_on
#endif

/*
 * Leaf index format
 *
 * A leaf has a small header followed by a table of extents.  A two level
 * index grows down from the top of the leaf towards the top of the extent
 * table.  The index maps each unique logical address in the leaf to one or
 * more extents beginning at that address.
 *
 * The top level index is a table of groups of entries all having the same
 * high 24 bits of logical address which is only stored once, along with the
 * 8 bit count of entries in the group.  Since there can be more than 256
 * entries at the same logical address, there could be more than one group
 * with the same logical address.  The group count is used both to know the
 * number of entries in the group and to find the beginning of the entry table
 * for a given group, by adding up the sizes of the proceeding groups.
 *
 * The 8 bit entry limit limits the number of different versions at the same
 * logical address to 255.  For now.
 *
 * The second level entry tables are stored end to end in reverse immediately
 * below the groups table, also stored in reverse.  Each entry has the low 24
 * bits of the logical address and the 8 bit 'limit' offset of the last extent
 * for that logical address, measuring from the first extent for the group in
 * units of extent size.  The limit is used rather than an offset so that the
 * final offset is the count of extents in the group, which is summed up to
 * locate the first extent for the group in the extent table.  The difference
 * between and entry limit and the limit of its predecessor gives the count of
 * extents for the logical address specified by the entry.
 *
 * At the top level of a very large or very sparse btree it is likely that the
 * group table will be relatively larger, up to the same size as all the entry
 * tables.  This does not matter much in terms of overall btree bulk.  A few
 * levels down the logical address space will have been split to the point
 * where most entries in a leaf fit into one entry table.
 *
 * This leaf indexing scheme has some obscure boundary conditions, such as
 * the zeroth entry of a group having no predecessor and thus needing to have
 * a special check to supply zero as the preceding limit.  Inserting and
 * deleting are fairly involved and subtle.  But the space required to index
 * extents in a deep btree is reduced considerably, which is compelling.  In
 * the end, the indexing scheme provides access to a simple linear table of
 * extents and a count, so there is little impact on the specialized methods
 * that operate on those extents due to the complexity of the indexing scheme.
 * The lookup operation on this index is very efficient.  Each level of the
 * index is suited to binary search.  A sequence of inserts in ascending order
 * in the same group requires no existing entries to be relocated, the reason
 * the entry list is stored in reverse.
 */

static inline struct dleaf *to_dleaf(vleaf *leaf)
{
	return leaf;
}

int dleaf_init(struct btree *btree, vleaf *leaf)
{
	if (!leaf)
		return -1;
	*to_dleaf(leaf) = (struct dleaf){
		.magic = to_be_u16(0x1eaf),
		.free = to_be_u16(sizeof(struct dleaf)),
		.used = to_be_u16(btree->sb->blocksize) };
	return 0;
}

static int dleaf_sniff(struct btree *btree, vleaf *leaf)
{
	return from_be_u16(to_dleaf(leaf)->magic) == 0x1eaf;
}

unsigned dleaf_free(struct btree *btree, vleaf *leaf)
{
	return from_be_u16(to_dleaf(leaf)->used) - from_be_u16(to_dleaf(leaf)->free);
}

unsigned dleaf_need(struct btree *btree, struct dleaf *leaf)
{
	return btree->sb->blocksize - dleaf_free(btree, leaf) - sizeof(struct dleaf);
}

static int dleaf_free2(struct btree *btree, void *vleaf)
{
	struct dleaf *leaf = vleaf;
	struct group *gdict = (void *)leaf + btree->sb->blocksize, *gstop = gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)gstop, *entry = edict;
	struct diskextent *extents = leaf->table;
	for (struct group *group = gdict; group-- > gstop;)
		extents += entry_limit(entry -= group_count(group));
	return (void *)entry - (void *)extents;
}

static inline tuxkey_t get_index(struct group *group, struct entry *entry)
{
	return ((tuxkey_t)group_keyhi(group) << 24) | entry_keylo(entry);
}

void dleaf_dump(struct btree *btree, vleaf *vleaf)
{
	unsigned blocksize = btree->sb->blocksize;
	struct dleaf *leaf = vleaf;
	struct group *gdict = (void *)leaf + blocksize, *gbase = --gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)(gbase + 1), *entry = edict;
	struct diskextent *extents = leaf->table;

	printf("%i entry groups:\n", dleaf_groups(leaf));
	for (struct group *group = gdict; group > gbase; group--) {
		printf("  %ti/%i:", gdict - group, group_count(group));
		//printf(" [%i]", extents - leaf->table);
		struct entry *ebase = entry - group_count(group);
		while (entry > ebase) {
			--entry;
			unsigned offset = entry == edict - 1 ? 0 : entry_limit(entry + 1);
			int count = entry_limit(entry) - offset;
			printf(" %Lx =>", (L)get_index(group, entry));
			//printf(" %p (%i)", entry, entry_limit(entry));
			if (count < 0)
				printf(" <corrupt>");
			else for (int i = 0; i < count; i++) {
				struct diskextent extent = extents[offset + i];
				printf(" %Lx", (L)extent_block(extent));
				if (extent_count(extent))
					printf("/%x", extent_count(extent));
			}
			//printf(" {%u}", entry_limit(entry));
			printf(";");
		}
		printf("\n");
		extents += entry_limit(entry);
		edict -= group_count(group);
	}
}

/* userland only */
int dleaf_check(struct btree *btree, struct dleaf *leaf)
{
	struct group *gdict = (void *)leaf + btree->sb->blocksize, *gstop = gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)gstop, *entry = edict;
	struct diskextent *extents = leaf->table;
	unsigned excount = 0, encount = 0;
	char *why;

	for (struct group *group = gdict - 1; group >= gstop; group--) {
		entry -= group_count(group);
		excount += entry_limit(entry);
		encount += group_count(group);
	}
	//printf("encount = %i, excount = %i, \n", encount, excount);
	why = "used count wrong";
	if (from_be_u16(leaf->used) != (void *)(edict - encount) - (void *)leaf)
		goto eek;
	why = "free count wrong";
	if (from_be_u16(leaf->free) != (void *)(extents + excount) - (void *)leaf)
		goto eek;
	why = "free check mismatch";
	if (from_be_u16(leaf->used) - from_be_u16(leaf->free) != dleaf_free2(btree, leaf))
		goto eek;
	return 0;
eek:
	printf("free %i, used %i\n", from_be_u16(leaf->free), from_be_u16(leaf->used));
	printf("%s!\n", why);
	return -1;
}

int dleaf_split_at(vleaf *from, vleaf *into, struct entry *entry, unsigned blocksize)
{
	struct dleaf *leaf = from, *leaf2 = into;
	unsigned groups = dleaf_groups(leaf), groups2;
	struct group *gdict = from + blocksize, *gbase = gdict - groups;
	struct entry *edict = (void *)gbase, *ebase = (void *)leaf + from_be_u16(leaf->used);
	unsigned recount = 0, grsplit = 0, exsplit = 0;
	unsigned entries = edict - ebase, split = edict - 1 - entry;

	printf("split %p into %p at %x\n", leaf, leaf2, split);
	if (!groups)
		return 0;
	assert(ebase <= entry && entry < edict);
	assert(split < entries);
	for (struct group *group = gdict - 1; group >= gbase; group--, grsplit++) {
		if (recount + group_count(group) > split)
			break;
		edict -= group_count(group);
		exsplit += entry_limit(edict);
		recount += group_count(group);
	}

	/* have to split a group? */
	unsigned cut = split - recount;
	if (cut)
		exsplit += entry_limit(edict - cut);
	edict = (void *)gbase; /* restore it */
	printf("split %i entries at group %i, entry %x\n", entries, grsplit, cut);
	printf("split extents at %i\n", exsplit);
	/* copy extents */
	unsigned size = from + from_be_u16(leaf->free) - (void *)(leaf->table + exsplit);
	memcpy(leaf2->table, leaf->table + exsplit, size);

	/* copy groups */
	struct group *gdict2 = (void *)leaf2 + blocksize;
	set_dleaf_groups(leaf2, groups2 = (groups - grsplit));
	veccopy(gdict2 - dleaf_groups(leaf2), gbase, dleaf_groups(leaf2));
	inc_group_count(gdict2 - 1, -cut);
	set_dleaf_groups(leaf, groups = (grsplit + !!cut));
	gbase = gdict - groups;
	if (cut)
		set_group_count(gdict - groups, cut);

	/* copy entries */
	struct entry *edict2 = (void *)(gdict2 - groups2);

	assert((struct entry *)((void *)leaf + from_be_u16(leaf->used)) == edict - entries);

	unsigned encopy = entries - split;
	veccopy(edict2 - encopy, ebase, encopy);
	if (cut)
		for (int i = 1; i <= group_count((gdict2 - 1)); i++)
			inc_entry_limit(edict2 - i, -entry_limit(edict - split));
	vecmove(gdict - groups - split, edict - split, split);

	/* clean up */
	leaf->free = to_be_u16((void *)(leaf->table + exsplit) - from);
	leaf->used = to_be_u16((void *)(gbase - split) - from);
	leaf2->free = to_be_u16((void *)leaf->table + size - from);
	leaf2->used = to_be_u16((void *)(gdict - groups2 - encopy) - from);
	memset(from + from_be_u16(leaf->free), 0, from_be_u16(leaf->used) - from_be_u16(leaf->free));
	return groups2;
}

/*
 * Split dleaf at middle in terms of entries, may be unbalanced in extents.
 * Not used for now because we do the splits by hand in filemap.c
 */
static tuxkey_t dleaf_split(struct btree *btree, tuxkey_t key, vleaf *from, vleaf *into)
{
	struct dleaf *leaf = to_dleaf(from), *leaf2 = to_dleaf(into);
	assert(dleaf_sniff(btree, from));
	unsigned blocksize = btree->sb->blocksize;
	struct group *gdict = from + blocksize, *gbase = gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)gbase;
	struct entry *ebase = (void *)leaf + from_be_u16(leaf->used);
	unsigned entries = edict - ebase;
	unsigned groups2 = dleaf_split_at(from, into, edict - entries / 2, blocksize);
	struct group *gdict2 = (void *)leaf2 + blocksize;
	return get_index(gdict2 - 1, (struct entry *)(gdict2 - groups2) - 1);
}

void dleaf_merge(struct btree *btree, struct dleaf *leaf, struct dleaf *from)
{
	struct group *gdict = (void *)leaf + btree->sb->blocksize, *gbase = gdict - dleaf_groups(leaf);
	struct entry *edict = (void *)gbase;
	printf("merge %p into %p\n", from, leaf);
	//assert(dleaf_need(from) <= dleaf_free(leaf));

	/* append extents */
	unsigned size = from_be_u16(from->free) - sizeof(struct dleaf);
	memcpy((void *)leaf + from_be_u16(leaf->free), from->table, size);
	leaf->free = to_be_u16(from_be_u16(leaf->free) + size);

	/* merge last group (lowest) with first of from (highest)? */
	struct group *gdict2 = (void *)from + btree->sb->blocksize;
	int uncut = dleaf_groups(leaf) && dleaf_groups(from) && (group_keyhi(gdict2 - 1) == group_keyhi(gbase));

	/* make space and append groups except for possibly merged group */
	unsigned addgroups = dleaf_groups(from) - uncut;
	struct group *gbase2 = gdict2 - dleaf_groups(from);
	struct entry *ebase2 = (void *)from + from_be_u16(from->used);
	struct entry *ebase = (void *)leaf + from_be_u16(leaf->used);
	vecmove(ebase - addgroups, ebase, edict - ebase);
	veccopy(gbase -= addgroups, gbase2, addgroups);
	ebase -= addgroups;
	if (uncut)
		inc_group_count(gbase + addgroups, group_count(gdict2 - 1));
	inc_dleaf_groups(leaf, addgroups);

	/* append entries */
	size = (void *)gbase2 - (void *)ebase2;
	memcpy((void *)ebase - size, ebase2, size);
	leaf->used = to_be_u16((void *)ebase - size - (void *)leaf);

	/* adjust entry limits for merged group */
	if (uncut)
		for (int i = 1; i <= group_count((gdict2 - 1)); i++)
			inc_entry_limit(ebase - i, entry_limit(ebase));
}

/*
 * dleaf format and dwalk structure
 *
 *         min address +--------------------------+
 *                     |     dleaf header         |
 *                   | | extent <0> (gr 0, ent 0) | __ walk->exbase
 * growing downwards | | extent <0> (gr 1, ent 0) | __ walk->extent
 *                   | | extent <1> (gr 1, ent 1) | __ walk->exstop
 *                   V | extent <2> (gr 1, ent 2) |
 *                     |                          |
 *                     |        .......           |
 *                     |                          | __ walk->estop
 *                     | entry <2> (gr 1)         |
 *                     | entry <1> (gr 1)         | __ walk->entry
 *                   ^ | entry <0> (gr 1)         |
 *                   | | entry <0> (gr 0)         | __ walk->group,walk->gstop
 * growing upwards   | | group <1>                |
 *                   | | group <0>                |
 *         max address +--------------------------+ __ walk->gdict
 *
 * The above is dleaf format, and now dwalk_next() was called 2 times.
 *
 *      ->gdict is the end of dleaf.
 *      ->group is the current group (group <1>)
 *      ->gstop is the last group in this dleaf
 *      ->entry is the current entry (entry <0> (gr 1))
 *      ->estop is the last entry in current group
 *      ->exbase is the first extent in current group
 *      ->extent is the current extent (extent <1> (gr1, ent 1)).
 *      ->exstop is the first extent in next entry.
 *        (I.e. the address that dwalk_next() has to update to next entry.
 *        If there is no next, it will stop with ->extent == ->exstop.)
 */

/* FIXME: current code is assuming the entry has only one extent. */

/* The first extent in dleaf */
static int dwalk_first(struct dwalk *walk)
{
	return walk->leaf->table == walk->extent;
}

/* The end of extent in dleaf */
int dwalk_end(struct dwalk *walk)
{
	return walk->extent == walk->exstop;
}

tuxkey_t dwalk_index(struct dwalk *walk)
{
	return get_index(walk->group, walk->entry);
}

block_t dwalk_block(struct dwalk *walk)
{
	return extent_block(*walk->extent);
}

unsigned dwalk_count(struct dwalk *walk)
{
	return extent_count(*walk->extent);
}

/* unused */
void dwalk_dump(struct dwalk *walk)
{
	if (walk->leaf->table == walk->exstop) {
		trace_on("empty leaf");
		return;
	}
	if (dwalk_end(walk)) {
		trace_on("end of extent");
		return;
	}
	struct diskextent *entry_exbase;
	if (walk->entry + 1 == walk->estop + group_count(walk->group))
		entry_exbase = walk->exbase;
	else
		entry_exbase = walk->exbase + entry_limit(walk->entry + 1);
	trace_on("leaf %p", walk->leaf);
	trace_on("group %tu/%tu", (walk->gdict - walk->group) - 1, walk->gdict - walk->gstop);
	trace_on("entry %tu/%u", group_count(walk->group) - (walk->entry - walk->estop) - 1, group_count(walk->group));
	trace_on("extent %tu/%tu", walk->extent - entry_exbase, walk->exstop - entry_exbase);
}

static void dwalk_check(struct dwalk *walk)
{
	if (!dleaf_groups(walk->leaf)) {
		assert(walk->group == walk->gstop);
		assert(walk->entry == walk->estop);
		assert(walk->exbase == walk->extent);
		assert(walk->extent == walk->exstop);
		assert(walk->leaf->table == walk->exstop);
	} else if (dwalk_end(walk)) {
		assert(walk->group == walk->gstop);
		assert(walk->entry == walk->estop);
		assert(walk->exbase < walk->extent);
		assert(walk->extent == walk->exstop);
	} else {
		assert(walk->group >= walk->gstop);
		assert(walk->entry >= walk->estop);
		assert(walk->exbase <= walk->extent);
		assert(walk->extent < walk->exstop);
	}
}

/* Set the cursor to next extent */
int dwalk_next(struct dwalk *walk)
{
	trace(" ");
	/* last extent of this dleaf, or empty dleaf */
	if (dwalk_end(walk))
		return 0;
	walk->extent++;
	if (walk->extent == walk->exstop) {
		if (walk->entry == walk->estop) {
			if (walk->group == walk->gstop)
				return 0;
			walk->group--;
			walk->exbase += entry_limit(walk->estop);
			walk->estop -= group_count(walk->group);
		}
		walk->entry--;
		walk->exstop = walk->exbase + entry_limit(walk->entry);
	}
	dwalk_check(walk);
	return 1;
}

/* Back to the previous extent. (i.e. rewind the previous dwalk_next()) */
int dwalk_back(struct dwalk *walk)
{
	trace(" ");
	/* first extent of this dleaf, or empty dleaf */
	if (dwalk_first(walk))
		return 0;
	struct diskextent *entry_exbase;
	if (walk->entry + 1 == walk->estop + group_count(walk->group))
		entry_exbase = walk->exbase;
	else
		entry_exbase = walk->exbase + entry_limit(walk->entry + 1);
	walk->extent--;
	if (walk->extent < entry_exbase) {
		if (walk->extent < walk->exbase) {
			if (walk->group == walk->gdict)
				return 1;
			walk->group++;
			walk->estop = walk->entry + 1;
			walk->exbase -= entry_limit(walk->entry + 1);
		}
		walk->entry++;
		walk->exstop = walk->exbase + entry_limit(walk->entry);
	}
	dwalk_check(walk);
	return 1;
}

/*
 * Probe the extent position with key. If not found, position is next
 * extent of key.  If probed all extents return 0, otherwise return 1
 * (I.e. current extent is valid. IOW, !dwalk_end()).
 */
int dwalk_probe(struct dleaf *leaf, unsigned blocksize, struct dwalk *walk, tuxkey_t key)
{
	trace("probe for 0x%Lx", (L)key);
	unsigned keylo = key & 0xffffff, keyhi = key >> 24;

	walk->leaf = leaf;
	walk->gdict = (void *)leaf + blocksize;
	walk->gstop = walk->gdict - dleaf_groups(leaf);
	walk->group = walk->gdict;
	walk->estop = (struct entry *)walk->gstop;
	walk->exbase = leaf->table;
	if (!dleaf_groups(leaf)) {
		/* dwalk_first() and dwalk_end() will return true */
		walk->entry = (struct entry *)walk->gstop;
		walk->extent = leaf->table;
		walk->exstop = leaf->table;
		dwalk_check(walk);
		return 0;
	}

	while (walk->group > walk->gstop) {
		walk->group--;
		walk->entry = walk->estop - 1;
		walk->estop -= group_count(walk->group);
		if (group_keyhi(walk->group) > keyhi)
			goto no_group;
		if (group_keyhi(walk->group) == keyhi) {
			if (entry_keylo(walk->entry) > keylo)
				goto no_group;
			if (walk->group == walk->gstop)
				goto probe_entry;
			if (group_keyhi(walk->group - 1) > keyhi)
				goto probe_entry;
			if (entry_keylo(walk->estop - 1) > keylo)
				goto probe_entry;
		}
		walk->exbase += entry_limit(walk->estop);
	}
	/* There is no group after this key */
	walk->entry = walk->estop;
	walk->exstop = walk->exbase;
	walk->extent = walk->exbase;
	walk->exbase = walk->exbase - entry_limit(walk->estop);
	dwalk_check(walk);
	return 0;

no_group:
	/* There is no interesting group, set first extent in this group */
	walk->extent = walk->exbase;
	walk->exstop = walk->exbase + entry_limit(walk->entry);
	dwalk_check(walk);
	return 1;

probe_entry:
	/* There is interesting group, next is probe interesting entry */
	walk->extent = walk->exbase;
	walk->exstop = walk->exbase + entry_limit(walk->entry);
	while (walk->entry > walk->estop) {
		if (entry_keylo(walk->entry - 1) > keylo)
			break;
		walk->entry--;
		walk->extent = walk->exstop;
		walk->exstop = walk->exbase + entry_limit(walk->entry);
	}
	/* Now, entry has the nearest keylo (<= key), probe extent */
	/* FIXME: this is assuming the entry has only one extent */
	if (key < dwalk_index(walk) + dwalk_count(walk))
		return 1;
	/* This entry didn't have the target extent, set next entry */
	dwalk_next(walk);
	return !dwalk_end(walk);
}

int dwalk_mock(struct dwalk *walk, tuxkey_t index, struct diskextent extent)
{
	if (!dleaf_groups(walk->leaf) || walk->entry == walk->estop || dwalk_index(walk) != index) {
		trace("add entry 0x%Lx", (L)index);
		unsigned keylo = index & 0xffffff, keyhi = index >> 24;
		if (!walk->mock.groups || group_keyhi(&walk->mock.group) != keyhi || group_count(&walk->mock.group) >= MAX_GROUP_ENTRIES) {
			trace("add group %i", walk->mock.groups);
			walk->exbase += entry_limit(&walk->mock.entry);
			walk->mock.group = make_group(keyhi, 0);
			walk->mock.used -= sizeof(struct group);
			walk->mock.groups++;
		}
		walk->mock.used -= sizeof(struct entry);
		walk->mock.entry = make_entry(keylo, walk->extent - walk->exbase);
		inc_group_count(&walk->mock.group, 1);
	}
	trace("add extent 0x%Lx => 0x%Lx/%x", (L)index, (L)extent_block(extent), extent_count(extent));
	walk->mock.free += sizeof(*walk->extent);
	walk->extent++;
	inc_entry_limit(&walk->mock.entry, 1);
	return 0;
}

/* This removes extents >= this extent. (cursor position is dwalk_end()). */
void dwalk_chop(struct dwalk *walk)
{
	trace(" ");
	if (dwalk_end(walk))
		return;

	struct dleaf *leaf = walk->leaf;
	if (dwalk_first(walk)) {
		unsigned blocksize = (void *)walk->gdict - (void *)leaf;
		set_dleaf_groups(leaf, 0);
		leaf->free = to_be_u16(sizeof(struct dleaf));
		leaf->used = to_be_u16(blocksize);
		/* Initialize dwalk state */
		dwalk_probe(leaf, blocksize, walk, 0);
		return;
	}

	/* This extent is first extent on this group, remove this group too */
	if (walk->exbase == walk->extent)
		dwalk_back(walk);

	struct entry *ebase = walk->estop + group_count(walk->group);
	void *entry = walk->entry;
	set_dleaf_groups(leaf, walk->gdict - walk->group);
	set_group_count(walk->group, ebase - walk->entry);
	entry += (void *)walk->group - (void *)walk->gstop;
	memmove(entry, walk->entry, (void *)walk->gstop - (void *)walk->entry);
	walk->estop = walk->entry = entry;
	walk->gstop = walk->group;
	walk->exstop = walk->exbase + entry_limit(walk->entry);
	walk->extent = walk->exstop;
	leaf->free = to_be_u16((void *)walk->exstop - (void *)leaf);
	leaf->used = to_be_u16((void *)walk->estop - (void *)leaf);
	dwalk_check(walk);
}

/*
 * Add extent to dleaf. This can use only if dwalk_end() is true.
 * Note, dwalk state is invalid after this.  (I.e. it can be used only
 * for dwalk_add())
 */
int dwalk_add(struct dwalk *walk, tuxkey_t index, struct diskextent extent)
{
	struct dleaf *leaf = walk->leaf;
	unsigned groups = dleaf_groups(leaf);
	unsigned free = from_be_u16(leaf->free);
	unsigned used = from_be_u16(leaf->used);

	/* FIXME: assume entry has only one extent */
	assert(!groups || dwalk_index(walk) != index);

	trace("group %ti/%i", walk->gstop + groups - 1 - walk->group, groups);
	if (!groups || dwalk_index(walk) != index) {
		trace("add entry 0x%Lx", (L)index);
		unsigned keylo = index & 0xffffff, keyhi = index >> 24;
		if (!groups || group_keyhi(walk->group) != keyhi || group_count(walk->group) >= MAX_GROUP_ENTRIES) {
			trace("add group %i", groups);
			/* will it fit? */
			assert(sizeof(*walk->entry) == sizeof(*walk->group));
			assert(free <= used - sizeof(*walk->entry));
			/* move entries down, adjust walk state */
			/* could preplan this to avoid move: need additional pack state */
			vecmove(walk->entry - 1, walk->entry, (struct entry *)walk->group - walk->entry);
			walk->entry--; /* adjust to moved position */
			walk->exbase += groups ? entry_limit(walk->entry) : 0;
			*--walk->group = make_group(keyhi, 0);
			used -= sizeof(*walk->group);
			set_dleaf_groups(leaf, ++groups);
		}
		assert(free <= used - sizeof(*walk->entry));
		used -= sizeof(*walk->entry);
		leaf->used = to_be_u16(used);
		*--walk->entry = make_entry(keylo, walk->extent - walk->exbase);
		inc_group_count(walk->group, 1);
	}
	trace("add extent %ti", walk->extent - leaf->table);
	assert(free + sizeof(*walk->extent) <= used);
	free += sizeof(*walk->extent);
	leaf->free = to_be_u16(free);
	*walk->extent++ = extent;
	inc_entry_limit(walk->entry, 1);

	return 0; // extent out of order??? leaf full???
}

/* Update this extent. The caller have to check new extent isn't overlapping. */
static void dwalk_update(struct dwalk *walk, struct diskextent extent)
{
	*walk->extent = extent;
}

/*
 * Reasons this dleaf truncator sucks:
 *
 * * Does not check for integrity at all so a corrupted leaf can cause overflow
 *   and system corruption.
 *
 * * Assumes all block pointers after the truncation point will be deleted,
 *   which does not hold when versions arrive.
 *
 * * Modifies a group count in the middle of the traversal knowing that it has
 *   already loaded the changed field and will not load it again, fragile.
 *
 * * Does not provide a generic mechanism that can be adapted to other
 *   truncation tasks.
 *
 * But it does truncate so it is getting checked in just for now.
 */
static int dleaf_chop(struct btree *btree, tuxkey_t chop, vleaf *vleaf)
{
	struct sb *sb = btree->sb;
	struct dleaf *leaf = to_dleaf(vleaf);
	struct dwalk walk;

	if (!dwalk_probe(leaf, sb->blocksize, &walk, chop))
		return 0;

	/* Chop this extent partially */
	if (dwalk_index(&walk) < chop) {
		block_t block = dwalk_block(&walk);
		unsigned count = chop - dwalk_index(&walk);

		/* FIXME: err check? */
		(btree->ops->bfree)(sb, block + count, dwalk_count(&walk) - count);
		dwalk_update(&walk, make_extent(block, count));
		if (!dwalk_next(&walk))
			return 1;
	}
	struct dwalk rewind = walk;
	do {
		/* FIXME: err check? */
		(btree->ops->bfree)(sb, dwalk_block(&walk), dwalk_count(&walk));
	} while (dwalk_next(&walk));
	dwalk_chop(&rewind);

	return 1;
}

struct btree_ops dtree_ops = {
	.leaf_sniff = dleaf_sniff,
	.leaf_init = dleaf_init,
	.leaf_dump = dleaf_dump,
	.leaf_split = dleaf_split,
//	.leaf_resize = dleaf_resize,
	.leaf_chop = dleaf_chop,
	.balloc = balloc,
	.bfree = bfree,
};
