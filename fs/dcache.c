/*
 * fs/dcache.c
 *
 * Complete reimplementation
 * (C) 1997 Thomas Schoebel-Theuer,
 * with heavy changes by Linus Torvalds
 */

/*
 * Notes on the allocation strategy:
 *
 * The dcache is a master of the icache - whenever a dcache entry
 * exists, the inode will always exist. "iput()" is done either when
 * the dcache entry is deleted or garbage collected.
 */

#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/hash.h>
#include <linux/cache.h>
#include <linux/module.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <asm/uaccess.h>
#include <linux/security.h>
#include <linux/seqlock.h>
#include <linux/swap.h>
#include <linux/bootmem.h>
#include <linux/fs_struct.h>
#include <linux/hardirq.h>
#include <linux/ratelimit.h>
#include <bc/beancounter.h>
#include <bc/dcache.h>
#include "internal.h"

int sysctl_vfs_cache_pressure __read_mostly = 100;
EXPORT_SYMBOL_GPL(sysctl_vfs_cache_pressure);

 __cacheline_aligned_in_smp DEFINE_SPINLOCK(dcache_lock);
__cacheline_aligned_in_smp DEFINE_SEQLOCK(rename_lock);

EXPORT_SYMBOL(dcache_lock);

struct kmem_cache *dentry_cache __read_mostly;

/*
 * This is the single most critical data structure when it comes
 * to the dcache: the hashtable for lookups. Somebody should try
 * to make this good - I've just made it work.
 *
 * This hash-function tries to avoid losing too many bits of hash
 * information, yet avoid using a prime hash-size or similar.
 */
#define D_HASHBITS     d_hash_shift
#define D_HASHMASK     d_hash_mask

static unsigned int d_hash_mask __read_mostly;
static unsigned int d_hash_shift __read_mostly;
static struct hlist_head *dentry_hashtable __read_mostly;

/* Statistics gathering. */
struct dentry_stat_t dentry_stat = {
	.age_limit = 45,
};

static void __d_free(struct dentry *dentry)
{
	WARN_ON(!list_empty(&dentry->d_alias));
	if (dname_external(dentry))
		kfree(dentry->d_name.name);
	kmem_cache_free(dentry_cache, dentry); 
}

static void d_callback(struct rcu_head *head)
{
	struct dentry * dentry = container_of(head, struct dentry, d_u.d_rcu);
	__d_free(dentry);
}

/*
 * no dcache_lock, please.  The caller must decrement dentry_stat.nr_dentry
 * inside dcache_lock.
 */
static void d_free(struct dentry *dentry)
{
	if (dentry->d_op && dentry->d_op->d_release)
		dentry->d_op->d_release(dentry);
	/* if dentry was never inserted into hash, immediate free is OK */
	if (hlist_unhashed(&dentry->d_hash))
		__d_free(dentry);
	else
		call_rcu(&dentry->d_u.d_rcu, d_callback);
}

/*
 * Release the dentry's inode, using the filesystem
 * d_iput() operation if defined.
 */
static void dentry_iput(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
{
	struct inode *inode = dentry->d_inode;
	if (inode) {
		dentry->d_inode = NULL;
		list_del_init(&dentry->d_alias);
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
		if (!inode->i_nlink)
			fsnotify_inoderemove(inode);
		if (dentry->d_op && dentry->d_op->d_iput)
			dentry->d_op->d_iput(dentry, inode);
		else
			iput(inode);
	} else {
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
	}
}

static unsigned int dcache_time_shift = 32;
static u64 jif_off;

static __init void dcache_time_init(void)
{
	unsigned long jiff;
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 0;
	jiff = timespec_to_jiffies(&ts);
	ts.tv_sec++;
	jiff = timespec_to_jiffies(&ts) - jiff;

	dcache_time_shift = ilog2(jiff);
	jif_off = get_jiffies_64();

	printk("Dcache time values: %lu -> %u , %Lu\n", jiff, dcache_time_shift, (unsigned long long)jif_off);
}

unsigned int dcache_update_time(void)
{
	u64 ctime;

	ctime = (get_jiffies_64() - jif_off) >> dcache_time_shift;
	if (unlikely(ctime > (u64)(unsigned int)-1))
		printk("Strange DC timestamp %Lu %Lu %u -> %Lu\n",
				get_jiffies_64(), jif_off, dcache_time_shift, ctime);
	return ctime;
}

/*
 * dentry_lru_(add|add_tail|del|del_init) must be called with dcache_lock held.
 */
static void dentry_lru_add(struct dentry *dentry)
{
	struct user_beancounter *bc = dentry->d_ub;

	if (ub_dcache_lru_popup)
		dentry->d_lru_time = dcache_update_time();
	list_add(&dentry->d_lru, &dentry->d_sb->s_dentry_lru);
	dentry->d_sb->s_nr_dentry_unused++;
	ub_dcache_insert(bc, dentry->d_lru_time);
	list_add(&dentry->d_bclru, &bc->ub_dentry_lru);
	bc->ub_dentry_unused++;
	dentry_stat.nr_unused++;
}

static void dentry_lru_popup(struct dentry *dentry)
{
	BUG_ON(dentry->d_flags & DCACHE_BCTOP);
	dentry->d_lru_time = dcache_update_time();
	list_move(&dentry->d_bclru, &dentry->d_ub->ub_dentry_lru);
}

static void dentry_lru_add_tail(struct dentry *dentry)
{
	struct user_beancounter *bc = dentry->d_ub;

	list_add_tail(&dentry->d_lru, &dentry->d_sb->s_dentry_lru);
	dentry->d_sb->s_nr_dentry_unused++;
	ub_dcache_insert(bc, 0);
	list_add_tail(&dentry->d_bclru, &bc->ub_dentry_lru);
	bc->ub_dentry_unused++;
	dentry_stat.nr_unused++;
}

static void dentry_lru_del(struct dentry *dentry)
{
	if (!list_empty(&dentry->d_lru)) {
		list_del(&dentry->d_lru);
		dentry->d_sb->s_nr_dentry_unused--;
		list_del(&dentry->d_bclru);
		dentry->d_ub->ub_dentry_unused--;
		dentry_stat.nr_unused--;
	}
}

static void dentry_lru_del_init(struct dentry *dentry)
{
	if (likely(!list_empty(&dentry->d_lru))) {
		list_del_init(&dentry->d_lru);
		dentry->d_sb->s_nr_dentry_unused--;
		list_del(&dentry->d_bclru);
		dentry->d_ub->ub_dentry_unused--;
		dentry_stat.nr_unused--;
	}
}

/**
 * d_kill - kill dentry and return parent
 * @dentry: dentry to kill
 *
 * The dentry must already be unhashed and removed from the LRU.
 *
 * If this is the root of the dentry tree, return NULL.
 */
static struct dentry *d_kill(struct dentry *dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
{
	struct dentry *parent;

	list_del(&dentry->d_u.d_child);
	dentry_stat.nr_dentry--;	/* For d_free, below */

	ub_dcache_uncharge(dentry->d_ub, dentry->d_name.len);
	if (dentry->d_flags & DCACHE_BCTOP)
		list_del(&dentry->d_bclru);

	/*drops the locks, at that point nobody can reach this dentry */
	dentry_iput(dentry);
	if (IS_ROOT(dentry))
		parent = NULL;
	else
		parent = dentry->d_parent;
	d_free(dentry);
	return parent;
}

/* 
 * This is dput
 *
 * This is complicated by the fact that we do not want to put
 * dentries that are no longer on any hash chain on the unused
 * list: we'd much rather just get rid of them immediately.
 *
 * However, that implies that we have to traverse the dentry
 * tree upwards to the parents which might _also_ now be
 * scheduled for deletion (it may have been only waiting for
 * its last child to go away).
 *
 * This tail recursion is done by hand as we don't want to depend
 * on the compiler to always get this right (gcc generally doesn't).
 * Real recursion would eat up our stack space.
 */

/*
 * dput - release a dentry
 * @dentry: dentry to release 
 *
 * Release a dentry. This will drop the usage count and if appropriate
 * call the dentry unlink method as well as removing it from the queues and
 * releasing its resources. If the parent dentries were scheduled for release
 * they too may now get deleted.
 *
 * no dcache lock, please.
 */

void dput_nocache(struct dentry *dentry, int nocache)
{
	if (!dentry)
		return;

repeat:
	if (atomic_read(&dentry->d_count) == 1)
		might_sleep();
	if (!atomic_dec_and_lock(&dentry->d_count, &dcache_lock))
		return;

	spin_lock(&dentry->d_lock);
	if (atomic_read(&dentry->d_count)) {
		spin_unlock(&dentry->d_lock);
		spin_unlock(&dcache_lock);
		return;
	}

	/*
	 * AV: ->d_delete() is _NOT_ allowed to block now.
	 */
	if (dentry->d_op && dentry->d_op->d_delete) {
		if (dentry->d_op->d_delete(dentry))
			goto unhash_it;
	}
	/* Unreachable? Get rid of it */
	if (unlikely(nocache))
		goto unhash_it;
 	if (d_unhashed(dentry))
		goto kill_it;

	if (unlikely(dentry->d_flags & DCACHE_DISCONNECTED))
		goto unhash_it;

  	if (list_empty(&dentry->d_lru)) {
  		dentry->d_flags |= DCACHE_REFERENCED;
		if (dentry->d_flags & DCACHE_BCTOP)
			ub_dcache_clear_owner(dentry);
		dentry_lru_add(dentry);
	} else if (ub_dcache_lru_popup)
		dentry_lru_popup(dentry);

 	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
	return;

unhash_it:
	__d_drop(dentry);
kill_it:
	/* if dentry was on the d_lru list delete it from there */
	dentry_lru_del(dentry);
	dentry = d_kill(dentry);
	if (dentry)
		goto repeat;
}

void dput(struct dentry *dentry)
{
	dput_nocache(dentry, 0);
}

/**
 * d_invalidate - invalidate a dentry
 * @dentry: dentry to invalidate
 *
 * Try to invalidate the dentry if it turns out to be
 * possible. If there are other dentries that can be
 * reached through this one we can't delete it and we
 * return -EBUSY. On success we return 0.
 *
 * no dcache lock.
 */
 
int d_invalidate(struct dentry * dentry)
{
	/*
	 * If it's already been dropped, return OK.
	 */
	spin_lock(&dcache_lock);
	if (d_unhashed(dentry)) {
		spin_unlock(&dcache_lock);
		return 0;
	}
	/*
	 * Check whether to do a partial shrink_dcache
	 * to get rid of unused child entries.
	 */
	if (!list_empty(&dentry->d_subdirs)) {
		spin_unlock(&dcache_lock);
		shrink_dcache_parent(dentry);
		spin_lock(&dcache_lock);
	}

	/*
	 * Somebody else still using it?
	 *
	 * If it's a directory, we can't drop it
	 * for fear of somebody re-populating it
	 * with children (even though dropping it
	 * would make it unreachable from the root,
	 * we might still populate it if it was a
	 * working directory or similar).
	 */
	spin_lock(&dentry->d_lock);
	if (atomic_read(&dentry->d_count) > 1) {
		if (dentry->d_inode && S_ISDIR(dentry->d_inode->i_mode)) {
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			return -EBUSY;
		}
	}

	__d_drop(dentry);
	spin_unlock(&dentry->d_lock);
	spin_unlock(&dcache_lock);
	return 0;
}

/* This should be called _only_ with dcache_lock held */

static inline struct dentry * __dget_locked(struct dentry *dentry)
{
	atomic_inc(&dentry->d_count);
	dentry_lru_del_init(dentry);
	return dentry;
}

struct dentry * dget_locked(struct dentry *dentry)
{
	return __dget_locked(dentry);
}

/**
 * d_find_alias - grab a hashed alias of inode
 * @inode: inode in question
 *
 * If inode has a hashed alias, or is a directory and has any alias,
 * acquire the reference to alias and return it. Otherwise return NULL.
 * Notice that if inode is a directory there can be only one alias and
 * it can be unhashed only if it has no children, or if it is the root
 * of a filesystem.
 *
 * If the inode has an IS_ROOT, DCACHE_DISCONNECTED alias, then prefer
 * any other hashed alias over that.
 */

static struct dentry *__d_find_alias(struct inode *inode)
{
	struct list_head *head, *next, *tmp;
	struct dentry *alias, *discon_alias=NULL;

	head = &inode->i_dentry;
	next = inode->i_dentry.next;
	while (next != head) {
		tmp = next;
		next = tmp->next;
		prefetch(next);
		alias = list_entry(tmp, struct dentry, d_alias);
 		if (S_ISDIR(inode->i_mode) || !d_unhashed(alias)) {
			if (IS_ROOT(alias) &&
			    (alias->d_flags & DCACHE_DISCONNECTED))
				discon_alias = alias;
			else {
				__dget_locked(alias);
				return alias;
			}
		}
	}
	if (discon_alias)
		__dget_locked(discon_alias);
	return discon_alias;
}

struct dentry * d_find_alias(struct inode *inode)
{
	struct dentry *de = NULL;

	if (!list_empty(&inode->i_dentry)) {
		spin_lock(&dcache_lock);
		de = __d_find_alias(inode);
		spin_unlock(&dcache_lock);
	}
	return de;
}

/*
 *	Try to kill dentries associated with this inode.
 * WARNING: you must own a reference to inode.
 */
void d_prune_aliases(struct inode *inode)
{
	struct dentry *dentry;
restart:
	spin_lock(&dcache_lock);
	list_for_each_entry(dentry, &inode->i_dentry, d_alias) {
		spin_lock(&dentry->d_lock);
		if (!atomic_read(&dentry->d_count)) {
			__dget_locked(dentry);
			__d_drop(dentry);
			spin_unlock(&dentry->d_lock);
			spin_unlock(&dcache_lock);
			dput(dentry);
			goto restart;
		}
		spin_unlock(&dentry->d_lock);
	}
	spin_unlock(&dcache_lock);
}

/*
 * Throw away a dentry - free the inode, dput the parent.  This requires that
 * the LRU list has already been removed.
 *
 * Try to prune ancestors as well.  This is necessary to prevent
 * quadratic behavior of shrink_dcache_parent(), but is also expected
 * to be beneficial in reducing dentry cache fragmentation.
 */
static void prune_one_dentry(struct dentry * dentry)
	__releases(dentry->d_lock)
	__releases(dcache_lock)
	__acquires(dcache_lock)
{
	__d_drop(dentry);
	dentry = d_kill(dentry);

	/*
	 * Prune ancestors.  Locking is simpler than in dput(),
	 * because dcache_lock needs to be taken anyway.
	 */
	spin_lock(&dcache_lock);
	while (dentry) {
		if (!atomic_dec_and_lock(&dentry->d_count, &dentry->d_lock))
			return;

		if (dentry->d_op && dentry->d_op->d_delete)
			dentry->d_op->d_delete(dentry);
		dentry_lru_del_init(dentry);
		__d_drop(dentry);
		dentry = d_kill(dentry);
		spin_lock(&dcache_lock);
	}
}

int __shrink_dcache_ub(struct user_beancounter *ub, int count, int popup)
{
	LIST_HEAD(referenced);
	LIST_HEAD(tmp);
	struct dentry *dentry;
	struct super_block *sb = NULL;
	int pruned = 0;
	unsigned int d_time = 0;

	while (!list_empty(&ub->ub_dentry_lru)) {
		dentry = list_entry(ub->ub_dentry_lru.prev,
				struct dentry, d_bclru);

		if (popup && dentry->d_lru_time) {
			if (!d_time)
				d_time = dentry->d_lru_time;
			else if (dentry->d_lru_time - d_time > ub_dcache_time_thresh)
				break;
		}

		spin_lock(&dentry->d_lock);
		if (!popup && (dentry->d_flags & DCACHE_REFERENCED)) {
			dentry->d_flags &= ~DCACHE_REFERENCED;
			list_move(&dentry->d_bclru, &referenced);
		} else
			list_move_tail(&dentry->d_bclru, &tmp);
		spin_unlock(&dentry->d_lock);
		cond_resched_lock(&dcache_lock);

		count--;
		if (!count)
			break;
	}

	while (!list_empty(&tmp)) {
		dentry = list_entry(tmp.prev, struct dentry, d_bclru);
		dentry_lru_del_init(dentry);
		spin_lock(&dentry->d_lock);
		/*
		 * We found an inuse dentry which was not removed from
		 * the LRU because of laziness during lookup.  Do not free
		 * it - just keep it off the LRU list.
		 */
		if (atomic_read(&dentry->d_count)) {
			spin_unlock(&dentry->d_lock);
			continue;
		}

		pruned++;

		/*
		 * Do not prune dentry if the filesystem is being unmounted,
		 * otherwise we could race with shrink_dcache_for_umount() and
		 * end up holding a reference to a dentry while the filesystem
		 * is unmounted.
		 */
		if (dentry->d_sb != sb) {
			if (!down_read_trylock(&dentry->d_sb->s_umount)) {
				spin_unlock(&dentry->d_lock);
				continue;
			}
			if (sb)
				up_read(&sb->s_umount);
			sb = dentry->d_sb;
		}

		prune_one_dentry(dentry);
		/* dentry->d_lock was dropped in prune_one_dentry() */
		cond_resched_lock(&dcache_lock);
	}

	list_splice(&referenced, &ub->ub_dentry_lru);

	ub->ub_dentry_pruned += pruned;

	/* report fake progress if lru isn't empty */
	if (!pruned && !list_empty(&ub->ub_dentry_lru))
		pruned = 1;

	if (sb)
		up_read(&sb->s_umount);

	return pruned;
}

/*
 * Shrink the dentry LRU on a given superblock.
 * @sb   : superblock to shrink dentry LRU.
 * @count: If count is NULL, we prune all dentries on superblock.
 * @flags: If flags is non-zero, we need to do special processing based on
 * which flags are set. This means we don't need to maintain multiple
 * similar copies of this loop.
 */
static void __shrink_dcache_sb(struct super_block *sb, int *count, int flags)
{
	LIST_HEAD(referenced);
	LIST_HEAD(tmp);
	struct dentry *dentry;
	int cnt = 0;

	BUG_ON(!sb);
	BUG_ON((flags & DCACHE_REFERENCED) && count == NULL);
	spin_lock(&dcache_lock);
	if (count != NULL)
		/* called from prune_dcache() and shrink_dcache_parent() */
		cnt = *count;
restart:
	if (count == NULL)
		list_splice_init(&sb->s_dentry_lru, &tmp);
	else {
		while (!list_empty(&sb->s_dentry_lru)) {
			dentry = list_entry(sb->s_dentry_lru.prev,
					struct dentry, d_lru);
			BUG_ON(dentry->d_sb != sb);

			spin_lock(&dentry->d_lock);
			/*
			 * If we are honouring the DCACHE_REFERENCED flag and
			 * the dentry has this flag set, don't free it. Clear
			 * the flag and put it back on the LRU.
			 */
			if ((flags & DCACHE_REFERENCED)
				&& (dentry->d_flags & DCACHE_REFERENCED)) {
				dentry->d_flags &= ~DCACHE_REFERENCED;
				list_move(&dentry->d_lru, &referenced);
				spin_unlock(&dentry->d_lock);
			} else {
				list_move_tail(&dentry->d_lru, &tmp);
				spin_unlock(&dentry->d_lock);
				cnt--;
				if (!cnt)
					break;
			}
			cond_resched_lock(&dcache_lock);
		}
	}
	while (!list_empty(&tmp)) {
		dentry = list_entry(tmp.prev, struct dentry, d_lru);
		dentry_lru_del_init(dentry);
		spin_lock(&dentry->d_lock);
		/*
		 * We found an inuse dentry which was not removed from
		 * the LRU because of laziness during lookup.  Do not free
		 * it - just keep it off the LRU list.
		 */
		if (atomic_read(&dentry->d_count)) {
			spin_unlock(&dentry->d_lock);
			continue;
		}
		prune_one_dentry(dentry);
		/* dentry->d_lock was dropped in prune_one_dentry() */
		cond_resched_lock(&dcache_lock);
	}
	if (count == NULL && !list_empty(&sb->s_dentry_lru))
		goto restart;
	if (count != NULL)
		*count = cnt;
	if (!list_empty(&referenced))
		list_splice(&referenced, &sb->s_dentry_lru);
	spin_unlock(&dcache_lock);
}

/**
 * prune_dcache - shrink the dcache
 * @count: number of entries to try to free
 *
 * Shrink the dcache. This is done when we need more memory, or simply when we
 * need to unmount something (at which point we need to unuse all dentries).
 *
 * This function may fail to free any resources if all the dentries are in use.
 */
static void prune_dcache_rr(int count, gfp_t gfp_mask)
{
	struct user_beancounter *ub;
	int w_count;
	int unused = dentry_stat.nr_unused;
	int prune_ratio;

	if (unused == 0 || count == 0)
		return;
	spin_lock(&dcache_lock);
	if (count >= unused)
		prune_ratio = 1;
	else
		prune_ratio = unused / count;

	rcu_read_lock();
	for_each_top_beancounter(ub) {
		if (!get_beancounter_rcu(ub))
			continue;
		rcu_read_unlock();

		if (prune_ratio != 1)
			w_count = (ub->ub_dentry_unused / prune_ratio) + 1;
		else
			w_count = ub->ub_dentry_unused;

		if (!(gfp_mask & __GFP_REPEAT)) {
			int delta;

			delta = ub->ub_dentry_unused - ub->ub_dcache_threshold;
			if (delta <= 0)
				goto skip;
			if (w_count > delta)
				w_count = delta;
		}

		__shrink_dcache_ub(ub, w_count, 0);

skip:
		rcu_read_lock();
		put_beancounter(ub);
	}
	rcu_read_unlock();

	spin_unlock(&dcache_lock);
}

static void prune_dcache_popup(int count, gfp_t gfp_mask)
{
	spin_lock(&dcache_lock);
	rcu_read_lock();
	while (1) {
		struct user_beancounter *ub;
		unsigned int cnt;

		if (count <= 0)
			break;

		ub = ub_dcache_next();
		if (!ub)
			break;
		rcu_read_unlock();

		cnt = __shrink_dcache_ub(ub, count, 1);
		count -= cnt;

		rcu_read_lock();
		put_beancounter(ub);
	}
	rcu_read_unlock();
	spin_unlock(&dcache_lock);

	/*
	 * As an optimization we do not keep beancounters whose dcache usage is
	 * below threshold on the priority queue. As a result the code above
	 * will not shrink them even if we are really short on memory, which is
	 * not good. So if the caller insists by passing __GFP_REPEAT, let's
	 * reclaim as much as possible by using the RR algorithm.
	 */
	if (count > 0 && (gfp_mask & __GFP_REPEAT))
		prune_dcache_rr(count, gfp_mask);
}

static void prune_dcache(int count, gfp_t gfp_mask)
{
	if (ub_dcache_lru_popup)
		prune_dcache_popup(count, gfp_mask);
	else
		prune_dcache_rr(count, gfp_mask);
}

/**
 * shrink_dcache_sb - shrink dcache for a superblock
 * @sb: superblock
 *
 * Shrink the dcache for the specified super block. This
 * is used to free the dcache before unmounting a file
 * system
 */
void shrink_dcache_sb(struct super_block * sb)
{
	__shrink_dcache_sb(sb, NULL, 0);
}

/*
 * destroy a single subtree of dentries for unmount
 * - see the comments on shrink_dcache_for_umount() for a description of the
 *   locking
 */
static void shrink_dcache_for_umount_subtree(struct dentry *dentry)
{
	struct dentry *parent;
	unsigned detached = 0;

	BUG_ON(!IS_ROOT(dentry));

	/* detach this root from the system */
	spin_lock(&dcache_lock);
	dentry_lru_del_init(dentry);
	__d_drop(dentry);
	spin_unlock(&dcache_lock);

	for (;;) {
		/* descend to the first leaf in the current subtree */
		while (!list_empty(&dentry->d_subdirs)) {
			struct dentry *loop;

			/* this is a branch with children - detach all of them
			 * from the system in one go */
			spin_lock(&dcache_lock);
			list_for_each_entry(loop, &dentry->d_subdirs,
					    d_u.d_child) {
				dentry_lru_del_init(loop);
				__d_drop(loop);
				cond_resched_lock(&dcache_lock);
			}
			spin_unlock(&dcache_lock);

			/* move to the first child */
			dentry = list_entry(dentry->d_subdirs.next,
					    struct dentry, d_u.d_child);
		}

		/* consume the dentries from this leaf up through its parents
		 * until we find one with children or run out altogether */
		do {
			struct inode *inode;

			if (atomic_read(&dentry->d_count) != 0) {
				printk(KERN_ERR
				       "BUG: Dentry %p{i=%lx,n=%s}"
				       " still in use (%d)"
				       " [unmount of %s %s]\n",
				       dentry,
				       dentry->d_inode ?
				       dentry->d_inode->i_ino : 0UL,
				       dentry->d_name.name,
				       atomic_read(&dentry->d_count),
				       dentry->d_sb->s_type->name,
				       dentry->d_sb->s_id);
				BUG();
			}

			if (IS_ROOT(dentry))
				parent = NULL;
			else {
				parent = dentry->d_parent;
				atomic_dec(&parent->d_count);
			}

			list_del(&dentry->d_u.d_child);
			detached++;

			inode = dentry->d_inode;
			if (inode) {
				dentry->d_inode = NULL;
				list_del_init(&dentry->d_alias);
				if (dentry->d_op && dentry->d_op->d_iput)
					dentry->d_op->d_iput(dentry, inode);
				else
					iput(inode);
			}

			ub_dcache_uncharge(dentry->d_ub, dentry->d_name.len);
			if (dentry->d_flags & DCACHE_BCTOP) {
				spin_lock(&dcache_lock);
				list_del(&dentry->d_bclru);
				spin_unlock(&dcache_lock);
			}

			d_free(dentry);

			/* finished when we fall off the top of the tree,
			 * otherwise we ascend to the parent and move to the
			 * next sibling if there is one */
			if (!parent)
				goto out;

			dentry = parent;

		} while (list_empty(&dentry->d_subdirs));

		dentry = list_entry(dentry->d_subdirs.next,
				    struct dentry, d_u.d_child);
	}
out:
	/* several dentries were freed, need to correct nr_dentry */
	spin_lock(&dcache_lock);
	dentry_stat.nr_dentry -= detached;
	spin_unlock(&dcache_lock);
}

/*
 * Unhash all children of the dentry and evict those with zero refcount.
 * This needs to be called from d_delete to make sure that this dentry
 * (which belongs to a directory) can be safely killed.
 */
static void unhash_offsprings(struct dentry *dentry)
{
	struct dentry *loop;
	LIST_HEAD(tmp);

	if (list_empty(&dentry->d_subdirs))
		return;

	list_for_each_entry(loop, &dentry->d_subdirs,
			    d_u.d_child) {
		spin_lock(&loop->d_lock);
		if (d_unhashed(loop)) {
			spin_unlock(&loop->d_lock);
			continue;
		}

		if (atomic_read(&loop->d_count)) {
			__d_drop(loop);
			spin_unlock(&loop->d_lock);
			continue;
		}

		list_move_tail(&loop->d_lru, &tmp);
		spin_unlock(&loop->d_lock);
	}

	while (!list_empty(&tmp)) {
		loop = list_entry(tmp.prev, struct dentry, d_lru);
		dentry_lru_del_init(loop);
		spin_lock(&loop->d_lock);
		/*
		 * This should never happen as the directory is already
		 * removed.
		 */
		if (atomic_read(&loop->d_count)) {
			__d_drop(loop);
			spin_unlock(&loop->d_lock);
			pr_warn("ex-WARN_ON in unhash_offsprings(): "
				"see OVZ-6827 for details\n");
			continue;
		}
		prune_one_dentry(loop);
	}
}

/*
 * destroy the dentries attached to a superblock on unmounting
 * - we don't need to use dentry->d_lock, and only need dcache_lock when
 *   removing the dentry from the system lists and hashes because:
 *   - the superblock is detached from all mountings and open files, so the
 *     dentry trees will not be rearranged by the VFS
 *   - s_umount is write-locked, so the memory pressure shrinker will ignore
 *     any dentries belonging to this superblock that it comes across
 *   - the filesystem itself is no longer permitted to rearrange the dentries
 *     in this superblock
 */
void shrink_dcache_for_umount(struct super_block *sb)
{
	struct dentry *dentry;

	if (down_read_trylock(&sb->s_umount))
		BUG();

	dentry = sb->s_root;
	sb->s_root = NULL;
	atomic_dec(&dentry->d_count);
	shrink_dcache_for_umount_subtree(dentry);

	while (!hlist_empty(&sb->s_anon)) {
		dentry = hlist_entry(sb->s_anon.first, struct dentry, d_hash);
		shrink_dcache_for_umount_subtree(dentry);
	}
}

/*
 * Search for at least 1 mount point in the dentry's subdirs.
 * We descend to the next level whenever the d_subdirs
 * list is non-empty and continue searching.
 */
 
/**
 * have_submounts - check for mounts over a dentry
 * @parent: dentry to check.
 *
 * Return true if the parent or its subdirectories contain
 * a mount point
 */
 
int have_submounts(struct dentry *parent)
{
	struct dentry *this_parent = parent;
	struct list_head *next;

	spin_lock(&dcache_lock);
	if (d_mountpoint(parent))
		goto positive;
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;
		/* Have we found a mount point ? */
		if (d_mountpoint(dentry))
			goto positive;
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
	}
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent) {
		next = this_parent->d_u.d_child.next;
		this_parent = this_parent->d_parent;
		goto resume;
	}
	spin_unlock(&dcache_lock);
	return 0; /* No mount points found in tree */
positive:
	spin_unlock(&dcache_lock);
	return 1;
}

/*
 * Search the dentry child list for the specified parent,
 * and move any unused dentries to the end of the unused
 * list for prune_dcache(). We descend to the next level
 * whenever the d_subdirs list is non-empty and continue
 * searching.
 *
 * It returns zero iff there are no unused children,
 * otherwise  it returns the number of children moved to
 * the end of the unused list. This may not be the total
 * number of unused children, because select_parent can
 * drop the lock and return early due to latency
 * constraints.
 */
static int select_parent(struct dentry * parent)
{
	struct dentry *this_parent = parent;
	struct list_head *next;
	int found = 0;

	spin_lock(&dcache_lock);
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;

		dentry_lru_del_init(dentry);
		/* 
		 * move only zero ref count dentries to the end 
		 * of the unused list for prune_dcache
		 */
		if (!atomic_read(&dentry->d_count)) {
			dentry_lru_add_tail(dentry);
			found++;
		}

		/*
		 * We can return to the caller if we have found some (this
		 * ensures forward progress). We'll be coming back to find
		 * the rest.
		 */
		if (found && need_resched())
			goto out;

		/*
		 * Descend a level if the d_subdirs list is non-empty.
		 */
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
	}
	/*
	 * All done at this level ... ascend and resume the search.
	 */
	if (this_parent != parent) {
		next = this_parent->d_u.d_child.next;
		this_parent = this_parent->d_parent;
		goto resume;
	}
out:
	spin_unlock(&dcache_lock);
	return found;
}

/**
 * shrink_dcache_parent - prune dcache
 * @parent: parent of entries to prune
 *
 * Prune the dcache to remove unused children of the parent dentry.
 */
 
void shrink_dcache_parent(struct dentry * parent)
{
	struct super_block *sb = parent->d_sb;
	int found;

	while ((found = select_parent(parent)) != 0)
		__shrink_dcache_sb(sb, &found, 0);
}

/*
 * Scan `nr' dentries and return the number which remain.
 *
 * We need to avoid reentering the filesystem if the caller is performing a
 * GFP_NOFS allocation attempt.  One example deadlock is:
 *
 * ext2_new_block->getblk->GFP->shrink_dcache_memory->prune_dcache->
 * prune_one_dentry->dput->dentry_iput->iput->inode->i_sb->s_op->put_inode->
 * ext2_discard_prealloc->ext2_free_blocks->lock_super->DEADLOCK.
 *
 * In this case we return -1 to tell the caller that we baled.
 */
static int shrink_dcache_memory(struct shrinker *shrink, int nr, gfp_t gfp_mask)
{
	int res = -1;

	KSTAT_PERF_ENTER(shrink_dcache)
	if (!ub_dcache_shrinkable(gfp_mask))
		goto out;
	if (nr) {
		if (!(gfp_mask & __GFP_FS))
			goto out;
		prune_dcache(nr, gfp_mask);
	}
	res = (dentry_stat.nr_unused / 100) * sysctl_vfs_cache_pressure;
out:
	KSTAT_PERF_LEAVE(shrink_dcache)
	return res;
}

static struct shrinker dcache_shrinker = {
	.shrink = shrink_dcache_memory,
	.seeks = DEFAULT_SEEKS,
};

/**
 * d_alloc	-	allocate a dcache entry
 * @parent: parent of entry to allocate
 * @name: qstr of the name
 *
 * Allocates a dentry. It returns %NULL if there is insufficient memory
 * available. On a success the dentry is returned. The name passed in is
 * copied and the copy passed in may be reused after this call.
 */
 
static struct dentry *__d_alloc(struct dentry *parent, const struct qstr *name,
				struct user_beancounter *ub)
{
	struct dentry *dentry;
	char *dname;

	if (ub_dcache_charge(ub, name->len))
		return NULL;

	dentry = kmem_cache_alloc(dentry_cache, GFP_KERNEL);
	if (!dentry) {
		ub_dcache_uncharge(ub, name->len);
		return NULL;
	}

	if (name->len > DNAME_INLINE_LEN-1) {
		dname = kmalloc(name->len + 1, GFP_KERNEL);
		if (!dname) {
			ub_dcache_uncharge(ub, name->len);
			kmem_cache_free(dentry_cache, dentry); 
			return NULL;
		}
	} else  {
		dname = dentry->d_iname;
	}	
	dentry->d_name.name = dname;

	dentry->d_name.len = name->len;
	dentry->d_name.hash = name->hash;
	memcpy(dname, name->name, name->len);
	dname[name->len] = 0;

	atomic_set(&dentry->d_count, 1);
	dentry->d_flags = DCACHE_UNHASHED;
	spin_lock_init(&dentry->d_lock);
	dentry->d_inode = NULL;
	dentry->d_parent = NULL;
	dentry->d_sb = NULL;
	dentry->d_op = NULL;
	dentry->d_fsdata = NULL;
	dentry->d_mounted = 0;
	dentry->d_ub = ub;
	dentry->d_lru_time = 0;
	INIT_HLIST_NODE(&dentry->d_hash);
	INIT_LIST_HEAD(&dentry->d_lru);
	INIT_LIST_HEAD(&dentry->d_bclru);
	INIT_LIST_HEAD(&dentry->d_subdirs);
	INIT_LIST_HEAD(&dentry->d_alias);
	INIT_LIST_HEAD(&dentry->d_u.d_child);

	spin_lock(&dcache_lock);
	dentry_stat.nr_dentry++;
	spin_unlock(&dcache_lock);

	return dentry;
}

struct dentry *d_alloc(struct dentry *parent, const struct qstr *name)
{
	struct dentry *dentry;
	
	dentry = __d_alloc(parent, name,
			   parent ? parent->d_ub : get_exec_ub_top());
	if (!dentry)
		return NULL;

	spin_lock(&dcache_lock);
	if (parent) {
		dentry->d_parent = dget(parent);
		dentry->d_sb = parent->d_sb;
		list_add(&dentry->d_u.d_child, &parent->d_subdirs);
	} else {
		dentry->d_flags |= DCACHE_BCTOP;
		list_add_tail(&dentry->d_bclru, &dentry->d_ub->ub_dentry_top);
	}
	spin_unlock(&dcache_lock);

	return dentry;
}

struct dentry *d_alloc_pseudo(struct super_block *sb, const struct qstr *name)
{
	struct dentry *dentry = __d_alloc(NULL, name, get_ub0());
	if (dentry) {
		dentry->d_sb = sb;
		dentry->d_parent = dentry;
		dentry->d_flags |= DCACHE_DISCONNECTED;
	}
	return dentry;
}
EXPORT_SYMBOL(d_alloc_pseudo);

struct dentry *d_alloc_name(struct dentry *parent, const char *name)
{
	struct qstr q;

	q.name = name;
	q.len = strlen(name);
	q.hash = full_name_hash(q.name, q.len);
	return d_alloc(parent, &q);
}

/* the caller must hold dcache_lock */
static void __d_instantiate(struct dentry *dentry, struct inode *inode)
{
	if (inode) {
		if (unlikely(IS_AUTOMOUNT(inode)))
			dentry->d_flags |= DCACHE_NEED_AUTOMOUNT;
		list_add(&dentry->d_alias, &inode->i_dentry);
	}
	dentry->d_inode = inode;
	fsnotify_d_instantiate(dentry, inode);
}

/**
 * d_instantiate - fill in inode information for a dentry
 * @entry: dentry to complete
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry.
 *
 * This turns negative dentries into productive full members
 * of society.
 *
 * NOTE! This assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */
 
void d_instantiate(struct dentry *entry, struct inode * inode)
{
	BUG_ON(!list_empty(&entry->d_alias));
	spin_lock(&dcache_lock);
	__d_instantiate(entry, inode);
	spin_unlock(&dcache_lock);
	security_d_instantiate(entry, inode);
}

/**
 * d_instantiate_unique - instantiate a non-aliased dentry
 * @entry: dentry to instantiate
 * @inode: inode to attach to this dentry
 *
 * Fill in inode information in the entry. On success, it returns NULL.
 * If an unhashed alias of "entry" already exists, then we return the
 * aliased dentry instead and drop one reference to inode.
 *
 * Note that in order to avoid conflicts with rename() etc, the caller
 * had better be holding the parent directory semaphore.
 *
 * This also assumes that the inode count has been incremented
 * (or otherwise set) by the caller to indicate that it is now
 * in use by the dcache.
 */
static struct dentry *__d_instantiate_unique(struct dentry *entry,
					     struct inode *inode)
{
	struct dentry *alias;
	int len = entry->d_name.len;
	const char *name = entry->d_name.name;
	unsigned int hash = entry->d_name.hash;

	if (!inode) {
		__d_instantiate(entry, NULL);
		return NULL;
	}

	list_for_each_entry(alias, &inode->i_dentry, d_alias) {
		struct qstr *qstr = &alias->d_name;

		if (qstr->hash != hash)
			continue;
		if (alias->d_parent != entry->d_parent)
			continue;
		if (qstr->len != len)
			continue;
		if (memcmp(qstr->name, name, len))
			continue;
		dget_locked(alias);
		return alias;
	}

	__d_instantiate(entry, inode);
	return NULL;
}

struct dentry *d_instantiate_unique(struct dentry *entry, struct inode *inode)
{
	struct dentry *result;

	BUG_ON(!list_empty(&entry->d_alias));

	spin_lock(&dcache_lock);
	result = __d_instantiate_unique(entry, inode);
	spin_unlock(&dcache_lock);

	if (!result) {
		security_d_instantiate(entry, inode);
		return NULL;
	}

	BUG_ON(!d_unhashed(result));
	iput(inode);
	return result;
}

EXPORT_SYMBOL(d_instantiate_unique);

/**
 * d_alloc_root - allocate root dentry
 * @root_inode: inode to allocate the root for
 *
 * Allocate a root ("/") dentry for the inode given. The inode is
 * instantiated and returned. %NULL is returned if there is insufficient
 * memory or the inode passed is %NULL.
 */
 
struct dentry * d_alloc_root(struct inode * root_inode)
{
	struct dentry *res = NULL;

	if (root_inode) {
		static const struct qstr name = { .name = "/", .len = 1 };

		res = d_alloc(NULL, &name);
		if (res) {
			res->d_sb = root_inode->i_sb;
			res->d_parent = res;
			d_instantiate(res, root_inode);
		}
	}
	return res;
}

static inline struct hlist_head *d_hash(struct dentry *parent,
					unsigned long hash)
{
	hash += ((unsigned long) parent ^ GOLDEN_RATIO_PRIME) / L1_CACHE_BYTES;
	hash = hash ^ ((hash ^ GOLDEN_RATIO_PRIME) >> D_HASHBITS);
	return dentry_hashtable + (hash & D_HASHMASK);
}

static struct dentry * __d_find_any_alias(struct inode *inode)
{
	struct dentry *alias;

	if (list_empty(&inode->i_dentry))
		return NULL;
	alias = list_first_entry(&inode->i_dentry, struct dentry, d_alias);
	__dget_locked(alias);
	return alias;
}

static struct dentry * d_find_any_alias(struct inode *inode)
{
	struct dentry *de;

	spin_lock(&dcache_lock);
	de = __d_find_any_alias(inode);
	spin_unlock(&dcache_lock);
	return de;
}


/**
 * d_obtain_alias - find or allocate a dentry for a given inode
 * @inode: inode to allocate the dentry for
 *
 * Obtain a dentry for an inode resulting from NFS filehandle conversion or
 * similar open by handle operations.  The returned dentry may be anonymous,
 * or may have a full name (if the inode was already in the cache).
 *
 * When called on a directory inode, we must ensure that the inode only ever
 * has one dentry.  If a dentry is found, that is returned instead of
 * allocating a new one.
 *
 * On successful return, the reference to the inode has been transferred
 * to the dentry.  In case of an error the reference on the inode is released.
 * To make it easier to use in export operations a %NULL or IS_ERR inode may
 * be passed in and will be the error will be propagate to the return value,
 * with a %NULL @inode replaced by ERR_PTR(-ESTALE).
 */
struct dentry *d_obtain_alias(struct inode *inode)
{
	static const struct qstr anonstring = { .name = "" };
	struct dentry *tmp;
	struct dentry *res;

	if (!inode)
		return ERR_PTR(-ESTALE);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	res = d_find_any_alias(inode);
	if (res)
		goto out_iput;

	tmp = d_alloc(NULL, &anonstring);
	if (!tmp) {
		res = ERR_PTR(-ENOMEM);
		goto out_iput;
	}
	tmp->d_parent = tmp; /* make sure dput doesn't croak */

	spin_lock(&dcache_lock);
	res = __d_find_any_alias(inode);
	if (res) {
		spin_unlock(&dcache_lock);
		dput(tmp);
		goto out_iput;
	}

	/* attach a disconnected dentry */
	spin_lock(&tmp->d_lock);
	tmp->d_sb = inode->i_sb;
	tmp->d_inode = inode;
	tmp->d_flags |= DCACHE_DISCONNECTED;
	tmp->d_flags &= ~DCACHE_UNHASHED;
	list_add(&tmp->d_alias, &inode->i_dentry);
	hlist_add_head(&tmp->d_hash, &inode->i_sb->s_anon);
	spin_unlock(&tmp->d_lock);
	spin_unlock(&dcache_lock);

	security_d_instantiate(tmp, inode);
	return tmp;

 out_iput:
	if (res && !IS_ERR(res))
		security_d_instantiate(res, inode);
	iput(inode);
	return res;
}
EXPORT_SYMBOL(d_obtain_alias);

static struct dentry *__find_moveable_alias(struct inode *inode,
						struct dentry *parent)
{
	struct dentry *alias;

	if (list_empty(&inode->i_dentry))
		return NULL;
	alias = list_first_entry(&inode->i_dentry, struct dentry, d_alias);
	if (alias->d_parent == parent || IS_ROOT(alias))
		return __dget_locked(alias);
	return NULL;
}

/**
 * d_splice_alias - splice a disconnected dentry into the tree if one exists
 * @inode:  the inode which may have a disconnected dentry
 * @dentry: a negative dentry which we want to point to the inode.
 *
 * If inode is a directory and has a 'disconnected' dentry (i.e. IS_ROOT and
 * DCACHE_DISCONNECTED), then d_move that in place of the given dentry
 * and return it, else simply d_add the inode to the dentry and return NULL.
 *
 * This is needed in the lookup routine of any filesystem that is exportable
 * (via knfsd) so that we can build dcache paths to directories effectively.
 *
 * If a dentry was found and moved, then it is returned.  Otherwise NULL
 * is returned.  This matches the expected return value of ->lookup.
 *
 */
struct dentry *d_splice_alias(struct inode *inode, struct dentry *dentry)
{
	struct dentry *new = NULL;

	if (inode && S_ISDIR(inode->i_mode)) {
		spin_lock(&dcache_lock);
		new = __find_moveable_alias(inode, dentry->d_parent);
		if (new) {
			spin_unlock(&dcache_lock);
			security_d_instantiate(new, inode);
			d_rehash(dentry);
			d_move(new, dentry);
			iput(inode);
		} else {
			/* already taking dcache_lock, so d_add() by hand */
			__d_instantiate(dentry, inode);
			spin_unlock(&dcache_lock);
			security_d_instantiate(dentry, inode);
			d_rehash(dentry);
		}
	} else
		d_add(dentry, inode);
	return new;
}

/**
 * d_add_ci - lookup or allocate new dentry with case-exact name
 * @inode:  the inode case-insensitive lookup has found
 * @dentry: the negative dentry that was passed to the parent's lookup func
 * @name:   the case-exact name to be associated with the returned dentry
 *
 * This is to avoid filling the dcache with case-insensitive names to the
 * same inode, only the actual correct case is stored in the dcache for
 * case-insensitive filesystems.
 *
 * For a case-insensitive lookup match and if the the case-exact dentry
 * already exists in in the dcache, use it and return it.
 *
 * If no entry exists with the exact case name, allocate new dentry with
 * the exact case, and return the spliced entry.
 */
struct dentry *d_add_ci(struct dentry *dentry, struct inode *inode,
			struct qstr *name)
{
	int error;
	struct dentry *found;
	struct dentry *new;

	/*
	 * First check if a dentry matching the name already exists,
	 * if not go ahead and create it now.
	 */
	found = d_hash_and_lookup(dentry->d_parent, name);
	if (!found) {
		new = d_alloc(dentry->d_parent, name);
		if (!new) {
			error = -ENOMEM;
			goto err_out;
		}

		found = d_splice_alias(inode, new);
		if (found) {
			dput(new);
			return found;
		}
		return new;
	}

	/*
	 * If a matching dentry exists, and it's not negative use it.
	 *
	 * Decrement the reference count to balance the iget() done
	 * earlier on.
	 */
	if (found->d_inode) {
		if (unlikely(found->d_inode != inode)) {
			/* This can't happen because bad inodes are unhashed. */
			BUG_ON(!is_bad_inode(inode));
			BUG_ON(!is_bad_inode(found->d_inode));
		}
		iput(inode);
		return found;
	}

	/*
	 * Negative dentry: instantiate it unless the inode is a directory and
	 * already has a dentry.
	 */
	spin_lock(&dcache_lock);
	if (!S_ISDIR(inode->i_mode) || list_empty(&inode->i_dentry)) {
		__d_instantiate(found, inode);
		spin_unlock(&dcache_lock);
		security_d_instantiate(found, inode);
		return found;
	}

	/*
	 * In case a directory already has a (disconnected) entry grab a
	 * reference to it, move it in place and use it.
	 */
	new = list_entry(inode->i_dentry.next, struct dentry, d_alias);
	dget_locked(new);
	spin_unlock(&dcache_lock);
	security_d_instantiate(found, inode);
	d_move(new, found);
	iput(inode);
	dput(found);
	return new;

err_out:
	iput(inode);
	return ERR_PTR(error);
}

/**
 * d_lookup - search for a dentry
 * @parent: parent dentry
 * @name: qstr of name we wish to find
 *
 * Searches the children of the parent dentry for the name in question. If
 * the dentry is found its reference count is incremented and the dentry
 * is returned. The caller must use dput to free the entry when it has
 * finished using it. %NULL is returned on failure.
 *
 * __d_lookup is dcache_lock free. The hash list is protected using RCU.
 * Memory barriers are used while updating and doing lockless traversal. 
 * To avoid races with d_move while rename is happening, d_lock is used.
 *
 * Overflows in memcmp(), while d_move, are avoided by keeping the length
 * and name pointer in one structure pointed by d_qstr.
 *
 * rcu_read_lock() and rcu_read_unlock() are used to disable preemption while
 * lookup is going on.
 *
 * The dentry unused LRU is not updated even if lookup finds the required dentry
 * in there. It is updated in places such as prune_dcache, shrink_dcache_sb,
 * select_parent and __dget_locked. This laziness saves lookup from dcache_lock
 * acquisition.
 *
 * d_lookup() is protected against the concurrent renames in some unrelated
 * directory using the seqlockt_t rename_lock.
 */

struct dentry * d_lookup(struct dentry * parent, struct qstr * name)
{
	struct dentry * dentry = NULL;
	unsigned long seq;

        do {
                seq = read_seqbegin(&rename_lock);
                dentry = __d_lookup(parent, name);
                if (dentry)
			break;
	} while (read_seqretry(&rename_lock, seq));
	return dentry;
}

struct dentry * __d_lookup(struct dentry * parent, struct qstr * name)
{
	unsigned int len = name->len;
	unsigned int hash = name->hash;
	const unsigned char *str = name->name;
	struct hlist_head *head = d_hash(parent,hash);
	struct dentry *found = NULL;
	struct hlist_node *node;
	struct dentry *dentry;

	rcu_read_lock();
	
	hlist_for_each_entry_rcu(dentry, node, head, d_hash) {
		struct qstr *qstr;

		if (dentry->d_name.hash != hash)
			continue;
		if (dentry->d_parent != parent)
			continue;

		spin_lock(&dentry->d_lock);

		/*
		 * Recheck the dentry after taking the lock - d_move may have
		 * changed things.  Don't bother checking the hash because we're
		 * about to compare the whole name anyway.
		 */
		if (dentry->d_parent != parent)
			goto next;

		/* non-existing due to RCU? */
		if (d_unhashed(dentry))
			goto next;

		/*
		 * It is safe to compare names since d_move() cannot
		 * change the qstr (protected by d_lock).
		 */
		qstr = &dentry->d_name;
		if (parent->d_op && parent->d_op->d_compare) {
			if (parent->d_op->d_compare(parent, qstr, name))
				goto next;
		} else {
			if (qstr->len != len)
				goto next;
			if (memcmp(qstr->name, str, len))
				goto next;
		}

		atomic_inc(&dentry->d_count);
		found = dentry;
		spin_unlock(&dentry->d_lock);
		break;
next:
		spin_unlock(&dentry->d_lock);
 	}
 	rcu_read_unlock();

 	return found;
}

/**
 * d_hash_and_lookup - hash the qstr then search for a dentry
 * @dir: Directory to search in
 * @name: qstr of name we wish to find
 *
 * On hash failure or on lookup failure NULL is returned.
 */
struct dentry *d_hash_and_lookup(struct dentry *dir, struct qstr *name)
{
	struct dentry *dentry = NULL;

	/*
	 * Check for a fs-specific hash function. Note that we must
	 * calculate the standard hash first, as the d_op->d_hash()
	 * routine may choose to leave the hash value unchanged.
	 */
	name->hash = full_name_hash(name->name, name->len);
	if (dir->d_op && dir->d_op->d_hash) {
		if (dir->d_op->d_hash(dir, name) < 0)
			goto out;
	}
	dentry = d_lookup(dir, name);
out:
	return dentry;
}

/**
 * d_validate - verify dentry provided from insecure source (deprecated)
 * @dentry: The dentry alleged to be valid child of @dparent
 * @dparent: The parent dentry (known to be valid)
 *
 * An insecure source has sent us a dentry, here we verify it and dget() it.
 * This is used by ncpfs in its readdir implementation.
 * Zero is returned in the dentry is invalid.
 *
 * This function is slow for big directories, and deprecated, do not use it.
 */
int d_validate(struct dentry *dentry, struct dentry *dparent)
{
	struct dentry *child;

	spin_lock(&dcache_lock);
	list_for_each_entry(child, &dparent->d_subdirs, d_u.d_child) {
		if (dentry == child) {
			__dget_locked(dentry);
			spin_unlock(&dcache_lock);
			return 1;
		}
	}
	spin_unlock(&dcache_lock);

	return 0;
}

/*
 * When a file is deleted, we have two options:
 * - turn this dentry into a negative dentry
 * - unhash this dentry and free it.
 *
 * Usually, we want to just turn this into
 * a negative dentry, but if anybody else is
 * currently using the dentry or the inode
 * we can't do that and we fall back on removing
 * it from the hash queues and waiting for
 * it to be deleted later when it has no users
 */
 
/**
 * d_delete - delete a dentry
 * @dentry: The dentry to delete
 *
 * Turn the dentry into a negative dentry if possible, otherwise
 * remove it from the hash queues so it can be deleted later
 */
 
void d_delete(struct dentry * dentry)
{
	int isdir = 0;
	/*
	 * Are we the only user?
	 */
	spin_lock(&dcache_lock);
	spin_lock(&dentry->d_lock);
	isdir = S_ISDIR(dentry->d_inode->i_mode);
	if (atomic_read(&dentry->d_count) == 1) {
		dentry_iput(dentry);
		fsnotify_nameremove(dentry, isdir);
		return;
	}

	if (!d_unhashed(dentry))
		__d_drop(dentry);
	spin_unlock(&dentry->d_lock);

	if (isdir)
		unhash_offsprings(dentry);

	spin_unlock(&dcache_lock);

	fsnotify_nameremove(dentry, isdir);
}

static void __d_rehash(struct dentry * entry, struct hlist_head *list)
{

 	entry->d_flags &= ~DCACHE_UNHASHED;
 	hlist_add_head_rcu(&entry->d_hash, list);
}

static void _d_rehash(struct dentry * entry)
{
	__d_rehash(entry, d_hash(entry->d_parent, entry->d_name.hash));
}

/**
 * d_rehash	- add an entry back to the hash
 * @entry: dentry to add to the hash
 *
 * Adds a dentry to the hash according to its name.
 */
 
void d_rehash(struct dentry * entry)
{
	spin_lock(&dcache_lock);
	spin_lock(&entry->d_lock);
	_d_rehash(entry);
	spin_unlock(&entry->d_lock);
	spin_unlock(&dcache_lock);
}

/*
 * When switching names, the actual string doesn't strictly have to
 * be preserved in the target - because we're dropping the target
 * anyway. As such, we can just do a simple memcpy() to copy over
 * the new name before we switch.
 *
 * Note that we have to be a lot more careful about getting the hash
 * switched - we have to switch the hash value properly even if it
 * then no longer matches the actual (corrupted) string of the target.
 * The hash value has to match the hash queue that the dentry is on..
 */
static void switch_names(struct dentry *dentry, struct dentry *target)
{
	if (dname_external(target)) {
		if (dname_external(dentry)) {
			/*
			 * Both external: swap the pointers
			 */
			swap(target->d_name.name, dentry->d_name.name);
		} else {
			/*
			 * dentry:internal, target:external.  Steal target's
			 * storage and make target internal.
			 */
			memcpy(target->d_iname, dentry->d_name.name,
					dentry->d_name.len + 1);
			dentry->d_name.name = target->d_name.name;
			target->d_name.name = target->d_iname;
		}
	} else {
		if (dname_external(dentry)) {
			/*
			 * dentry:external, target:internal.  Give dentry's
			 * storage to target and make dentry internal
			 */
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
			target->d_name.name = dentry->d_name.name;
			dentry->d_name.name = dentry->d_iname;
		} else {
			/*
			 * Both are internal.  Just copy target to dentry
			 */
			memcpy(dentry->d_iname, target->d_name.name,
					target->d_name.len + 1);
			dentry->d_name.len = target->d_name.len;
			return;
		}
	}
	swap(dentry->d_name.len, target->d_name.len);
}

/*
 * We cannibalize "target" when moving dentry on top of it,
 * because it's going to be thrown away anyway. We could be more
 * polite about it, though.
 *
 * This forceful removal will result in ugly /proc output if
 * somebody holds a file open that got deleted due to a rename.
 * We could be nicer about the deleted file, and let it show
 * up under the name it had before it was deleted rather than
 * under the original name of the file that was moved on top of it.
 */
 
/*
 * __d_move - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way.  Caller hold
 * rename_lock.
 */
static void __d_move(struct dentry * dentry, struct dentry * target)
{
	struct hlist_head *list;

	if (!dentry->d_inode)
		printk(KERN_WARNING "VFS: moving negative dcache entry\n");

	/*
	 * XXXX: do we really need to take target->d_lock?
	 */
	if (target < dentry) {
		spin_lock(&target->d_lock);
		spin_lock_nested(&dentry->d_lock, DENTRY_D_LOCK_NESTED);
	} else {
		spin_lock(&dentry->d_lock);
		spin_lock_nested(&target->d_lock, DENTRY_D_LOCK_NESTED);
	}

	/* Move the dentry to the target hash queue, if on different bucket */
	if (d_unhashed(dentry))
		goto already_unhashed;

	hlist_del_rcu(&dentry->d_hash);

already_unhashed:
	list = d_hash(target->d_parent, target->d_name.hash);
	__d_rehash(dentry, list);

	/* Unhash the target: dput() will then get rid of it */
	__d_drop(target);

	list_del(&dentry->d_u.d_child);
	list_del(&target->d_u.d_child);

	/* Switch the names.. */
	switch_names(dentry, target);
	swap(dentry->d_name.hash, target->d_name.hash);

	if (dentry->d_ub != target->d_parent->d_ub &&
			!(dentry->d_flags & DCACHE_BCTOP))
		ub_dcache_change_owner(dentry, target->d_parent->d_ub);

	/* ... and switch the parents */
	if (IS_ROOT(dentry)) {
		dentry->d_parent = target->d_parent;
		target->d_parent = target;
		INIT_LIST_HEAD(&target->d_u.d_child);

		/* If disconnected BCTOP dentry was moved into the tree
		 * we need to remove it from list of BCTOP dentries */
		if (unlikely((dentry->d_flags & DCACHE_BCTOP) &&
		    (dentry->d_ub == dentry->d_parent->d_ub))) {
			dentry->d_flags &= ~DCACHE_BCTOP;
			list_del(&dentry->d_bclru);
		}
	} else {
		swap(dentry->d_parent, target->d_parent);

		/* And add them back to the (new) parent lists */
		list_add(&target->d_u.d_child, &target->d_parent->d_subdirs);
	}

	list_add(&dentry->d_u.d_child, &dentry->d_parent->d_subdirs);
	spin_unlock(&target->d_lock);
	fsnotify_d_move(dentry);
	spin_unlock(&dentry->d_lock);
}

/**
 * d_move - move a dentry
 * @dentry: entry to move
 * @target: new dentry
 *
 * Update the dcache to reflect the move of a file name. Negative
 * dcache entries should not be moved in this way.
 */

void d_move(struct dentry * dentry, struct dentry * target)
{
	spin_lock(&dcache_lock);
	write_seqlock(&rename_lock);
	__d_move(dentry, target);
	write_sequnlock(&rename_lock);
	spin_unlock(&dcache_lock);
}

/**
 * d_ancestor - search for an ancestor
 * @p1: ancestor dentry
 * @p2: child dentry
 *
 * Returns the ancestor dentry of p2 which is a child of p1, if p1 is
 * an ancestor of p2, else NULL.
 */
struct dentry *d_ancestor(struct dentry *p1, struct dentry *p2)
{
	struct dentry *p;

	for (p = p2; !IS_ROOT(p); p = p->d_parent) {
		if (p->d_parent == p1)
			return p;
	}
	return NULL;
}

/*
 * This helper attempts to cope with remotely renamed directories
 *
 * It assumes that the caller is already holding
 * dentry->d_parent->d_inode->i_mutex, the dcache_lock and rename_lock
 *
 * Note: If ever the locking in lock_rename() changes, then please
 * remember to update this too...
 */
static struct dentry *__d_unalias(struct dentry *dentry, struct dentry *alias)
	__releases(dcache_lock)
{
	struct mutex *m1 = NULL, *m2 = NULL;
	struct dentry *ret;

	/* If alias and dentry share a parent, then no extra locks required */
	if (alias->d_parent == dentry->d_parent)
		goto out_unalias;

	/* Check for loops */
	ret = ERR_PTR(-ELOOP);
	if (d_ancestor(alias, dentry))
		goto out_err;

	/* See lock_rename() */
	ret = ERR_PTR(-ESTALE);
	if (!mutex_trylock(&dentry->d_sb->s_vfs_rename_mutex))
		goto out_err;
	m1 = &dentry->d_sb->s_vfs_rename_mutex;
	if (!mutex_trylock(&alias->d_parent->d_inode->i_mutex))
		goto out_err;
	m2 = &alias->d_parent->d_inode->i_mutex;
out_unalias:
	__d_move(alias, dentry);
	ret = alias;
out_err:
	spin_unlock(&dcache_lock);
	if (m2)
		mutex_unlock(m2);
	if (m1)
		mutex_unlock(m1);
	return ret;
}

/*
 * Prepare an anonymous dentry for life in the superblock's dentry tree as a
 * named dentry in place of the dentry to be replaced.
 */
static void __d_materialise_dentry(struct dentry *dentry, struct dentry *anon)
{
	struct dentry *dparent, *aparent;

	switch_names(dentry, anon);
	swap(dentry->d_name.hash, anon->d_name.hash);

	dparent = dentry->d_parent;
	aparent = anon->d_parent;

	dentry->d_parent = (aparent == anon) ? dentry : aparent;
	list_del(&dentry->d_u.d_child);
	if (!IS_ROOT(dentry))
		list_add(&dentry->d_u.d_child, &dentry->d_parent->d_subdirs);
	else
		INIT_LIST_HEAD(&dentry->d_u.d_child);

	anon->d_parent = (dparent == dentry) ? anon : dparent;
	list_del(&anon->d_u.d_child);
	if (!IS_ROOT(anon))
		list_add(&anon->d_u.d_child, &anon->d_parent->d_subdirs);
	else
		INIT_LIST_HEAD(&anon->d_u.d_child);

	anon->d_flags &= ~DCACHE_DISCONNECTED;
}

/**
 * d_materialise_unique - introduce an inode into the tree
 * @dentry: candidate dentry
 * @inode: inode to bind to the dentry, to which aliases may be attached
 *
 * Introduces an dentry into the tree, substituting an extant disconnected
 * root directory alias in its place if there is one
 */
struct dentry *d_materialise_unique(struct dentry *dentry, struct inode *inode)
{
	struct dentry *actual;

	BUG_ON(!d_unhashed(dentry));

	spin_lock(&dcache_lock);

	if (!inode) {
		actual = dentry;
		__d_instantiate(dentry, NULL);
		goto found_lock;
	}

	if (S_ISDIR(inode->i_mode)) {
		struct dentry *alias;

		/* Does an aliased dentry already exist? */
		alias = __d_find_alias(inode);
		if (alias) {
			actual = alias;
			write_seqlock(&rename_lock);

			if (d_ancestor(alias, dentry)) {
				/* Check for loops */
				actual = ERR_PTR(-ELOOP);
				write_sequnlock(&rename_lock);
				pr_warn_ratelimited(
					"VFS: Lookup of '%s' in %s %s"
					" would have caused loop\n",
					dentry->d_name.name,
					inode->i_sb->s_type->name,
					inode->i_sb->s_id);
				dput(alias);
				goto out_unlock_dcache;
			} else if (IS_ROOT(alias)) {
				/* Is this an anonymous mountpoint that we
				 * could splice into our tree? */
				spin_lock(&alias->d_lock);
				__d_materialise_dentry(dentry, alias);
				write_sequnlock(&rename_lock);
				__d_drop(alias);
				goto found;
			} else {
				/* Nope, but we must(!) avoid directory
				 * aliasing */
				actual = __d_unalias(dentry, alias);
				write_sequnlock(&rename_lock);
				if (IS_ERR(actual))
					dput(alias);
				goto out_nolock;
			}
		}
	}

	/* Add a unique reference */
	actual = __d_instantiate_unique(dentry, inode);
	if (!actual)
		actual = dentry;
	else if (unlikely(!d_unhashed(actual)))
		goto shouldnt_be_hashed;

found_lock:
	spin_lock(&actual->d_lock);
found:
	_d_rehash(actual);
	spin_unlock(&actual->d_lock);
out_unlock_dcache:
	spin_unlock(&dcache_lock);
out_nolock:
	if (actual == dentry) {
		security_d_instantiate(dentry, inode);
		return NULL;
	}

	iput(inode);
	return actual;

shouldnt_be_hashed:
	spin_unlock(&dcache_lock);
	BUG();
}

static int prepend(char **buffer, int *buflen, const char *str, int namelen)
{
	*buflen -= namelen;
	if (*buflen < 0)
		return -ENAMETOOLONG;
	*buffer -= namelen;
	memcpy(*buffer, str, namelen);
	return 0;
}

static int prepend_name(char **buffer, int *buflen, struct qstr *name)
{
	return prepend(buffer, buflen, name->name, name->len);
}

/**
 * d_root_check - checks if dentry is accessible from current's fs root
 * @dentry: dentry to be verified
 * @vfsmnt: vfsmnt to which the dentry belongs
 */
int d_root_check(struct path *path)
{
	return PTR_ERR(d_path(path, NULL, 0));
}

/**
 * __d_path - return the path of a dentry
 * @path: the dentry/vfsmount to report
 * @root: root vfsmnt/dentry (may be modified by this function)
 * @buffer: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns a pointer into the buffer or an error code if the
 * path was too long.
 *
 * "buflen" should be positive. Caller holds the dcache_lock.
 *
 * If path is not reachable from the supplied root, then the value of
 * root is changed (without modifying refcounts).
 */
char *__d_path(const struct path *path, struct path *root,
	       char *buffer, int buflen)
{
	struct dentry *dentry = path->dentry;
	struct vfsmount *vfsmnt = path->mnt;
	char *end = buffer + buflen;
	char *retval, *tail;
	int deleted;
	struct vfsmount *oldmnt = vfsmnt;
	struct ve_struct *ve = get_exec_env();

	spin_lock(&vfsmount_lock);
	if (buffer) {
		prepend(&end, &buflen, "\0", 1);
		if (buflen < 1)
			goto Elong;
	}
	deleted = (!IS_ROOT(dentry) && d_unhashed(dentry));

	/* Get '/' right */
	retval = end-1;
	tail = retval;
	if (buffer)
		*retval = '/';

	for (;;) {
		struct dentry * parent;

		if (dentry == root->dentry && vfsmnt == root->mnt)
			break;
		if (dentry == vfsmnt->mnt_root || IS_ROOT(dentry)) {
			/* Escaped? */
			if (buffer && dentry != vfsmnt->mnt_root) {
				retval = tail;
				*retval = '/';
				goto out;
			}
			/* Global root? */
			if (vfsmnt->mnt_parent == vfsmnt) {
				goto global_root;
			}
			/* CT root? */
			if (!ve_is_super(ve) && vfsmnt == ve->root_path.mnt)
				goto ct_root;
			dentry = vfsmnt->mnt_mountpoint;
			vfsmnt = vfsmnt->mnt_parent;
			continue;
		}
		parent = dentry->d_parent;
		prefetch(parent);
		if (buffer && ((prepend_name(&end, &buflen, &dentry->d_name) != 0) ||
		    (prepend(&end, &buflen, "/", 1) != 0)))
			goto Elong;
		retval = end;
		dentry = parent;
	}

out:
	if (deleted && buffer &&
			prepend(&retval, &buflen, " (deleted)", 10) != 0)
		goto Elong;

	spin_unlock(&vfsmount_lock);
	return buffer ? retval : NULL;

global_root:
	/*
	 * We traversed the tree upward and reached a root, but the given
	 * lookup terminal point wasn't encountered.  It means either that the
	 * dentry is out of our scope or belongs to an abstract space like
	 * sock_mnt or pipe_mnt.  Check for it.
	 *
	 * There are different options to check it.
	 * We may assume that any dentry tree is unreachable unless it's
	 * connected to `root' (defined as fs root of init aka child reaper)
	 * and expose all paths that are not connected to it.
	 * The other option is to allow exposing of known abstract spaces
	 * explicitly and hide the path information for other cases.
	 * This approach is more safe, let's take it.  2001/04/22  SAW
	 */
	if (!(oldmnt->mnt_sb->s_flags & MS_NOUSER) &&
	    !ve_accessible_veid(vfsmnt->owner, get_exec_env()->veid)) {
		retval = ERR_PTR(-EINVAL);
		goto out_err;
	}
ct_root:
	retval += 1;	/* hit the slash */
	if (buffer && prepend_name(&retval, &buflen, &dentry->d_name) != 0)
		goto Elong;
	root->mnt = vfsmnt;
	root->dentry = dentry;
	goto out;

Elong:
	retval = ERR_PTR(-ENAMETOOLONG);
out_err:
	spin_unlock(&vfsmount_lock);
	return retval;

}
EXPORT_SYMBOL(__d_path);

/**
 * d_path - return the path of a dentry
 * @path: path to report
 * @buf: buffer to return value in
 * @buflen: buffer length
 *
 * Convert a dentry into an ASCII path name. If the entry has been deleted
 * the string " (deleted)" is appended. Note that this is ambiguous.
 *
 * Returns a pointer into the buffer or an error code if the path was
 * too long. Note: Callers should use the returned pointer, not the passed
 * in buffer, to use the name! The implementation often starts at an offset
 * into the buffer, and may leave 0 bytes at the start.
 *
 * "buflen" should be positive.
 */
char *d_path(const struct path *path, char *buf, int buflen)
{
	char *res;
	struct path root;
	struct path tmp;

	/*
	 * We have various synthetic filesystems that never get mounted.  On
	 * these filesystems dentries are never used for lookup purposes, and
	 * thus don't need to be hashed.  They also don't need a name until a
	 * user wants to identify the object in /proc/pid/fd/.  The little hack
	 * below allows us to generate a name for these objects on demand:
	 *
	 * pipefs and socketfs methods assume valid buffer, d_root_check()
	 * supplies NULL one for access checks.
	 */
	if (buf && path->dentry->d_op && path->dentry->d_op->d_dname)
		return path->dentry->d_op->d_dname(path->dentry, buf, buflen);

	get_fs_root(current->fs, &root);
	spin_lock(&dcache_lock);
	tmp = root;
	res = __d_path(path, &tmp, buf, buflen);
	spin_unlock(&dcache_lock);
	path_put(&root);
	return res;
}

/*
 * Helper function for dentry_operations.d_dname() members
 */
char *dynamic_dname(struct dentry *dentry, char *buffer, int buflen,
			const char *fmt, ...)
{
	va_list args;
	char temp[64];
	int sz;

	va_start(args, fmt);
	sz = vsnprintf(temp, sizeof(temp), fmt, args) + 1;
	va_end(args);

	if (sz > sizeof(temp) || sz > buflen)
		return ERR_PTR(-ENAMETOOLONG);

	buffer += buflen - sz;
	return memcpy(buffer, temp, sz);
}

/*
 * Write full pathname from the root of the filesystem into the buffer.
 */
char *dentry_path(struct dentry *dentry, char *buf, int buflen)
{
	char *end = buf + buflen;
	char *retval;

	spin_lock(&dcache_lock);
	prepend(&end, &buflen, "\0", 1);
	if (d_unlinked(dentry) &&
		(prepend(&end, &buflen, "//deleted", 9) != 0))
			goto Elong;
	if (buflen < 1)
		goto Elong;
	/* Get '/' right */
	retval = end-1;
	*retval = '/';

	while (!IS_ROOT(dentry)) {
		struct dentry *parent = dentry->d_parent;

		prefetch(parent);
		if ((prepend_name(&end, &buflen, &dentry->d_name) != 0) ||
		    (prepend(&end, &buflen, "/", 1) != 0))
			goto Elong;

		retval = end;
		dentry = parent;
	}
	spin_unlock(&dcache_lock);
	return retval;
Elong:
	spin_unlock(&dcache_lock);
	return ERR_PTR(-ENAMETOOLONG);
}

/*
 * NOTE! The user-level library version returns a
 * character pointer. The kernel system call just
 * returns the length of the buffer filled (which
 * includes the ending '\0' character), or a negative
 * error value. So libc would do something like
 *
 *	char *getcwd(char * buf, size_t size)
 *	{
 *		int retval;
 *
 *		retval = sys_getcwd(buf, size);
 *		if (retval >= 0)
 *			return buf;
 *		errno = -retval;
 *		return NULL;
 *	}
 */
SYSCALL_DEFINE2(getcwd, char __user *, buf, unsigned long, size)
{
	int error;
	struct path pwd, root;
	char *page = (char *) __get_free_page(GFP_USER);

	if (!page)
		return -ENOMEM;

	get_fs_root_and_pwd(current->fs, &root, &pwd);

	if (pwd.dentry->d_inode->i_op &&
			pwd.dentry->d_inode->i_op->permission) {
		error = pwd.dentry->d_inode->i_op->permission(
				pwd.dentry->d_inode, 0);
		if (error == -ERESTARTSYS)
			goto out;
	}

	error = -ENOENT;
	spin_lock(&dcache_lock);
	if (!d_unlinked(pwd.dentry)) {
		unsigned long len;
		struct path tmp = root;
		char * cwd;

		cwd = __d_path(&pwd, &tmp, page, PAGE_SIZE);

		error = PTR_ERR(cwd);
		if (error == -EINVAL) {
			struct ve_struct *ve;

			ve = get_exec_env();
			tmp = ve->root_path;
			cwd = __d_path(&pwd, &tmp, page, PAGE_SIZE);
		}

		spin_unlock(&dcache_lock);

		error = PTR_ERR(cwd);
		if (IS_ERR(cwd))
			goto out;

		error = -ERANGE;
		len = PAGE_SIZE + page - cwd;
		if (len <= size) {
			error = len;
			if (copy_to_user(buf, cwd, len))
				error = -EFAULT;
		}
	} else
		spin_unlock(&dcache_lock);

out:
	path_put(&pwd);
	path_put(&root);
	free_page((unsigned long) page);
	return error;
}

/*
 * Test whether new_dentry is a subdirectory of old_dentry.
 *
 * Trivially implemented using the dcache structure
 */

/**
 * is_subdir - is new dentry a subdirectory of old_dentry
 * @new_dentry: new dentry
 * @old_dentry: old dentry
 *
 * Returns 1 if new_dentry is a subdirectory of the parent (at any depth).
 * Returns 0 otherwise.
 * Caller must ensure that "new_dentry" is pinned before calling is_subdir()
 */
  
int is_subdir(struct dentry *new_dentry, struct dentry *old_dentry)
{
	int result;
	unsigned long seq;

	if (new_dentry == old_dentry)
		return 1;

	/*
	 * Need rcu_readlock to protect against the d_parent trashing
	 * due to d_move
	 */
	rcu_read_lock();
	do {
		/* for restarting inner loop in case of seq retry */
		seq = read_seqbegin(&rename_lock);
		if (d_ancestor(old_dentry, new_dentry))
			result = 1;
		else
			result = 0;
	} while (read_seqretry(&rename_lock, seq));
	rcu_read_unlock();

	return result;
}

void d_genocide(struct dentry *root)
{
	struct dentry *this_parent = root;
	struct list_head *next;

	spin_lock(&dcache_lock);
repeat:
	next = this_parent->d_subdirs.next;
resume:
	while (next != &this_parent->d_subdirs) {
		struct list_head *tmp = next;
		struct dentry *dentry = list_entry(tmp, struct dentry, d_u.d_child);
		next = tmp->next;
		if (d_unhashed(dentry)||!dentry->d_inode)
			continue;
		if (!list_empty(&dentry->d_subdirs)) {
			this_parent = dentry;
			goto repeat;
		}
		atomic_dec(&dentry->d_count);
	}
	if (this_parent != root) {
		next = this_parent->d_u.d_child.next;
		atomic_dec(&this_parent->d_count);
		this_parent = this_parent->d_parent;
		goto resume;
	}
	spin_unlock(&dcache_lock);
}

/**
 * find_inode_number - check for dentry with name
 * @dir: directory to check
 * @name: Name to find.
 *
 * Check whether a dentry already exists for the given name,
 * and return the inode number if it has an inode. Otherwise
 * 0 is returned.
 *
 * This routine is used to post-process directory listings for
 * filesystems using synthetic inode numbers, and is necessary
 * to keep getcwd() working.
 */
 
ino_t find_inode_number(struct dentry *dir, struct qstr *name)
{
	struct dentry * dentry;
	ino_t ino = 0;

	dentry = d_hash_and_lookup(dir, name);
	if (dentry) {
		if (dentry->d_inode)
			ino = dentry->d_inode->i_ino;
		dput(dentry);
	}
	return ino;
}

static __initdata unsigned long dhash_entries;
static int __init set_dhash_entries(char *str)
{
	if (!str)
		return 0;
	dhash_entries = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("dhash_entries=", set_dhash_entries);

static void __init dcache_init_early(void)
{
	unsigned int loop;

	/* If hashes are distributed across NUMA nodes, defer
	 * hash allocation until vmalloc space is available.
	 */
	if (hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_head),
					dhash_entries,
					13,
					HASH_EARLY,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1U << d_hash_shift); loop++)
		INIT_HLIST_HEAD(&dentry_hashtable[loop]);
}

static void __init dcache_init(void)
{
	unsigned int loop;

	/* 
	 * A constructor could be added for stable state like the lists,
	 * but it is probably not worth it because of the cache nature
	 * of the dcache. 
	 */
	dentry_cache = KMEM_CACHE(dentry,
		SLAB_RECLAIM_ACCOUNT|SLAB_PANIC|SLAB_MEM_SPREAD);
	
	register_shrinker(&dcache_shrinker);

	/* Hash may have been set up in dcache_init_early */
	if (!hashdist)
		return;

	dentry_hashtable =
		alloc_large_system_hash("Dentry cache",
					sizeof(struct hlist_head),
					dhash_entries,
					13,
					0,
					&d_hash_shift,
					&d_hash_mask,
					0);

	for (loop = 0; loop < (1U << d_hash_shift); loop++)
		INIT_HLIST_HEAD(&dentry_hashtable[loop]);
}

/* SLAB cache for __getname() consumers */
struct kmem_cache *names_cachep __read_mostly;

EXPORT_SYMBOL(d_genocide);

void __init vfs_caches_init_early(void)
{
	dcache_init_early();
	inode_init_early();
}

void __init vfs_caches_init(unsigned long mempages)
{
	unsigned long reserve;

	/* Base hash sizes on available memory, with a reserve equal to
           150% of current kernel size */

	reserve = min((mempages - nr_free_pages()) * 3/2, mempages - 1);
	mempages -= reserve;

	names_cachep = kmem_cache_create("names_cache", PATH_MAX, 0,
			SLAB_HWCACHE_ALIGN|SLAB_PANIC, NULL);

	dcache_init();
	inode_init();
	files_init(mempages);
	mnt_init();
	bdev_cache_init();
	chrdev_init();
	dcache_time_init();
}

EXPORT_SYMBOL(d_alloc);
EXPORT_SYMBOL(d_alloc_root);
EXPORT_SYMBOL(d_delete);
EXPORT_SYMBOL(d_find_alias);
EXPORT_SYMBOL(d_instantiate);
EXPORT_SYMBOL(d_invalidate);
EXPORT_SYMBOL(d_lookup);
EXPORT_SYMBOL(d_move);
EXPORT_SYMBOL_GPL(d_materialise_unique);
EXPORT_SYMBOL(d_path);
EXPORT_SYMBOL(d_prune_aliases);
EXPORT_SYMBOL(d_rehash);
EXPORT_SYMBOL(d_splice_alias);
EXPORT_SYMBOL(d_add_ci);
EXPORT_SYMBOL(d_validate);
EXPORT_SYMBOL(dget_locked);
EXPORT_SYMBOL(dput);
EXPORT_SYMBOL(dput_nocache);
EXPORT_SYMBOL(find_inode_number);
EXPORT_SYMBOL(have_submounts);
EXPORT_SYMBOL(names_cachep);
EXPORT_SYMBOL(shrink_dcache_parent);
EXPORT_SYMBOL(shrink_dcache_sb);
