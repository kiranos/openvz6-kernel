/*
 *	linux/mm/mlock.c
 *
 *  (C) Copyright 1995 Linus Torvalds
 *  (C) Copyright 2002 Christoph Hellwig
 */

#include <linux/capability.h>
#include <linux/mman.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagemap.h>
#include <linux/mempolicy.h>
#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/rmap.h>
#include <linux/mmzone.h>
#include <linux/mmgang.h>
#include <linux/hugetlb.h>
#include <bc/vmpages.h>

#include "internal.h"

int can_do_mlock(void)
{
	if (capable(CAP_IPC_LOCK))
		return 1;
	if (current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur != 0)
		return 1;
	return 0;
}
EXPORT_SYMBOL(can_do_mlock);

/*
 * Mlocked pages are marked with PageMlocked() flag for efficient testing
 * in vmscan and, possibly, the fault path; and to support semi-accurate
 * statistics.
 *
 * An mlocked page [PageMlocked(page)] is unevictable.  As such, it will
 * be placed on the LRU "unevictable" list, rather than the [in]active lists.
 * The unevictable list is an LRU sibling list to the [in]active lists.
 * PageUnevictable is set to indicate the unevictable state.
 *
 * When lazy mlocking via vmscan, it is important to ensure that the
 * vma's VM_LOCKED status is not concurrently being modified, otherwise we
 * may have mlocked a page that is being munlocked. So lazy mlock must take
 * the mmap_sem for read, and verify that the vma really is locked
 * (see mm/rmap.c).
 */

/*
 *  LRU accounting for clear_page_mlock()
 */
void __clear_page_mlock(struct page *page)
{
	VM_BUG_ON(!PageLocked(page));

	if (!page->mapping) {	/* truncated ? */
		return;
	}

	dec_zone_page_state(page, NR_MLOCK);
	count_vm_event(UNEVICTABLE_PGCLEARED);
	if (!isolate_lru_page(page)) {
		putback_lru_page(page);
	} else {
		/*
		 * We lost the race. the page already moved to evictable list.
		 */
		if (PageUnevictable(page))
			count_vm_event(UNEVICTABLE_PGSTRANDED);
	}
}

/*
 * Mark page as mlocked if not already.
 * If page on LRU, isolate and putback to move to unevictable list.
 */
void mlock_vma_page(struct vm_area_struct *vma, struct page *page)
{
	/* Serialize with page migration */
	BUG_ON(!PageLocked(page));

	if (!TestSetPageMlocked(page)) {
		inc_zone_page_state(page, NR_MLOCK);
		count_vm_event(UNEVICTABLE_PGMLOCKED);
		if (!isolate_lru_page(page)) {
			struct gang_set *gs = get_mm_gang(vma->vm_mm);

			if (!page_in_gang(page, gs))
				gang_mod_user_page(page, gs,
						GFP_ATOMIC|__GFP_NOFAIL);

			putback_lru_page(page);
		}
	}
}
EXPORT_SYMBOL(mlock_vma_page);

/*
 * called from munlock()/munmap() path with page supposedly on the LRU.
 *
 * Note:  unlike mlock_vma_page(), we can't just clear the PageMlocked
 * [in try_to_munlock()] and then attempt to isolate the page.  We must
 * isolate the page to keep others from messing with its unevictable
 * and mlocked state while trying to munlock.  However, we pre-clear the
 * mlocked state anyway as we might lose the isolation race and we might
 * not get another chance to clear PageMlocked.  If we successfully
 * isolate the page and try_to_munlock() detects other VM_LOCKED vmas
 * mapping the page, it will restore the PageMlocked state, unless the page
 * is mapped in a non-linear vma.  So, we go ahead and ClearPageMlocked(),
 * perhaps redundantly.
 * If we lose the isolation race, and the page is mapped by other VM_LOCKED
 * vmas, we'll detect this in vmscan--via try_to_munlock() or try_to_unmap()
 * either of which will restore the PageMlocked state by calling
 * mlock_vma_page() above, if it can grab the vma's mmap sem.
 */
void munlock_vma_page(struct page *page)
{
	/* For try_to_munlock() and to serialize with page migration */
	BUG_ON(!PageLocked(page));

	if (TestClearPageMlocked(page)) {
		dec_zone_page_state(page, NR_MLOCK);
		if (!isolate_lru_page(page)) {
			int ret = try_to_munlock(page);
			/*
			 * did try_to_unlock() succeed or punt?
			 */
			if (ret != SWAP_MLOCK)
				count_vm_event(UNEVICTABLE_PGMUNLOCKED);

			putback_lru_page(page);
		} else {
			/*
			 * We lost the race.  let try_to_unmap() deal
			 * with it.  At least we get the page state and
			 * mlock stats right.  However, page is still on
			 * the noreclaim list.  We'll fix that up when
			 * the page is eventually freed or we scan the
			 * noreclaim list.
			 */
			if (PageUnevictable(page))
				count_vm_event(UNEVICTABLE_PGSTRANDED);
			else
				count_vm_event(UNEVICTABLE_PGMUNLOCKED);
		}
	}
}
EXPORT_SYMBOL(munlock_vma_page);

/**
 * __mlock_vma_pages_range() -  mlock a range of pages in the vma.
 * @vma:   target vma
 * @start: start address
 * @end:   end address
 *
 * This takes care of making the pages present too.
 *
 * return 0 on success, negative error code on error.
 *
 * vma->vm_mm->mmap_sem must be held for at least read.
 */
static long __mlock_vma_pages_range(struct vm_area_struct *vma,
				    unsigned long start, unsigned long end)
{
	struct mm_struct *mm = vma->vm_mm;
	unsigned long addr = start;
	struct page *pages[16]; /* 16 gives a reasonable batch */
	int nr_pages = (end - start) / PAGE_SIZE;
	int ret = 0;
	int gup_flags;

	VM_BUG_ON(start & ~PAGE_MASK);
	VM_BUG_ON(end   & ~PAGE_MASK);
	VM_BUG_ON(start < vma->vm_start);
	VM_BUG_ON(end   > vma->vm_end);
	VM_BUG_ON(!rwsem_is_locked(&mm->mmap_sem));

	gup_flags = FOLL_TOUCH | FOLL_GET;
	/*
	 * We want to touch writable mappings with a write fault in order
	 * to break COW, except for shared mappings because these don't COW
	 * and we would not want to dirty them for nothing.
	 */
	if ((vma->vm_flags & (VM_WRITE | VM_SHARED)) == VM_WRITE)
		gup_flags |= FOLL_WRITE;

	/*
	 * We want mlock to succeed for regions that have any permissions
	 * other than PROT_NONE.
	 */
	if (vma->vm_flags & (VM_READ | VM_WRITE | VM_EXEC))
		gup_flags |= FOLL_FORCE;

	while (nr_pages > 0) {
		int i;

		cond_resched();

		/*
		 * get_user_pages makes pages present if we are
		 * setting mlock. and this extra reference count will
		 * disable migration of this page.  However, page may
		 * still be truncated out from under us.
		 */
		ret = __get_user_pages(current, mm, addr,
				min_t(int, nr_pages, ARRAY_SIZE(pages)),
				gup_flags, pages, NULL);
		/*
		 * This can happen for, e.g., VM_NONLINEAR regions before
		 * a page has been allocated and mapped at a given offset,
		 * or for addresses that map beyond end of a file.
		 * We'll mlock the pages if/when they get faulted in.
		 */
		if (ret < 0)
			break;

		lru_add_drain();	/* push cached pages to LRU */

		for (i = 0; i < ret; i++) {
			struct page *page = pages[i];

			if (page->mapping) {
				/*
				 * That preliminary check is mainly to avoid
				 * the pointless overhead of lock_page on the
				 * ZERO_PAGE: which might bounce very badly if
				 * there is contention.  However, we're still
				 * dirtying its cacheline with get/put_page:
				 * we'll add another __get_user_pages flag to
				 * avoid it if that case turns out to matter.
				 */
				lock_page(page);
				/*
				 * Because we lock page here and migration is
				 * blocked by the elevated reference, we need
				 * only check for file-cache page truncation.
				 */
				if (page->mapping)
					mlock_vma_page(vma, page);
				unlock_page(page);
			}
			put_page(page);	/* ref from get_user_pages() */
		}

		addr += ret * PAGE_SIZE;
		nr_pages -= ret;
		ret = 0;
	}

	return ret;	/* 0 or negative error code */
}

/*
 * convert get_user_pages() return value to posix mlock() error
 */
static int __mlock_posix_error_return(long retval)
{
	if (retval == -EFAULT)
		retval = -ENOMEM;
	else if (retval == -ENOMEM)
		retval = -EAGAIN;
	return retval;
}

/**
 * mlock_vma_pages_range() - mlock pages in specified vma range.
 * @vma - the vma containing the specfied address range
 * @start - starting address in @vma to mlock
 * @end   - end address [+1] in @vma to mlock
 *
 * For mmap()/mremap()/expansion of mlocked vma.
 *
 * return 0 on success for "normal" vmas.
 *
 * return number of pages [> 0] to be removed from locked_vm on success
 * of "special" vmas.
 */
long mlock_vma_pages_range(struct vm_area_struct *vma,
			unsigned long start, unsigned long end)
{
	int nr_pages = (end - start) / PAGE_SIZE;
	BUG_ON(!(vma->vm_flags & VM_LOCKED));

	/*
	 * filter unlockable vmas
	 */
	if (vma->vm_flags & (VM_IO | VM_PFNMAP))
		goto no_mlock;

	if (!((vma->vm_flags & (VM_DONTEXPAND | VM_RESERVED)) ||
			is_vm_hugetlb_page(vma) ||
			vma == get_gate_vma(current->mm))) {

		__mlock_vma_pages_range(vma, start, end);

		/* Hide errors from mmap() and other callers */
		return 0;
	}

	/*
	 * User mapped kernel pages or huge pages:
	 * make these pages present to populate the ptes, but
	 * fall thru' to reset VM_LOCKED--no need to unlock, and
	 * return nr_pages so these don't get counted against task's
	 * locked limit.  huge pages are already counted against
	 * locked vm limit.
	 */
	make_pages_present(start, end);

no_mlock:
	vma->vm_flags &= ~VM_LOCKED;	/* and don't come back! */
	return nr_pages;		/* error or pages NOT mlocked */
}

/*
 * munlock_vma_pages_range() - munlock all pages in the vma range.'
 * @vma - vma containing range to be munlock()ed.
 * @start - start address in @vma of the range
 * @end - end of range in @vma.
 *
 *  For mremap(), munmap() and exit().
 *
 * Called with @vma VM_LOCKED.
 *
 * Returns with VM_LOCKED cleared.  Callers must be prepared to
 * deal with this.
 *
 * We don't save and restore VM_LOCKED here because pages are
 * still on lru.  In unmap path, pages might be scanned by reclaim
 * and re-mlocked by try_to_{munlock|unmap} before we unmap and
 * free them.  This will result in freeing mlocked pages.
 */
void __munlock_vma_pages_range(struct vm_area_struct *vma,
			     unsigned long start, unsigned long end, int acct)
{
	unsigned long addr;

	lru_add_drain();
	if (acct)
		ub_locked_uncharge(vma->vm_mm, end - start);
	vma->vm_flags &= ~VM_LOCKED;

	for (addr = start; addr < end; addr += PAGE_SIZE) {
		struct page *page;
		/*
		 * Although FOLL_DUMP is intended for get_dump_page(),
		 * it just so happens that its special treatment of the
		 * ZERO_PAGE (returning an error instead of doing get_page)
		 * suits munlock very well (and if somehow an abnormal page
		 * has sneaked into the range, we won't oops here: great).
		 */
		page = follow_page(vma, addr, FOLL_GET | FOLL_DUMP);
		if (page && !IS_ERR(page)) {
			lock_page(page);
			/*
			 * Like in __mlock_vma_pages_range(),
			 * because we lock page here and migration is
			 * blocked by the elevated reference, we need
			 * only check for file-cache page truncation.
			 */
			if (page->mapping)
				munlock_vma_page(page);
			unlock_page(page);
			put_page(page);
		}
		cond_resched();
	}
}

/*
 * mlock_fixup  - handle mlock[all]/munlock[all] requests.
 *
 * Filters out "special" vmas -- VM_LOCKED never gets set for these, and
 * munlock is a no-op.  However, for some special vmas, we go ahead and
 * populate the ptes via make_pages_present().
 *
 * For vmas that pass the filters, merge/split as appropriate.
 */
static int mlock_fixup(struct vm_area_struct *vma, struct vm_area_struct **prev,
	unsigned long start, unsigned long end, vm_flags_t newflags,
	bool convert_error)
{
	struct mm_struct *mm = vma->vm_mm;
	pgoff_t pgoff;
	int nr_pages;
	int ret = 0;
	int lock = !!(newflags & VM_LOCKED);

	if (newflags == vma->vm_flags ||
			(vma->vm_flags & (VM_IO | VM_PFNMAP)))
		goto out;	/* don't set VM_LOCKED,  don't count */

	if ((vma->vm_flags & (VM_DONTEXPAND | VM_RESERVED)) ||
			is_vm_hugetlb_page(vma) ||
			vma == get_gate_vma(current->mm)) {
		if (lock)
			make_pages_present(start, end);
		goto out;	/* don't set VM_LOCKED,  don't count */
	}

	if (newflags & VM_LOCKED) {
		ret = ub_locked_charge(mm, end - start);
		if (ret < 0)
			goto out;
	}

	pgoff = vma->vm_pgoff + ((start - vma->vm_start) >> PAGE_SHIFT);
	*prev = vma_merge(mm, *prev, start, end, newflags, vma->anon_vma,
			  vma->vm_file, pgoff, vma_policy(vma));
	if (*prev) {
		vma = *prev;
		goto success;
	}

	if (start != vma->vm_start) {
		ret = split_vma(mm, vma, start, 1);
		if (ret)
			goto out_uncharge;
	}

	if (end != vma->vm_end) {
		ret = split_vma(mm, vma, end, 0);
		if (ret)
			goto out_uncharge;
	}

success:
	/*
	 * Keep track of amount of locked VM.
	 */
	nr_pages = (end - start) >> PAGE_SHIFT;
	if (!lock)
		nr_pages = -nr_pages;
	mm->locked_vm += nr_pages;

	/*
	 * vm_flags is protected by the mmap_sem held in write mode.
	 * It's okay if try_to_unmap_one unmaps a page just after we
	 * set VM_LOCKED, __mlock_vma_pages_range will bring it back.
	 */

	if (lock) {
		vma->vm_flags = newflags;
		ret = __mlock_vma_pages_range(vma, start, end);
		if ((ret < 0) && (convert_error == true))
			ret = __mlock_posix_error_return(ret);
	} else {
		munlock_vma_pages_range(vma, start, end);
	}

out:
	*prev = vma;
	return ret;

out_uncharge:
	if (newflags & VM_LOCKED)
		ub_locked_uncharge(mm, end - start);
	goto out;
}

static int do_mlock(unsigned long start, size_t len, int on, bool convert_error)
{
	unsigned long nstart, end, tmp;
	struct vm_area_struct * vma, * prev;
	int error;

	len = PAGE_ALIGN(len);
	end = start + len;
	if (end < start)
		return -EINVAL;
	if (end == start)
		return 0;
	vma = find_vma_prev(current->mm, start, &prev);
	if (!vma || vma->vm_start > start)
		return -ENOMEM;

	if (start > vma->vm_start)
		prev = vma;

	for (nstart = start ; ; ) {
		vm_flags_t newflags;

		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */

		newflags = vma->vm_flags | VM_LOCKED;
		if (!on)
			newflags &= ~VM_LOCKED;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mlock_fixup(vma, &prev, nstart, tmp, newflags, convert_error);
		if (error)
			break;
		nstart = tmp;
		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			break;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			break;
		}
	}
	return error;
}

int __mlock(unsigned long start, size_t len, bool convert_error)
{
	unsigned long locked;
	unsigned long lock_limit;
	int error = -ENOMEM;

	if (!can_do_mlock())
		return -EPERM;

	lru_add_drain_all();	/* flush pagevec */

	down_write(&current->mm->mmap_sem);
	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
	start &= PAGE_MASK;

	locked = len >> PAGE_SHIFT;
	locked += current->mm->locked_vm;

	lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
	lock_limit >>= PAGE_SHIFT;

	/* check against resource limits */
	if ((locked <= lock_limit) || capable(CAP_IPC_LOCK))
		error = do_mlock(start, len, 1, convert_error);
	up_write(&current->mm->mmap_sem);
	return error;
}
EXPORT_SYMBOL_GPL(__mlock);

SYSCALL_DEFINE2(mlock, unsigned long, start, size_t, len)
{
	return __mlock(start, len, true);
}

int __munlock(unsigned long start, size_t len, bool convert_error)
{
	int ret;

	down_write(&current->mm->mmap_sem);
	len = PAGE_ALIGN(len + (start & ~PAGE_MASK));
	start &= PAGE_MASK;
	ret = do_mlock(start, len, 0, convert_error);
	up_write(&current->mm->mmap_sem);
	return ret;
}
EXPORT_SYMBOL_GPL(__munlock);

SYSCALL_DEFINE2(munlock, unsigned long, start, size_t, len)
{
	return __munlock(start, len, true);
}

static int do_mlockall(int flags)
{
	struct vm_area_struct * vma, * prev = NULL;
	unsigned int def_flags = 0;

	if (flags & MCL_FUTURE)
		def_flags = VM_LOCKED;
	current->mm->def_flags = def_flags;
	if (flags == MCL_FUTURE)
		goto out;

	for (vma = current->mm->mmap; vma ; vma = prev->vm_next) {
		vm_flags_t newflags;

		newflags = vma->vm_flags | VM_LOCKED;
		if (!(flags & MCL_CURRENT))
			newflags &= ~VM_LOCKED;

		/* Ignore errors */
		mlock_fixup(vma, &prev, vma->vm_start, vma->vm_end, newflags, true);
	}
out:
	return 0;
}

SYSCALL_DEFINE1(mlockall, int, flags)
{
	unsigned long lock_limit;
	int ret = -EINVAL;

	if (!flags || (flags & ~(MCL_CURRENT | MCL_FUTURE)))
		goto out;

	ret = -EPERM;
	if (!can_do_mlock())
		goto out;

	lru_add_drain_all();	/* flush pagevec */

	down_write(&current->mm->mmap_sem);

	lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
	lock_limit >>= PAGE_SHIFT;

	ret = -ENOMEM;
	if (!(flags & MCL_CURRENT) || (current->mm->total_vm <= lock_limit) ||
	    capable(CAP_IPC_LOCK))
		ret = do_mlockall(flags);
	up_write(&current->mm->mmap_sem);
out:
	return ret;
}

SYSCALL_DEFINE0(munlockall)
{
	int ret;

	down_write(&current->mm->mmap_sem);
	ret = do_mlockall(0);
	up_write(&current->mm->mmap_sem);
	return ret;
}

/*
 * Objects with different lifetime than processes (SHM_LOCK and SHM_HUGETLB
 * shm segments) get accounted against the user_struct instead.
 */
static DEFINE_SPINLOCK(shmlock_user_lock);

int user_shm_lock(size_t size, struct user_struct *user)
{
	unsigned long lock_limit, locked;
	int allowed = 0;

	locked = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	lock_limit = current->signal->rlim[RLIMIT_MEMLOCK].rlim_cur;
	if (lock_limit == RLIM_INFINITY)
		allowed = 1;
	lock_limit >>= PAGE_SHIFT;
	spin_lock(&shmlock_user_lock);
	if (!allowed &&
	    locked + user->locked_shm > lock_limit && !capable(CAP_IPC_LOCK))
		goto out;
	get_uid(user);
	user->locked_shm += locked;
	allowed = 1;
out:
	spin_unlock(&shmlock_user_lock);
	return allowed;
}

void user_shm_unlock(size_t size, struct user_struct *user)
{
	spin_lock(&shmlock_user_lock);
	user->locked_shm -= (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
	spin_unlock(&shmlock_user_lock);
	free_uid(user);
}
