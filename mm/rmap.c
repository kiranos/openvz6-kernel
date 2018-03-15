/*
 * mm/rmap.c - physical to virtual reverse mappings
 *
 * Copyright 2001, Rik van Riel <riel@conectiva.com.br>
 * Released under the General Public License (GPL).
 *
 * Simple, low overhead reverse mapping scheme.
 * Please try to keep this thing as modular as possible.
 *
 * Provides methods for unmapping each kind of mapped page:
 * the anon methods track anonymous pages, and
 * the file methods track pages belonging to an inode.
 *
 * Original design by Rik van Riel <riel@conectiva.com.br> 2001
 * File methods by Dave McCracken <dmccr@us.ibm.com> 2003, 2004
 * Anonymous methods by Andrea Arcangeli <andrea@suse.de> 2004
 * Contributions by Hugh Dickins 2003, 2004
 */

/*
 * Lock ordering in mm:
 *
 * inode->i_mutex	(while writing or truncating, not reading or faulting)
 *   inode->i_alloc_sem (vmtruncate_range)
 *   mm->mmap_sem
 *     page->flags PG_locked (lock_page)
 *       mapping->i_mmap_lock
 *         anon_vma->lock
 *           mm->page_table_lock or pte_lock
 *             zone->lru_lock (in mark_page_accessed, isolate_lru_page)
 *             swap_lock (in swap_duplicate, swap_info_get)
 *               mmlist_lock (in mmput, drain_mmlist and others)
 *               mapping->private_lock (in __set_page_dirty_buffers)
 *               inode_lock (in set_page_dirty's __mark_inode_dirty)
 *                 sb_lock (within inode_lock in fs/fs-writeback.c)
 *                 mapping->tree_lock (widely used, in set_page_dirty,
 *                           in arch-dependent flush_dcache_mmap_lock,
 *                           within inode_lock in __sync_single_inode)
 *
 * (code doesn't rely on that order so it could be switched around)
 * ->tasklist_lock
 *   anon_vma->lock      (memory_failure, collect_procs_anon)
 *     pte map lock
 */

#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/ksm.h>
#include <linux/rmap.h>
#include <linux/rcupdate.h>
#include <linux/module.h>
#include <linux/memcontrol.h>
#include <linux/mmgang.h>
#include <linux/mmu_notifier.h>
#include <linux/migrate.h>
#include <linux/hugetlb.h>
#include <linux/backing-dev.h>
#include <trace/events/kmem.h>

#include <bc/beancounter.h>
#include <bc/vmpages.h>
#include <bc/kmem.h>

#include <asm/tlbflush.h>

#include "internal.h"

static struct kmem_cache *anon_vma_cachep;
static struct kmem_cache *anon_vma_chain_cachep;

static inline struct anon_vma *anon_vma_alloc(struct mm_struct *mm)
{
	struct user_beancounter *ub = mm_ub_top(mm);
	struct anon_vma *anon_vma;

	anon_vma =  ub_kmem_alloc(ub, anon_vma_cachep, GFP_KERNEL);
	if (anon_vma) {
		anon_vma->degree = 1;	/* Reference for first vma */
		anon_vma->parent = anon_vma;
		anon_vma->anon_vma_ub = get_beancounter(ub);
	}

	return anon_vma;
}

void anon_vma_free(struct anon_vma *anon_vma)
{
	struct user_beancounter *ub = anon_vma->anon_vma_ub;
	ub_kmem_free(ub, anon_vma_cachep, anon_vma);
	put_beancounter(ub);
}

#define anon_vma_chain_alloc(mm, gfp) \
	ub_kmem_alloc(mm_ub_top(mm), anon_vma_chain_cachep, gfp)
#define anon_vma_chain_free(mm, avc) \
	ub_kmem_free(mm_ub_top(mm), anon_vma_chain_cachep, avc)

/**
 * anon_vma_prepare - attach an anon_vma to a memory region
 * @vma: the memory region in question
 *
 * This makes sure the memory mapping described by 'vma' has
 * an 'anon_vma' attached to it, so that we can associate the
 * anonymous pages mapped into it with that anon_vma.
 *
 * The common case will be that we already have one, but if
 * if not we either need to find an adjacent mapping that we
 * can re-use the anon_vma from (very common when the only
 * reason for splitting a vma has been mprotect()), or we
 * allocate a new one.
 *
 * Anon-vma allocations are very subtle, because we may have
 * optimistically looked up an anon_vma in page_lock_anon_vma()
 * and that may actually touch the spinlock even in the newly
 * allocated vma (it depends on RCU to make sure that the
 * anon_vma isn't actually destroyed).
 *
 * As a result, we need to do proper anon_vma locking even
 * for the new allocation. At the same time, we do not want
 * to do any locking for the common case of already having
 * an anon_vma.
 *
 * This must be called with the mmap_sem held for reading.
 */
int anon_vma_prepare(struct vm_area_struct *vma)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	struct anon_vma_chain *avc;

	might_sleep();
	if (unlikely(!anon_vma)) {
		struct mm_struct *mm = vma->vm_mm;
		struct anon_vma *allocated;

		avc = anon_vma_chain_alloc(mm, GFP_KERNEL);
		if (!avc)
			goto out_enomem;

		anon_vma = find_mergeable_anon_vma(vma);
		allocated = NULL;
		if (!anon_vma) {
			anon_vma = anon_vma_alloc(mm);
			if (unlikely(!anon_vma))
				goto out_enomem_free_avc;
			allocated = anon_vma;
			/*
			 * This VMA had no anon_vma yet.  This anon_vma is
			 * the root of any anon_vma tree that might form.
			 */
			anon_vma->root = anon_vma;
		}

		anon_vma_lock(anon_vma);
		/* page_table_lock to protect against threads */
		spin_lock(&mm->page_table_lock);
		if (likely(!vma->anon_vma)) {
			vma->anon_vma = anon_vma;
			avc->anon_vma = anon_vma;
			avc->vma = vma;
			list_add(&avc->same_vma, &vma->anon_vma_chain);
			list_add_tail(&avc->same_anon_vma, &anon_vma->head);
			/* vma reference or self-parent link for new root */
			anon_vma->degree++;
			allocated = NULL;
			avc = NULL;
		}
		spin_unlock(&mm->page_table_lock);
		anon_vma_unlock(anon_vma);

		if (unlikely(allocated))
			anon_vma_free(allocated);
		if (unlikely(avc))
			anon_vma_chain_free(mm, avc);
	}
	return 0;

 out_enomem_free_avc:
	anon_vma_chain_free(vma->vm_mm, avc);
 out_enomem:
	return -ENOMEM;
}
EXPORT_SYMBOL(anon_vma_prepare);

/*
 * This is a useful helper function for locking the anon_vma root as
 * we traverse the vma->anon_vma_chain, looping over anon_vma's that
 * have the same vma.
 *
 * Such anon_vma's should have the same root, so you'd expect to see
 * just a single mutex_lock for the whole traversal.
 */
static inline struct anon_vma *lock_anon_vma_root(struct anon_vma *root, struct anon_vma *anon_vma)
{
	struct anon_vma *new_root = anon_vma->root;
	if (new_root != root) {
		if (WARN_ON_ONCE(root))
			spin_unlock(&root->lock);
		root = new_root;
		spin_lock(&root->lock);
	}
	return root;
}

static inline void unlock_anon_vma_root(struct anon_vma *root)
{
	if (root)
		spin_unlock(&root->lock);
}

static void anon_vma_chain_link(struct vm_area_struct *vma,
				struct anon_vma_chain *avc,
				struct anon_vma *anon_vma)
{
	avc->vma = vma;
	avc->anon_vma = anon_vma;
	list_add(&avc->same_vma, &vma->anon_vma_chain);

	/*
	 * It's critical to add new vmas to the tail of the anon_vma,
	 * see comment in huge_memory.c:__split_huge_page().
	 */
	list_add_tail(&avc->same_anon_vma, &anon_vma->head);
}

/*
 * Attach the anon_vmas from src to dst.
 * Returns 0 on success, -ENOMEM on failure.
 *
 * If dst->anon_vma is NULL this function tries to find and reuse existing
 * anon_vma which has no vmas and only one child anon_vma. This prevents
 * degradation of anon_vma hierarchy to endless linear chain in case of
 * constantly forking task. On the other hand, an anon_vma with more than one
 * child isn't reused even if there was no alive vma, thus rmap walker has a
 * good chance of avoiding scanning the whole hierarchy when it searches where
 * page is mapped.
 */
int anon_vma_clone(struct vm_area_struct *dst, struct vm_area_struct *src)
{
	struct anon_vma_chain *avc, *pavc;
	struct anon_vma *root = NULL;

	list_for_each_entry_reverse(pavc, &src->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma;

		avc = anon_vma_chain_alloc(dst->vm_mm, GFP_NOWAIT | __GFP_NOWARN);
		if (unlikely(!avc)) {
			unlock_anon_vma_root(root);
			root = NULL;
			avc = anon_vma_chain_alloc(dst->vm_mm, GFP_KERNEL);
			if (!avc)
				goto enomem_failure;
		}
		anon_vma = pavc->anon_vma;
		root = lock_anon_vma_root(root, anon_vma);
		anon_vma_chain_link(dst, avc, anon_vma);

		/*
		 * Reuse existing anon_vma if its degree lower than two,
		 * that means it has no vma and only one anon_vma child.
		 *
		 * Do not chose parent anon_vma, otherwise first child
		 * will always reuse it. Root anon_vma is never reused:
		 * it has self-parent reference and at least one child.
		 */
		if (!dst->anon_vma && anon_vma != src->anon_vma &&
				anon_vma->degree < 2)
			dst->anon_vma = anon_vma;
	}
	if (dst->anon_vma)
		dst->anon_vma->degree++;
	unlock_anon_vma_root(root);
	return 0;

 enomem_failure:
	/*
	 * dst->anon_vma is dropped here otherwise its degree can be incorrectly
	 * decremented in unlink_anon_vmas().
	 * We can safely do this because callers of anon_vma_clone() don't care
	 * about dst->anon_vma if anon_vma_clone() failed.
	 */
	dst->anon_vma = NULL;
	unlink_anon_vmas(dst);
	return -ENOMEM;
}

/*
 * Some rmap walk that needs to find all ptes/hugepmds without false
 * negatives (like migrate and split_huge_page) running concurrent
 * with operations that copy or move pagetables (like mremap() and
 * fork()) to be safe. They depend on the anon_vma "same_anon_vma"
 * list to be in a certain order: the dst_vma must be placed after the
 * src_vma in the list. This is always guaranteed by fork() but
 * mremap() needs to call this function to enforce it in case the
 * dst_vma isn't newly allocated and chained with the anon_vma_clone()
 * function but just an extension of a pre-existing vma through
 * vma_merge.
 *
 * NOTE: the same_anon_vma list can still be changed by other
 * processes while mremap runs because mremap doesn't hold the
 * anon_vma mutex to prevent modifications to the list while it
 * runs. All we need to enforce is that the relative order of this
 * process vmas isn't changing (we don't care about other vmas
 * order). Each vma corresponds to an anon_vma_chain structure so
 * there's no risk that other processes calling anon_vma_moveto_tail()
 * and changing the same_anon_vma list under mremap() will screw with
 * the relative order of this process vmas in the list, because we
 * they can't alter the order of any vma that belongs to this
 * process. And there can't be another anon_vma_moveto_tail() running
 * concurrently with mremap() coming from this process because we hold
 * the mmap_sem for the whole mremap(). fork() ordering dependency
 * also shouldn't be affected because fork() only cares that the
 * parent vmas are placed in the list before the child vmas and
 * anon_vma_moveto_tail() won't reorder vmas from either the fork()
 * parent or child.
 */
void anon_vma_moveto_tail(struct vm_area_struct *dst)
{
	struct anon_vma_chain *pavc;
	struct anon_vma *root = NULL;

	list_for_each_entry_reverse(pavc, &dst->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = pavc->anon_vma;
		VM_BUG_ON(pavc->vma != dst);
		root = lock_anon_vma_root(root, anon_vma);
		list_del(&pavc->same_anon_vma);
		list_add_tail(&pavc->same_anon_vma, &anon_vma->head);
	}
	unlock_anon_vma_root(root);
}

/*
 * Attach vma to its own anon_vma, as well as to the anon_vmas that
 * the corresponding VMA in the parent process is attached to.
 * Returns 0 on success, non-zero on failure.
 */
int anon_vma_fork(struct vm_area_struct *vma, struct vm_area_struct *pvma)
{
	struct anon_vma_chain *avc;
	struct anon_vma *anon_vma;

	/* Don't bother if the parent process has no anon_vma here. */
	if (!pvma->anon_vma)
		return 0;

	/* Drop inherited anon_vma, we'll reuse existing or allocate new. */
	vma->anon_vma = NULL;

	/*
	 * First, attach the new VMA to the parent VMA's anon_vmas,
	 * so rmap can find non-COWed pages in child processes.
	 */
	if (anon_vma_clone(vma, pvma))
		return -ENOMEM;

	/* An existing anon_vma has been reused, all done then. */
	if (vma->anon_vma)
		return 0;

	/* Then add our own anon_vma. */
	anon_vma = anon_vma_alloc(vma->vm_mm);
	if (!anon_vma)
		goto out_error;
	avc = anon_vma_chain_alloc(vma->vm_mm, GFP_KERNEL);
	if (!avc)
		goto out_error_free_anon_vma;

	anon_vma->root = pvma->anon_vma->root;
	anon_vma->parent = pvma->anon_vma;
	/*
	 * With KSM refcounts, an anon_vma can stay around longer than the
	 * process it belongs to.  The root anon_vma needs to be pinned
	 * until this anon_vma is freed, because that is where the lock lives.
	 */
	get_anon_vma(anon_vma->root);
	/* Mark this anon_vma as the one where our new (COWed) pages go. */
	vma->anon_vma = anon_vma;
	anon_vma_lock(anon_vma);
	anon_vma_chain_link(vma, avc, anon_vma);
	anon_vma->parent->degree++;
	anon_vma_unlock(anon_vma);

	return 0;

 out_error_free_anon_vma:
	anon_vma_free(anon_vma);
 out_error:
	unlink_anon_vmas(vma);
	return -ENOMEM;
}

int anon_vma_link(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc;
	struct anon_vma *anon_vma = vma->anon_vma;

	avc = anon_vma_chain_alloc(vma->vm_mm, GFP_KERNEL);
	if (!avc)
		goto enomem_failure;

	anon_vma_lock(anon_vma);
	anon_vma_chain_link(vma, avc, anon_vma);
	anon_vma->parent->degree++;
	anon_vma_unlock(anon_vma);
	return 0;

enomem_failure:
	return -ENOMEM;
}
EXPORT_SYMBOL(anon_vma_link);

void unlink_anon_vmas(struct vm_area_struct *vma)
{
	struct anon_vma_chain *avc, *next;
	struct anon_vma *root = NULL;

	/* Unlink each anon_vma chained to the VMA, from newest to oldest. */
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		root = lock_anon_vma_root(root, anon_vma);
		list_del(&avc->same_anon_vma);

		/*
		 * Leave empty anon_vmas on the list - we'll need
		 * to free them outside the lock. However, if there
		 * is an externel refcount, its holder will free it.
		 */
		if (list_empty(&anon_vma->head)) {
			anon_vma->parent->degree--;
			if (!anonvma_external_refcount(anon_vma))
				continue;
		}

		list_del(&avc->same_vma);
		anon_vma_chain_free(vma->vm_mm, avc);
	}
	if (vma->anon_vma)
		vma->anon_vma->degree--;
	unlock_anon_vma_root(root);

	/*
	 * Iterate the list once more, it now only contains empty and unlinked
	 * anon_vmas, destroy them. Could not do before due to __put_anon_vma()
	 * needing to acquire the anon_vma->root->mutex.
	 */
	list_for_each_entry_safe(avc, next, &vma->anon_vma_chain, same_vma) {
		struct anon_vma *anon_vma = avc->anon_vma;

		BUG_ON(anon_vma->degree);

		/* We no longer need the root anon_vma */
		if (anon_vma->root != anon_vma)
			drop_anon_vma(anon_vma->root);
		anon_vma_free(anon_vma);

		list_del(&avc->same_vma);
		anon_vma_chain_free(vma->vm_mm, avc);
	}
}

static void anon_vma_ctor(void *data)
{
	struct anon_vma *anon_vma = data;

	spin_lock_init(&anon_vma->lock);
	anonvma_external_refcount_init(anon_vma);
	INIT_LIST_HEAD(&anon_vma->head);
}

void __init anon_vma_init(void)
{
	anon_vma_cachep = kmem_cache_create("anon_vma", sizeof(struct anon_vma),
			0, SLAB_DESTROY_BY_RCU|SLAB_PANIC, anon_vma_ctor);
	anon_vma_chain_cachep = KMEM_CACHE(anon_vma_chain, SLAB_PANIC);
}

/*
 * Getting a lock on a stable anon_vma from a page off the LRU is
 * tricky: page_lock_anon_vma rely on RCU to guard against the races.
 */
struct anon_vma *page_lock_anon_vma(struct page *page)
{
	struct anon_vma *anon_vma, *root_anon_vma;
	unsigned long anon_mapping;

	rcu_read_lock();
	anon_mapping = (unsigned long) ACCESS_ONCE(page->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS) != PAGE_MAPPING_ANON)
		goto out;
	if (!page_mapped(page))
		goto out;

	anon_vma = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	root_anon_vma = ACCESS_ONCE(anon_vma->root);
	spin_lock(&root_anon_vma->lock);

	/*
	 * If this page is still mapped, then its anon_vma cannot have been
	 * freed.  But if it has been unmapped, we have no security against
	 * the anon_vma structure being freed and reused (for another anon_vma:
	 * SLAB_DESTROY_BY_RCU guarantees that - so the spin_lock above cannot
	 * corrupt): with anon_vma_prepare() or anon_vma_fork() redirecting
	 * anon_vma->root before page_unlock_anon_vma() is called to unlock.
	 */
	if (page_mapped(page))
		return anon_vma;

	spin_unlock(&root_anon_vma->lock);
out:
	rcu_read_unlock();
	return NULL;
}
EXPORT_SYMBOL(page_lock_anon_vma);

void page_unlock_anon_vma(struct anon_vma *anon_vma)
{
	anon_vma_unlock(anon_vma);
	rcu_read_unlock();
}
EXPORT_SYMBOL(page_unlock_anon_vma);

/*
 * At what user virtual address is page expected in @vma?
 * Returns virtual address or -EFAULT if page's index/offset is not
 * within the range mapped the @vma.
 */
inline unsigned long
vma_address(struct page *page, struct vm_area_struct *vma)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	unsigned long address;

	if (unlikely(is_vm_hugetlb_page(vma)))
		pgoff = page->index << huge_page_order(page_hstate(page));
	address = vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
	if (unlikely(address < vma->vm_start || address >= vma->vm_end)) {
		/* page should be within @vma mapping range */
		return -EFAULT;
	}
	return address;
}
EXPORT_SYMBOL(vma_address);

/*
 * At what user virtual address is page expected in vma?
 * Caller should check the page is actually part of the vma.
 */
unsigned long page_address_in_vma(struct page *page, struct vm_area_struct *vma)
{
	if (PageAnon(page)) {
		struct anon_vma *page__anon_vma = page_anon_vma(page);
		/*
		 * Note: swapoff's unuse_vma() is more efficient with this
		 * check, and needs it to match anon_vma when KSM is active.
		 */
		if (!vma->anon_vma || !page__anon_vma ||
		    vma->anon_vma->root != page__anon_vma->root)
			return -EFAULT;
	} else if (page->mapping && !(vma->vm_flags & VM_NONLINEAR)) {
		if (!vma->vm_file ||
		    vma->vm_file->f_mapping != page->mapping)
			return -EFAULT;
	} else
		return -EFAULT;
	return vma_address(page, vma);
}

/*
 * Check that @page is mapped at @address into @mm.
 *
 * If @sync is false, page_check_address may perform a racy check to avoid
 * the page table lock when the pte is not present (helpful when reclaiming
 * highly shared pages).
 *
 * On success returns with pte mapped and locked.
 */
pte_t *page_check_address(struct page *page, struct mm_struct *mm,
			  unsigned long address, spinlock_t **ptlp, int sync)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;

	if (unlikely(PageHuge(page))) {
		/* when pud is not present, pte will be NULL */
		pte = huge_pte_offset(mm, address);
		if (!pte)
			return NULL;

		ptl = &mm->page_table_lock;
		goto check;
	}

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return NULL;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return NULL;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return NULL;
	if (pmd_trans_huge(*pmd))
		return NULL;

	pte = pte_offset_map(pmd, address);
	/* Make a quick check before getting the lock */
	if (!sync && !pte_present(*pte)) {
		pte_unmap(pte);
		return NULL;
	}

	ptl = pte_lockptr(mm, pmd);
check:
	spin_lock(ptl);
	if (pte_present(*pte) && page_to_pfn(page) == pte_pfn(*pte)) {
		*ptlp = ptl;
		return pte;
	}
	pte_unmap_unlock(pte, ptl);
	return NULL;
}

/**
 * page_mapped_in_vma - check whether a page is really mapped in a VMA
 * @page: the page to test
 * @vma: the VMA to test
 *
 * Returns 1 if the page is mapped into the page tables of the VMA, 0
 * if the page is not mapped into the page tables of this VMA.  Only
 * valid for normal file or anonymous VMAs.
 */
int page_mapped_in_vma(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address;
	pte_t *pte;
	spinlock_t *ptl;

	address = vma_address(page, vma);
	if (address == -EFAULT)		/* out of vma range */
		return 0;
	pte = page_check_address(page, vma->vm_mm, address, &ptl, 1);
	if (!pte)			/* the page is not in this mm */
		return 0;
	pte_unmap_unlock(pte, ptl);

	return 1;
}

/*
 * Subfunctions of page_referenced: page_referenced_one called
 * repeatedly from either page_referenced_anon or page_referenced_file.
 */
int page_referenced_one(struct page *page, struct vm_area_struct *vma,
			unsigned long address, unsigned int *mapcount,
			unsigned long *vm_flags)
{
	struct mm_struct *mm = vma->vm_mm;
	int referenced = 0;

	if (unlikely(PageTransHuge(page))) {
		pmd_t *pmd;

		spin_lock(&mm->page_table_lock);
		/*
		 * rmap might return false positives; we must filter
		 * these out using page_check_address_pmd().
		 */
		pmd = page_check_address_pmd(page, mm, address,
					     PAGE_CHECK_ADDRESS_PMD_FLAG);
		if (!pmd) {
			spin_unlock(&mm->page_table_lock);
			goto out;
		}

		if (vma->vm_flags & VM_LOCKED) {
			spin_unlock(&mm->page_table_lock);
			*mapcount = 0;	/* break early from loop */
			*vm_flags |= VM_LOCKED;
			goto out;
		}

		/* go ahead even if the pmd is pmd_trans_splitting() */
		if (pmdp_clear_flush_young_notify(vma, address, pmd))
			referenced++;
		spin_unlock(&mm->page_table_lock);
	} else {
		pte_t *pte;
		spinlock_t *ptl;

		/*
		 * rmap might return false positives; we must filter
		 * these out using page_check_address().
		 */
		pte = page_check_address(page, mm, address, &ptl, 0);
		if (!pte)
			goto out;

		if (vma->vm_flags & VM_LOCKED) {
			pte_unmap_unlock(pte, ptl);
			*mapcount = 0;	/* break early from loop */
			*vm_flags |= VM_LOCKED;
			goto out;
		}

		if (ptep_clear_flush_young_notify(vma, address, pte)) {
			/*
			 * Don't treat a reference through a sequentially read
			 * mapping as such.  If the page has been used in
			 * another mapping, we will catch it; if this other
			 * mapping is already gone, the unmap path will have
			 * set PG_referenced or activated the page.
			 */
			if (likely(!VM_SequentialReadHint(vma)))
				referenced++;
		}
		pte_unmap_unlock(pte, ptl);
	}

	/* Pretend the page is referenced if the task has the
	   swap token and is in the middle of a page fault. */
	if (mm != current->mm && has_swap_token(mm) &&
			rwsem_is_locked(&mm->mmap_sem))
		referenced++;

	(*mapcount)--;

	if (referenced)
		*vm_flags |= vma->vm_flags;
out:
	return referenced;
}

static int page_referenced_anon(struct page *page,
				struct mem_cgroup *mem_cont,
				unsigned long *vm_flags)
{
	unsigned int mapcount;
	struct anon_vma *anon_vma;
	struct anon_vma_chain *avc;
	int referenced = 0;

	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		return referenced;

	mapcount = page_mapcount(page);
	list_for_each_entry(avc, &anon_vma->head, same_anon_vma) {
		struct vm_area_struct *vma = avc->vma;
		unsigned long address = vma_address(page, vma);
		if (address == -EFAULT)
			continue;
		/*
		 * If we are reclaiming on behalf of a cgroup, skip
		 * counting on behalf of references from different
		 * cgroups
		 */
		if (mem_cont && !mm_match_cgroup(vma->vm_mm, mem_cont))
			continue;
		referenced += page_referenced_one(page, vma, address,
						  &mapcount, vm_flags);
		if (!mapcount)
			break;
	}

	page_unlock_anon_vma(anon_vma);
	return referenced;
}

/**
 * page_referenced_file - referenced check for object-based rmap
 * @page: the page we're checking references on.
 * @mem_cont: target memory controller
 * @vm_flags: collect encountered vma->vm_flags who actually referenced the page
 *
 * For an object-based mapped page, find all the places it is mapped and
 * check/clear the referenced flag.  This is done by following the page->mapping
 * pointer, then walking the chain of vmas it holds.  It returns the number
 * of references it found.
 *
 * This function is only called from page_referenced for object-based pages.
 */
static int page_referenced_file(struct page *page,
				struct mem_cgroup *mem_cont,
				unsigned long *vm_flags)
{
	unsigned int mapcount;
	struct address_space *mapping = page->mapping, *peer;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int referenced = 0;

	/*
	 * The caller's checks on page->mapping and !PageAnon have made
	 * sure that this is a file page: the check for page->mapping
	 * excludes the case just before it gets set on an anon page.
	 */
	BUG_ON(PageAnon(page));

	/*
	 * The page lock not only makes sure that page->mapping cannot
	 * suddenly be NULLified by truncation, it makes sure that the
	 * structure at mapping cannot be freed and reused yet,
	 * so we can safely take mapping->i_mmap_lock.
	 */
	BUG_ON(!PageLocked(page));

	spin_lock_nested(&mapping->i_mmap_lock, SINGLE_DEPTH_NESTING);

	/*
	 * i_mmap_lock does not stabilize mapcount at all, but mapcount
	 * is more likely to be accurate if we note it after spinning.
	 */
	mapcount = page_mapcount(page);

	if (!mapcount)
		goto out;

	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		unsigned long address = vma_address(page, vma);
		if (address == -EFAULT)
			continue;
		/*
		 * If we are reclaiming on behalf of a cgroup, skip
		 * counting on behalf of references from different
		 * cgroups
		 */
		if (mem_cont && !mm_match_cgroup(vma->vm_mm, mem_cont))
			continue;
		referenced += page_referenced_one(page, vma, address,
						  &mapcount, vm_flags);
		if (!mapcount)
			goto out;
	}

	list_for_each_entry(peer, &mapping->i_peer_list, i_peer_list) {
		if (!mapping_mapped(peer))
			continue;

		spin_lock(&peer->i_mmap_lock);

		vma_prio_tree_foreach(vma, &iter, &peer->i_mmap, pgoff, pgoff) {
			unsigned long address = vma_address(page, vma);
			if (address == -EFAULT)
				continue;
			if (mem_cont && !mm_match_cgroup(vma->vm_mm, mem_cont))
				continue;
			referenced += page_referenced_one(page, vma, address,
							&mapcount, vm_flags);
			if (!mapcount)
				break;
		}

		spin_unlock(&peer->i_mmap_lock);

		if (!mapcount)
			break;
	}
out:
	spin_unlock(&mapping->i_mmap_lock);
	return referenced;
}

/**
 * page_referenced - test if the page was referenced
 * @page: the page to test
 * @is_locked: caller holds lock on the page
 * @mem_cont: target memory controller
 * @vm_flags: collect encountered vma->vm_flags who actually referenced the page
 *
 * Quick test_and_clear_referenced for all mappings to a page,
 * returns the number of ptes which referenced the page.
 */
int page_referenced(struct page *page,
		    int is_locked,
		    struct mem_cgroup *mem_cont,
		    unsigned long *vm_flags)
{
	int referenced = 0;
	int we_locked = 0;

	*vm_flags = 0;
	if (page_mapped(page) && page_rmapping(page)) {
		if (!is_locked && (!PageAnon(page) || PageKsm(page))) {
			we_locked = trylock_page(page);
			if (!we_locked) {
				referenced++;
				goto out;
			}
		}
		if (unlikely(PageKsm(page)))
			referenced += page_referenced_ksm(page, mem_cont,
								vm_flags);
		else if (PageAnon(page))
			referenced += page_referenced_anon(page, mem_cont,
								vm_flags);
		else if (page->mapping)
			referenced += page_referenced_file(page, mem_cont,
								vm_flags);
		if (we_locked)
			unlock_page(page);

		if (page_test_and_clear_young(page))
			referenced++;
	}
out:

	return referenced;
}

static int page_mkclean_one(struct page *page, struct vm_area_struct *vma,
			    unsigned long address)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte;
	spinlock_t *ptl;
	int ret = 0;

	pte = page_check_address(page, mm, address, &ptl, 1);
	if (!pte)
		goto out;

	if (pte_dirty(*pte) || pte_write(*pte)) {
		pte_t entry;

		flush_cache_page(vma, address, pte_pfn(*pte));
		entry = ptep_clear_flush_notify(vma, address, pte);
		entry = pte_wrprotect(entry);
		entry = pte_mkclean(entry);
		set_pte_at(mm, address, pte, entry);
		ret = 1;
	}

	pte_unmap_unlock(pte, ptl);
out:
	return ret;
}

static int page_mkclean_file(struct address_space *mapping, struct page *page)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int ret = 0;

	BUG_ON(PageAnon(page));

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		if (vma->vm_flags & VM_SHARED) {
			unsigned long address = vma_address(page, vma);
			if (address == -EFAULT)
				continue;
			ret += page_mkclean_one(page, vma, address);
		}
	}
	spin_unlock(&mapping->i_mmap_lock);
	return ret;
}

int page_mkclean(struct page *page)
{
	int ret = 0;

	BUG_ON(!PageLocked(page));

	if (page_mapped(page)) {
		struct address_space *mapping = page_mapping(page);
		if (mapping)
			ret = page_mkclean_file(mapping, page);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(page_mkclean);

/**
 * page_move_anon_rmap - move a page to our anon_vma
 * @page:	the page to move to our anon_vma
 * @vma:	the vma the page belongs to
 * @address:	the user virtual address mapped
 *
 * When a page belongs exclusively to one process after a COW event,
 * that page can be moved into the anon_vma that belongs to just that
 * process, so the rmap code will not search the parent or sibling
 * processes.
 */
void page_move_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(!anon_vma);
	VM_BUG_ON(page->index != linear_page_index(vma, address));

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
}

/**
 * __page_set_anon_rmap - set up new anonymous rmap
 * @page:	Page to add to rmap	
 * @vma:	VM area to add page to.
 * @address:	User virtual address of the mapping	
 * @exclusive:	the page is exclusively owned by the current process
 */
static void __page_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);

	if (PageAnon(page))
		return;

	/*
	 * If the page isn't exclusively mapped into this vma,
	 * we must use the _oldest_ possible anon_vma for the
	 * page mapping!
	 */
	if (!exclusive)
		anon_vma = anon_vma->root;

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
	page->index = linear_page_index(vma, address);
}

/**
 * __page_check_anon_rmap - sanity check anonymous rmap addition
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 */
static void __page_check_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
#ifdef CONFIG_DEBUG_VM
	/*
	 * The page's anon-rmap details (mapping and index) are guaranteed to
	 * be set up correctly at this point.
	 *
	 * We have exclusion against page_add_anon_rmap because the caller
	 * always holds the page locked, except if called from page_dup_rmap,
	 * in which case the page is already known to be setup.
	 *
	 * We have exclusion against page_add_new_anon_rmap because those pages
	 * are initially only visible via the pagetables, and the pte is locked
	 * over the call to page_add_new_anon_rmap.
	 */
	BUG_ON(page_anon_vma(page)->root != vma->anon_vma->root);
	BUG_ON(page->index != linear_page_index(vma, address));
#endif
}

/**
 * page_add_anon_rmap - add pte mapping to an anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 *
 * The caller needs to hold the pte lock, and the page must be locked in
 * the anon_vma case: to serialize mapping,index checking after setting,
 * and to ensure that PageAnon is not being upgraded racily to PageKsm
 * (but PageKsm is never downgraded to PageAnon).
 */
void page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	do_page_add_anon_rmap(page, vma, address, 0);
}

/*
 * Special version of the above for do_swap_page, which often runs
 * into pages that are exclusively owned by the current process.
 * Everybody else should continue to use page_add_anon_rmap above.
 */
void do_page_add_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	int first = atomic_inc_and_test(&page->_mapcount);
	if (first) {
		struct gang_set *gs = get_mm_gang(vma->vm_mm);

		if (PageLRU(page) && !page_in_gang(page, gs) &&
				!isolate_lru_page(page)) {
			gang_mod_user_page(page, gs,
					GFP_ATOMIC|__GFP_NOFAIL);
			putback_lru_page(page);
		}

		if (!PageTransHuge(page))
			__inc_zone_page_state(page, NR_ANON_PAGES);
		else
			__inc_zone_page_state(page,
					      NR_ANON_TRANSPARENT_HUGEPAGES);
	}
	if (unlikely(PageKsm(page)))
		return;

	VM_BUG_ON(!PageLocked(page));
	VM_BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	if (first) {
		__page_set_anon_rmap(page, vma, address, exclusive);
	} else
		__page_check_anon_rmap(page, vma, address);
}

/**
 * page_add_new_anon_rmap - add pte mapping to a new anonymous page
 * @page:	the page to add the mapping to
 * @vma:	the vm area in which the mapping is added
 * @address:	the user virtual address mapped
 *
 * Same as page_add_anon_rmap but must only be called on *new* pages.
 * This means the inc-and-test can be bypassed.
 * Page does not have to be locked.
 */
void page_add_new_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address)
{
	VM_BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	SetPageSwapBacked(page);
	atomic_set(&page->_mapcount, 0); /* increment count (starts at -1) */
	if (!PageTransHuge(page))
		__inc_zone_page_state(page, NR_ANON_PAGES);
	else
		__inc_zone_page_state(page, NR_ANON_TRANSPARENT_HUGEPAGES);
	__page_set_anon_rmap(page, vma, address, 1);
	if (page_evictable(page, vma))
		lru_cache_add_lru(page, LRU_ACTIVE_ANON);
	else
		add_page_to_unevictable_list(page);
}
EXPORT_SYMBOL(page_add_new_anon_rmap);

/**
 * page_add_file_rmap - add pte mapping to a file page
 * @page: the page to add the mapping to
 *
 * The caller needs to hold the pte lock.
 */
void page_add_file_rmap(struct page *page, struct mm_struct *mm)
{
	if (atomic_inc_and_test(&page->_mapcount)) {
		struct gang_set *gs = get_mm_gang(mm);

		if (PageLRU(page) && !page_in_gang(page, gs) &&
				!isolate_lru_page(page)) {
			gang_mod_user_page(page, gs,
					GFP_ATOMIC|__GFP_NOFAIL);
			putback_lru_page(page);
		}

		__inc_zone_page_state(page, NR_FILE_MAPPED);
		mem_cgroup_update_file_mapped(page, 1);
	}
}

/**
 * page_remove_rmap - take down pte mapping from a page
 * @page: page to remove mapping from
 *
 * The caller needs to hold the pte lock.
 */
void page_remove_rmap(struct page *page)
{
	struct address_space *mapping = page_mapping(page);

	/* page still mapped by someone else? */
	if (!atomic_add_negative(-1, &page->_mapcount))
		return;

	/*
	 * Now that the last pte has gone, s390 must transfer dirty
	 * flag from storage key to struct page.  We can usually skip
	 * this if the page is anon, so about to be freed; but perhaps
	 * not if it's in swapcache - there might be another pte slot
	 * containing the swap entry, but page not yet written to swap.
	 *
	 * And we can skip it on file pages, so long as the filesystem
	 * participates in dirty tracking; but need to catch shm and tmpfs
	 * and ramfs pages which have been modified since creation by read
	 * fault.
	 *
	 * Note that mapping must be decided above, before decrementing
	 * mapcount (which luckily provides a barrier): once page is unmapped,
	 * it could be truncated and page->mapping reset to NULL at any moment.
	 * Note also that we are relying on page_mapping(page) to set mapping
	 * to &swapper_space when PageSwapCache(page).
	 */
	if (mapping && !mapping_cap_account_dirty(mapping) &&
	    page_test_dirty(page)) {
		page_clear_dirty(page);
		set_page_dirty(page);
	}
	/*
	 * Hugepages are not counted in NR_ANON_PAGES nor NR_FILE_MAPPED
	 * and not charged by memcg for now.
	 */
	if (unlikely(PageHuge(page)))
		return;
	/*
	 * Well, when a page is unmapped, we cannot keep PG_checkpointed
	 * flag, it is not accessible via process VM and we have no way
	 * to reset its state
	 */
	ClearPageCheckpointed(page);
	if (PageAnon(page)) {
		mem_cgroup_uncharge_page(page);
		if (!PageTransHuge(page))
			__dec_zone_page_state(page, NR_ANON_PAGES);
		else
			__dec_zone_page_state(page,
					      NR_ANON_TRANSPARENT_HUGEPAGES);
	} else {
		__dec_zone_page_state(page, NR_FILE_MAPPED);
		mem_cgroup_update_file_mapped(page, -1);
	}
	/*
	 * It would be tidy to reset the PageAnon mapping here,
	 * but that might overwrite a racing page_add_anon_rmap
	 * which increments mapcount after us but sets mapping
	 * before us: so leave the reset to free_hot_cold_page,
	 * and remember that it's only reliable while mapped.
	 * Leaving it set also helps swapoff to reinstate ptes
	 * faster for those pages still in swapcache.
	 */
}

/*
 * Subfunctions of try_to_unmap: try_to_unmap_one called
 * repeatedly from either try_to_unmap_anon or try_to_unmap_file.
 */
int try_to_unmap_one(struct page *page, struct vm_area_struct *vma,
		     unsigned long address, enum ttu_flags flags)
{
	struct mm_struct *mm = vma->vm_mm;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	int ret = SWAP_AGAIN;

	pte = page_check_address(page, mm, address, &ptl, 0);
	if (!pte)
		goto out;

	/*
	 * If the page is mlock()d, we cannot swap it out.
	 * If it's recently referenced (perhaps page_referenced
	 * skipped over this mm) then we should reactivate it.
	 */
	if (!(flags & TTU_IGNORE_MLOCK)) {
		if (vma->vm_flags & VM_LOCKED) {
			ret = SWAP_MLOCK;
			goto out_unmap;
		}
		if (TTU_ACTION(flags) == TTU_MUNLOCK)
			goto out_unmap;
	}
	if (!(flags & TTU_IGNORE_ACCESS)) {
		if (ptep_clear_flush_young_notify(vma, address, pte)) {
			ret = SWAP_FAIL;
			goto out_unmap;
		}
  	}

	/* Nuke the page table entry. */
	flush_cache_page(vma, address, page_to_pfn(page));
	pteval = ptep_clear_flush_notify(vma, address, pte);

	/* Move the dirty bit to the physical page now the pte is gone. */
	if (pte_dirty(pteval))
		set_page_dirty_mm(page, mm);

	/* Update high watermark before we lower rss */
	update_hiwater_rss(mm);

	if (PageHWPoison(page) && !(flags & TTU_IGNORE_HWPOISON)) {
		if (PageAnon(page))
			dec_mm_counter(mm, anon_rss);
		else
			dec_mm_counter(mm, file_rss);
		set_pte_at(mm, address, pte,
				swp_entry_to_pte(make_hwpoison_entry(page)));
	} else if (PageAnon(page)) {
		swp_entry_t entry = { .val = page_private(page) };

		if (PageSwapCache(page)) {
			/*
			 * Store the swap location in the pte.
			 * See handle_pte_fault() ...
			 */
			if (swap_duplicate(entry) < 0) {
				set_pte_at(mm, address, pte, pteval);
				ret = SWAP_FAIL;
				goto out_unmap;
			}
			if (list_empty(&mm->mmlist)) {
				spin_lock(&mmlist_lock);
				if (list_empty(&mm->mmlist))
					list_add(&mm->mmlist, &init_mm.mmlist);
				spin_unlock(&mmlist_lock);
			}
			dec_mm_counter(mm, anon_rss);
			inc_mm_counter(mm, swap_usage);
		} else if (PAGE_MIGRATION &
			   (TTU_ACTION(flags) == TTU_MIGRATION)) {
			/*
			 * Store the pfn of the page in a special migration
			 * pte. do_swap_page() will wait until the migration
			 * pte is removed and then restart fault handling.
			 */
			entry = make_migration_entry(page, pte_write(pteval));
		} else if (SWP_VSWAP_NUM && (TTU_ACTION(flags) == TTU_VSWAP)) {
			entry = make_vswap_entry(page, pte_write(pteval));
			__count_vm_event(VSWPOUT);
			dec_mm_counter(mm, anon_rss);
			inc_mm_counter(mm, swap_usage);
			get_vswap_page(page);
			set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
			page_remove_rmap(page);
			goto out_unmap;
		}
		set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
		BUG_ON(pte_file(*pte));
	} else if (PAGE_MIGRATION && (TTU_ACTION(flags) == TTU_MIGRATION)) {
		/* Establish migration entry for a file page */
		swp_entry_t entry;
		entry = make_migration_entry(page, pte_write(pteval));
		set_pte_at(mm, address, pte, swp_entry_to_pte(entry));
	} else
		dec_mm_counter(mm, file_rss);

	page_remove_rmap(page);
	page_cache_release(page);

out_unmap:
	pte_unmap_unlock(pte, ptl);

	if (ret == SWAP_MLOCK) {
		ret = SWAP_AGAIN;
		if (down_read_trylock(&vma->vm_mm->mmap_sem)) {
			if (vma->vm_flags & VM_LOCKED) {
				mlock_vma_page(vma, page);
				ret = SWAP_MLOCK;
			}
			up_read(&vma->vm_mm->mmap_sem);
		}
		trace_mm_anon_unmap(vma->vm_mm, vma->vm_start+page->index);
	}
out:
	return ret;
}

/*
 * objrmap doesn't work for nonlinear VMAs because the assumption that
 * offset-into-file correlates with offset-into-virtual-addresses does not hold.
 * Consequently, given a particular page and its ->index, we cannot locate the
 * ptes which are mapping that page without an exhaustive linear search.
 *
 * So what this code does is a mini "virtual scan" of each nonlinear VMA which
 * maps the file to which the target page belongs.  The ->vm_private_data field
 * holds the current cursor into that scan.  Successive searches will circulate
 * around the vma's virtual address space.
 *
 * So as more replacement pressure is applied to the pages in a nonlinear VMA,
 * more scanning pressure is placed against them as well.   Eventually pages
 * will become fully unmapped and are eligible for eviction.
 *
 * For very sparsely populated VMAs this is a little inefficient - chances are
 * there there won't be many ptes located within the scan cluster.  In this case
 * maybe we could scan further - to the end of the pte page, perhaps.
 *
 * Mlocked pages:  check VM_LOCKED under mmap_sem held for read, if we can
 * acquire it without blocking.  If vma locked, mlock the pages in the cluster,
 * rather than unmapping them.  If we encounter the "check_page" that vmscan is
 * trying to unmap, return SWAP_MLOCK, else default SWAP_AGAIN.
 */
#define CLUSTER_SIZE	min(32*PAGE_SIZE, PMD_SIZE)
#define CLUSTER_MASK	(~(CLUSTER_SIZE - 1))

static int try_to_unmap_cluster(unsigned long cursor, unsigned int *mapcount,
		struct vm_area_struct *vma, struct page *check_page)
{
	struct mm_struct *mm = vma->vm_mm;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
	pte_t pteval;
	spinlock_t *ptl;
	struct page *page;
	unsigned long address;
	unsigned long end;
	int ret = SWAP_AGAIN;
	int locked_vma = 0;

	address = (vma->vm_start + cursor) & CLUSTER_MASK;
	end = address + CLUSTER_SIZE;
	if (address < vma->vm_start)
		address = vma->vm_start;
	if (end > vma->vm_end)
		end = vma->vm_end;

	pgd = pgd_offset(mm, address);
	if (!pgd_present(*pgd))
		return ret;

	pud = pud_offset(pgd, address);
	if (!pud_present(*pud))
		return ret;

	pmd = pmd_offset(pud, address);
	if (!pmd_present(*pmd))
		return ret;

	/*
	 * If we can acquire the mmap_sem for read, and vma is VM_LOCKED,
	 * keep the sem while scanning the cluster for mlocking pages.
	 */
	if (down_read_trylock(&vma->vm_mm->mmap_sem)) {
		locked_vma = (vma->vm_flags & VM_LOCKED);
		if (!locked_vma)
			up_read(&vma->vm_mm->mmap_sem); /* don't need it */
	}

	pte = pte_offset_map_lock(mm, pmd, address, &ptl);

	/* Update high watermark before we lower rss */
	update_hiwater_rss(mm);

	for (; address < end; pte++, address += PAGE_SIZE) {
		if (!pte_present(*pte))
			continue;
		page = vm_normal_page(vma, address, *pte);
		BUG_ON(!page || PageAnon(page));

		if (locked_vma) {
			if (page == check_page) {
				/* we know we have check_page locked */
				mlock_vma_page(vma, page);
				ret = SWAP_MLOCK;
			} else if (trylock_page(page)) {
				/*
				 * If we can lock the page, perform mlock.
				 * Otherwise leave the page alone, it will be
				 * eventually encountered again later.
				 */
				mlock_vma_page(vma, page);
				unlock_page(page);
			}
			continue;	/* don't unmap */
		}

		if (ptep_clear_flush_young_notify(vma, address, pte))
			continue;

		/* Nuke the page table entry. */
		flush_cache_page(vma, address, pte_pfn(*pte));
		pteval = ptep_clear_flush_notify(vma, address, pte);

		/* If nonlinear, store the file page offset in the pte. */
		if (page->index != linear_page_index(vma, address))
			set_pte_at(mm, address, pte, pgoff_to_pte(page->index));

		/* Move the dirty bit to the physical page now the pte is gone. */
		if (pte_dirty(pteval))
			set_page_dirty_mm(page, mm);

		page_remove_rmap(page);
		page_cache_release(page);
		dec_mm_counter(mm, file_rss);
		(*mapcount)--;
	}
	pte_unmap_unlock(pte - 1, ptl);
	if (locked_vma)
		up_read(&vma->vm_mm->mmap_sem);
	return ret;
}

/**
 * try_to_unmap_anon - unmap or unlock anonymous page using the object-based
 * rmap method
 * @page: the page to unmap/unlock
 * @unlock:  request for unlock rather than unmap [unlikely]
 * @migration:  unmapping for migration - ignored if @unlock
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the anon_vma struct it points to.
 *
 * This function is only called from try_to_unmap/try_to_munlock for
 * anonymous pages.
 * When called from try_to_munlock(), the mmap_sem of the mm containing the vma
 * where the page was found will be held for write.  So, we won't recheck
 * vm_flags for that VMA.  That should be OK, because that vma shouldn't be
 * 'LOCKED.
 */
static int try_to_unmap_anon(struct page *page, enum ttu_flags flags)
{
	struct anon_vma *anon_vma;
	struct anon_vma_chain *avc;
	int ret = SWAP_AGAIN;

	anon_vma = page_lock_anon_vma(page);
	if (!anon_vma)
		return ret;

	list_for_each_entry(avc, &anon_vma->head, same_anon_vma) {
		struct vm_area_struct *vma = avc->vma;
		unsigned long address;

		/*
		 * During exec, a temporary VMA is setup and later moved.
		 * The VMA is moved under the anon_vma lock but not the
		 * page tables leading to a race where migration cannot
		 * find the migration ptes. Rather than increasing the
		 * locking requirements of exec(), migration skips
		 * temporary VMAs until after exec() completes.
		 */
		if (PAGE_MIGRATION && (flags & TTU_MIGRATION) &&
				is_vma_temporary_stack(vma))
			continue;

		address = vma_address(page, vma);
		if (address == -EFAULT)
			continue;
		ret = try_to_unmap_one(page, vma, address, flags);
		if (ret != SWAP_AGAIN || !page_mapped(page))
			break;
	}

	page_unlock_anon_vma(anon_vma);
	return ret;
}

/**
 * try_to_unmap_file - unmap/unlock file page using the object-based rmap method
 * @page: the page to unmap/unlock
 * @flags: action and flags
 *
 * Find all the mappings of a page using the mapping pointer and the vma chains
 * contained in the address_space struct it points to.
 *
 * This function is only called from try_to_unmap/try_to_munlock for
 * object-based pages.
 * When called from try_to_munlock(), the mmap_sem of the mm containing the vma
 * where the page was found will be held for write.  So, we won't recheck
 * vm_flags for that VMA.  That should be OK, because that vma shouldn't be
 * 'LOCKED.
 */
static int try_to_unmap_mapping(struct page *page,
				struct address_space *mapping,
				enum ttu_flags flags)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int ret = SWAP_AGAIN;
	unsigned long cursor;
	unsigned long max_nl_cursor = 0;
	unsigned long max_nl_size = 0;
	unsigned int mapcount;

	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		unsigned long address = vma_address(page, vma);
		if (address == -EFAULT)
			continue;
		ret = try_to_unmap_one(page, vma, address, flags);
		if (ret != SWAP_AGAIN || !page_mapped(page))
			goto out;
		trace_mm_filemap_unmap(vma->vm_mm, vma->vm_start+page->index);
	}

	if (list_empty(&mapping->i_mmap_nonlinear))
		goto out;

	/*
	 * We don't bother to try to find the munlocked page in nonlinears.
	 * It's costly. Instead, later, page reclaim logic may call
	 * try_to_unmap(TTU_MUNLOCK) and recover PG_mlocked lazily.
	 */
	if (TTU_ACTION(flags) == TTU_MUNLOCK)
		goto out;

	list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
		cursor = (unsigned long) vma->vm_private_data;
		if (cursor > max_nl_cursor)
			max_nl_cursor = cursor;
		cursor = vma->vm_end - vma->vm_start;
		if (cursor > max_nl_size)
			max_nl_size = cursor;
	}

	if (max_nl_size == 0) {	/* all nonlinears locked or reserved ? */
		ret = SWAP_FAIL;
		goto out;
	}

	/*
	 * We don't try to search for this page in the nonlinear vmas,
	 * and page_referenced wouldn't have found it anyway.  Instead
	 * just walk the nonlinear vmas trying to age and unmap some.
	 * The mapcount of the page we came in with is irrelevant,
	 * but even so use it as a guide to how hard we should try?
	 */
	mapcount = page_mapcount(page);
	if (!mapcount)
		goto out;
	cond_resched_lock(&mapping->i_mmap_lock);

	max_nl_size = (max_nl_size + CLUSTER_SIZE - 1) & CLUSTER_MASK;
	if (max_nl_cursor == 0)
		max_nl_cursor = CLUSTER_SIZE;

	do {
		list_for_each_entry(vma, &mapping->i_mmap_nonlinear,
						shared.vm_set.list) {
			cursor = (unsigned long) vma->vm_private_data;
			while ( cursor < max_nl_cursor &&
				cursor < vma->vm_end - vma->vm_start) {
				if (try_to_unmap_cluster(cursor, &mapcount,
						vma, page) == SWAP_MLOCK)
					ret = SWAP_MLOCK;
				cursor += CLUSTER_SIZE;
				vma->vm_private_data = (void *) cursor;
				if ((int)mapcount <= 0)
					goto out;
			}
			vma->vm_private_data = (void *) max_nl_cursor;
		}
		cond_resched_lock(&mapping->i_mmap_lock);
		max_nl_cursor += CLUSTER_SIZE;
	} while (max_nl_cursor <= max_nl_size);

	/*
	 * Don't loop forever (perhaps all the remaining pages are
	 * in locked vmas).  Reset cursor on all unreserved nonlinear
	 * vmas, now forgetting on which ones it had fallen behind.
	 */
	list_for_each_entry(vma, &mapping->i_mmap_nonlinear, shared.vm_set.list)
		vma->vm_private_data = NULL;
out:
	spin_unlock(&mapping->i_mmap_lock);
	return ret;
}

static int try_to_unmap_file(struct page *page, enum ttu_flags flags)
{
	struct address_space *mapping = page->mapping, *peer;
	int ret;

	ret = try_to_unmap_mapping(page, mapping, flags);

	if (ret != SWAP_AGAIN || !page_mapped(page) ||
	    list_empty(&mapping->i_peer_list) ||
	    TTU_ACTION(flags) == TTU_MUNLOCK)
		return ret;

	/*
	 * Ignore TTU_MUNLOCK, reclaimer can handle it.
	 * Handle TTU_MIGRATION like TTU_UNMAP, without migration ptes.
	 */
	flags = TTU_UNMAP | (flags & ~TTU_ACTION_MASK);

	spin_lock_nested(&mapping->i_mmap_lock, SINGLE_DEPTH_NESTING);
	list_for_each_entry(peer, &mapping->i_peer_list, i_peer_list) {
		ret = try_to_unmap_mapping(page, peer, flags);
		if (ret != SWAP_AGAIN || !page_mapped(page))
			break;
	}
	spin_unlock(&mapping->i_mmap_lock);

	return ret;
}

/**
 * try_to_unmap - try to remove all page table mappings to a page
 * @page: the page to get unmapped
 * @flags: action and flags
 *
 * Tries to remove all the page table entries which are mapping this
 * page, used in the pageout path.  Caller must hold the page lock.
 * Return values are:
 *
 * SWAP_SUCCESS	- we succeeded in removing all mappings
 * SWAP_AGAIN	- we missed a mapping, try again later
 * SWAP_FAIL	- the page is unswappable
 * SWAP_MLOCK	- page is mlocked.
 */
int try_to_unmap(struct page *page, enum ttu_flags flags)
{
	int ret;

	BUG_ON(!PageLocked(page));
	VM_BUG_ON(!PageHuge(page) && PageTransHuge(page));

	if (unlikely(PageKsm(page)))
		ret = try_to_unmap_ksm(page, flags);
	else if (PageAnon(page))
		ret = try_to_unmap_anon(page, flags);
	else
		ret = try_to_unmap_file(page, flags);
	if (ret != SWAP_MLOCK && !page_mapped(page))
		ret = SWAP_SUCCESS;
	return ret;
}

/**
 * try_to_munlock - try to munlock a page
 * @page: the page to be munlocked
 *
 * Called from munlock code.  Checks all of the VMAs mapping the page
 * to make sure nobody else has this page mlocked. The page will be
 * returned with PG_mlocked cleared if no other vmas have it mlocked.
 *
 * Return values are:
 *
 * SWAP_AGAIN	- no vma is holding page mlocked, or,
 * SWAP_AGAIN	- page mapped in mlocked vma -- couldn't acquire mmap sem
 * SWAP_FAIL	- page cannot be located at present
 * SWAP_MLOCK	- page is now mlocked.
 */
int try_to_munlock(struct page *page)
{
	VM_BUG_ON(!PageLocked(page) || PageLRU(page));

	if (unlikely(PageKsm(page)))
		return try_to_unmap_ksm(page, TTU_MUNLOCK);
	else if (PageAnon(page))
		return try_to_unmap_anon(page, TTU_MUNLOCK);
	else
		return try_to_unmap_file(page, TTU_MUNLOCK);
}

#if defined(CONFIG_KSM) || defined(CONFIG_MIGRATION)
/*
 * Drop an anon_vma refcount, freeing the anon_vma and anon_vma->root
 * if necessary.  Be careful to do all the tests under the lock.  Once
 * we know we are the last user, nobody else can get a reference and we
 * can do the freeing without the lock.
 */
void drop_anon_vma(struct anon_vma *anon_vma)
{
	BUG_ON(atomic_read(&anon_vma->external_refcount) <= 0);
	if (atomic_dec_and_lock(&anon_vma->external_refcount, &anon_vma->root->lock)) {
		struct anon_vma *root = anon_vma->root;
		int empty = list_empty(&anon_vma->head);
		int last_root_user = 0;
		int root_empty = 0;

		/*
		 * The refcount on a non-root anon_vma got dropped.  Drop
		 * the refcount on the root and check if we need to free it.
		 */
		if (empty && anon_vma != root) {
			BUG_ON(atomic_read(&root->external_refcount) <= 0);
			last_root_user = atomic_dec_and_test(&root->external_refcount);
			root_empty = list_empty(&root->head);
		}
		anon_vma_unlock(anon_vma);

		if (empty) {
			BUG_ON(anon_vma->degree);
			anon_vma_free(anon_vma);
			if (root_empty && last_root_user) {
				BUG_ON(root->degree);
				anon_vma_free(root);
			}
		}
	}
}
#endif

#if defined(CONFIG_MIGRATION) || defined(CONFIG_MEMORY_VSWAP)
/*
 * rmap_walk() and its helpers rmap_walk_anon() and rmap_walk_file():
 * Called by migrate.c to remove migration ptes, but might be used more later.
 */
static int rmap_walk_anon(struct page *page, struct rmap_walk_control *rwc)
{
	struct anon_vma *anon_vma;
	struct anon_vma_chain *avc;
	int ret = SWAP_AGAIN;

	/*
	 * Note: remove_migration_ptes() cannot use page_lock_anon_vma()
	 * because that depends on page_mapped(); but not all its usages
	 * are holding mmap_sem. Users without mmap_sem are required to
	 * take a reference count to prevent the anon_vma disappearing
	 */
	anon_vma = page_anon_vma(page);
	if (!anon_vma)
		return ret;
	anon_vma_lock(anon_vma);
	list_for_each_entry(avc, &anon_vma->head, same_anon_vma) {
		struct vm_area_struct *vma = avc->vma;
		unsigned long address = vma_address(page, vma);
		if (address == -EFAULT)
			continue;
		ret = rwc->rmap_one(page, vma, address, rwc->arg);
		if (ret != SWAP_AGAIN)
			break;
	}
	anon_vma_unlock(anon_vma);
	return ret;
}

static int rmap_walk_file(struct page *page, struct rmap_walk_control *rwc)
{
	struct address_space *mapping = page->mapping;
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);
	struct vm_area_struct *vma;
	struct prio_tree_iter iter;
	int ret = SWAP_AGAIN;

	if (!mapping)
		return ret;
	spin_lock(&mapping->i_mmap_lock);
	vma_prio_tree_foreach(vma, &iter, &mapping->i_mmap, pgoff, pgoff) {
		unsigned long address = vma_address(page, vma);
		if (address == -EFAULT)
			continue;
		ret = rwc->rmap_one(page, vma, address, rwc->arg);
		if (ret != SWAP_AGAIN)
			goto done;
	}

	if (!rwc->file_nonlinear)
		goto done;

	if (list_empty(&mapping->i_mmap_nonlinear))
		goto done;

	ret = rwc->file_nonlinear(page, mapping, rwc->arg);

done:
	spin_unlock(&mapping->i_mmap_lock);
	return ret;
}

int rmap_walk(struct page *page, struct rmap_walk_control *rwc)
{
	VM_BUG_ON(!PageLocked(page));

	if (unlikely(PageKsm(page)))
		return rmap_walk_ksm(page, rwc);
	else if (PageAnon(page))
		return rmap_walk_anon(page, rwc);
	else
		return rmap_walk_file(page, rwc);
}
#endif /* defined(CONFIG_MIGRATION) || defined(CONFIG_MEMORY_VSWAP) */

#ifdef CONFIG_HUGETLB_PAGE
/*
 * The following three functions are for anonymous (private mapped) hugepages.
 * Unlike common anonymous pages, anonymous hugepages have no accounting code
 * and no lru code, because we handle hugepages differently from common pages.
 */
static void __hugepage_set_anon_rmap(struct page *page,
	struct vm_area_struct *vma, unsigned long address, int exclusive)
{
	struct anon_vma *anon_vma = vma->anon_vma;

	BUG_ON(!anon_vma);

	if (PageAnon(page))
		return;
	if (!exclusive)
		anon_vma = anon_vma->root;

	anon_vma = (void *) anon_vma + PAGE_MAPPING_ANON;
	page->mapping = (struct address_space *) anon_vma;
	page->index = linear_page_index(vma, address);
}

void hugepage_add_anon_rmap(struct page *page,
			    struct vm_area_struct *vma, unsigned long address)
{
	struct anon_vma *anon_vma = vma->anon_vma;
	int first;

	BUG_ON(!PageLocked(page));
	BUG_ON(!anon_vma);
	BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	first = atomic_inc_and_test(&page->_mapcount);
	if (first)
		__hugepage_set_anon_rmap(page, vma, address, 0);
}

void hugepage_add_new_anon_rmap(struct page *page,
			struct vm_area_struct *vma, unsigned long address)
{
	BUG_ON(address < vma->vm_start || address >= vma->vm_end);
	atomic_set(&page->_mapcount, 0);
	__hugepage_set_anon_rmap(page, vma, address, 1);
}
#endif /* CONFIG_HUGETLB_PAGE */
