#include <unistd.h>
#include <fcntl.h>

#include "page.h"
#include "pagemap-cache.h"
#include "common/compiler.h"
#include "xmalloc.h"
#include "util.h"
#include "log.h"
#include "vma.h"
#include "mem.h"
#include "kerndat.h"

#undef LOG_PREFIX
#define LOG_PREFIX "pagemap-cache: "

/* To carry up to 2M of physical memory */
#define PMC_SHIFT    (21)
#define PMC_SIZE     (1ul << PMC_SHIFT)
#define PMC_MASK     (~(PMC_SIZE - 1))
#define PMC_SIZE_GAP (PMC_SIZE / 4)

#define PAGEMAP_LEN(addr) (PAGE_PFN(addr) * sizeof(u64))
#define PAGEMAP_NR_PMES(size) ((size) / sizeof(u64))

/*
 * It's a workaround for a kernel bug. In the 3.19 kernel when pagemap are read
 * for a few vma-s for one read call, it returns incorrect data.
 * https://github.com/checkpoint-restore/criu/issues/207
*/
static bool pagemap_cache_disabled;

static inline void pmc_reset(pmc_t *pmc)
{
	memzero(pmc, sizeof(*pmc));
	pmc->fd = -1;
}

static inline void pmc_zap(pmc_t *pmc)
{
	pmc->start = pmc->end = 0;
	pmc->read_map_len = 0;
	pmc->nr_pme_read = 0;
}

int pmc_init(pmc_t *pmc, pid_t pid, const struct list_head *vma_head, size_t size)
{
	size_t map_size = max(size, (size_t)PMC_SIZE);
	pmc_reset(pmc);

	BUG_ON(!vma_head);

	pmc->pid = pid;
	pmc->map_len = PAGEMAP_LEN(map_size);
	pmc->vma_head = vma_head;

	pmc->map = xmalloc(pmc->map_len);
	if (!pmc->map)
		goto err;

	if (pagemap_cache_disabled)
		pr_warn_once("The pagemap cache is disabled\n");

	if (kdat.pmap == PM_DISABLED) {
		/*
		 * FIXME We might need to implement greedy
		 * mode via reading all pages available inside
		 * parasite.
		 *
		 * Actually since linux-4.4 the pagemap file
		 * is available for usernamespace with hiding
		 * PFNs but providing page attributes, so other
		 * option simply require kernel 4.4 and above
		 * for usernamespace support.
		 */
		pr_err("No pagemap for %d available\n", pid);
		goto err;
	} else {
		pmc->fd = open_proc(pid, "pagemap");
		if (pmc->fd < 0)
			goto err;
	}

	pr_debug("created for pid %d (takes %zu bytes)\n", pid, pmc->map_len);
	return 0;

err:
	pr_err("Failed to init pagemap for %d\n", pid);
	pmc_fini(pmc);
	return -1;
}

size_t pmc_get_pfn_from(pmc_t *pmc, unsigned long addr)
{
	size_t pfn = PAGE_PFN(addr - pmc->start);
	if (addr < pmc->start || addr > pmc->end) {
		pr_err("Trying to read addr %lx while only %lx - %lx are read\n",
		       addr, pmc->start, pmc->end);
		BUG();
	}
	return pfn;
}

u64 *pmc_get_map_at(pmc_t *pmc, size_t pos)
{
	if (pos >= pmc->nr_pme_read) {
		pr_err("Trying to read PME %zu while only %zu are read\n",
		       pos, pmc->nr_pme_read);
		return NULL;
		BUG();
	}
	return &pmc->map[pos];
}

u64 *pmc_get_map_from(pmc_t *pmc, unsigned long addr)
{
	size_t pfn = pmc_get_pfn_from(pmc, addr);
	return pmc_get_map_at(pmc, pfn);
}

static int pmc_fill_cache(pmc_t *pmc, const struct vma_area *vma)
{
	unsigned long low = vma->e->start & PMC_MASK;
	unsigned long high = low + PMC_SIZE;
	size_t len = vma_area_len(vma);
	size_t read_map_len;

	if (high > kdat.task_size)
		high = kdat.task_size;

	pmc->start = vma->e->start;
	pmc->end = vma->e->end;

	pr_debug("%d: filling VMA %lx-%lx (%zuK)\n",
		 pmc->pid, (long)vma->e->start, (long)vma->e->end, len >> 10);

	/*
	 * If we meet a small VMA, lets try to fit 2M cache
	 * window at least 75% full, otherwise left as a plain
	 * "one vma at a time" read. Note the VMAs in cache must
	 * fit in solid manner, iow -- either the whole vma fits
	 * the cache window, either plain read is used.
	 *
	 * The benefit (apart redusing the number of read() calls)
	 * is to walk page tables less.
	 */
	if (!pagemap_cache_disabled && len < PMC_SIZE && (vma->e->start - low) < PMC_SIZE_GAP) {
		size_t size_cov = len;
		size_t nr_vmas = 1;

		pr_debug("\t%d: %16lx-%-16lx nr:%-5zu cov:%zu\n", pmc->pid, (long)vma->e->start, (long)vma->e->end,
			 nr_vmas, size_cov);

		list_for_each_entry_continue(vma, pmc->vma_head, list) {
			if (vma->e->start > high || vma->e->end > high)
				break;

			BUG_ON(vma->e->start < low);
			size_cov += vma_area_len(vma);
			nr_vmas++;

			pr_debug("\t%d: %16lx-%-16lx nr:%-5zu cov:%zu\n", pmc->pid, (long)vma->e->start,
				 (long)vma->e->end, nr_vmas, size_cov);
		}

		if (nr_vmas > 1) {
			/*
			 * Note we don't touch low bound since it's set
			 * to first VMA start already and not updating it
			 * allows us to save a couple of code bytes.
			 */
			pmc->end = high;
			pr_debug("\t%d: cache  mode [l:%lx h:%lx]\n", pmc->pid, pmc->start, pmc->end);
		} else
			pr_debug("\t%d: simple mode [l:%lx h:%lx]\n", pmc->pid, pmc->start, pmc->end);
	}

	read_map_len = PAGEMAP_LEN(pmc->end - pmc->start);
	BUG_ON(pmc->map_len < read_map_len);
	BUG_ON(pmc->fd < 0);

	if (pread(pmc->fd, pmc->map, read_map_len, PAGEMAP_PFN_OFF(pmc->start)) != read_map_len) {
		pmc_zap(pmc);
		pr_perror("Can't read %d's pagemap file", pmc->pid);
		return -1;
	}
	pmc->nr_pme_read = PAGEMAP_NR_PMES(read_map_len);
	pmc->read_map_len = read_map_len;

	return 0;
}

u64 *pmc_get_map(pmc_t *pmc, const struct vma_area *vma)
{
	/* Hit */
	if (likely(pmc->start <= vma->e->start && pmc->end >= vma->e->end))
		return pmc_get_map_from(pmc, vma->e->start);

	/* Miss, refill the cache */
	if (pmc_fill_cache(pmc, vma)) {
		pr_err("Failed to fill cache for %d (%lx-%lx)\n", pmc->pid, (long)vma->e->start, (long)vma->e->end);
		return NULL;
	}

	/* Hit for sure */
	return pmc_get_map_from(pmc, vma->e->start);
}

void pmc_fini(pmc_t *pmc)
{
	close_safe(&pmc->fd);
	xfree(pmc->map);
	pmc_reset(pmc);
}

static void __attribute__((constructor)) pagemap_cache_init(void)
{
	pagemap_cache_disabled = (getenv("CRIU_PMC_OFF") != NULL);
}
