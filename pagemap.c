/*
 * Licensed under GPLv2, see COPYING file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#define PM_PAGE_FRAME_NUMBER_MASK	0x007fffffffffffff
#define PM_SWAP_TYPE_MASK		0x000000000000001f
#define PM_SWAP_OFFSET_MASK		0x007fffffffffffe0
#define PM_PTE_SOFT_DIRTY		55
#define PM_PAGE_EXCLUSIVELY_MAPPED	56
#define PM_PTE_UFFD_WRITE_PROTECTED	57
#define PM_PAGE_FILE_OR_SHARED_ANON	61
#define PM_PAGE_SWAPPED			62
#define PM_PAGE_PRESENT			63

#define KPF_LOCKED			0
#define KPF_ERROR			1
#define KPF_REFERENCED			2
#define KPF_UPTODATE			3
#define KPF_DIRTY			4
#define KPF_LRU				5
#define KPF_ACTIVE			6
#define KPF_SLAB			7
#define KPF_WRITEBACK			8
#define KPF_RECLAIM			9
#define KPF_BUDDY			10
#define KPF_MMAP			11	/* (since Linux 2.6.31) */
#define KPF_ANON			12	/* (since Linux 2.6.31) */
#define KPF_SWAPCACHE			13	/* (since Linux 2.6.31) */
#define KPF_SWAPBACKED			14	/* (since Linux 2.6.31) */
#define KPF_COMPOUND_HEAD		15	/* (since Linux 2.6.31) */
#define KPF_COMPOUND_TAIL		16	/* (since Linux 2.6.31) */
#define KPF_HUGE			17	/* (since Linux 2.6.31) */
#define KPF_UNEVICTABLE    		18	/* (since Linux 2.6.31) */
#define KPF_HWPOISON			19	/* (since Linux 2.6.31) */
#define KPF_NOPAGE			20	/* (since Linux 2.6.31) */
#define KPF_KSM				21	/* (since Linux 2.6.32) */
#define KPF_THP				22	/* (since Linux 3.4) */
/* #define KPF_BALLOON			23	   (since Linux 3.18) */
#define KPF_OFFLINE			23	/* (since Linux 5.1) */
#define KPF_ZERO_PAGE			24	/* (since Linux 4.0) */
#define KPF_IDLE			25	/* (since Linux 4.3) */
#define KPF_PGTABLE			26	/* (since Linux 5.1) */

#define KPF_RESERVED			32
#define KPF_MLOCKED			33
#define KPF_MAPPEDTODISK		34
#define KPF_PRIVATE			35
#define KPF_PRIVATE_2			36
#define KPF_OWNER_PRIVATE		37
#define KPF_ARCH			38
#define KPF_UNCACHED			39
#define KPF_SOFTDIRTY			40
#define KPF_ARCH_2			41

#define KPF_ANON_EXCLUSIVE		47
#define KPF_READAHEAD			48
#define KPF_SLOB_FREE			49
#define KPF_SLUB_FROZEN			50
#define KPF_SLUB_DEBUG			51
#define KPF_FILE			61
#define KPF_SWAP			62
#define KPF_MMAP_EXCLUSIVE		63

#define BIT(x) (1ULL << x)

static char *kpf_desc[64] = {
	[KPF_LOCKED]		= "locked",
	[KPF_ERROR]		= "error",
	[KPF_REFERENCED]	= "referenced",
	[KPF_UPTODATE]		= "up to date",
	[KPF_DIRTY]		= "dirty",
	[KPF_LRU]		= "lru",
	[KPF_ACTIVE]		= "active",
	[KPF_SLAB]		= "slab",
	[KPF_WRITEBACK]		= "writeback",
	[KPF_RECLAIM]		= "reclaim",
	[KPF_BUDDY]		= "buddy",
	[KPF_MMAP]		= "mmap",
	[KPF_ANON]		= "anon",
	[KPF_SWAPCACHE]		= "swap cache",
	[KPF_SWAPBACKED]	= "swap backed",
	[KPF_COMPOUND_HEAD]	= "compound head",
	[KPF_COMPOUND_TAIL]	= "compound tail",
	[KPF_HUGE]		= "huge",
	[KPF_UNEVICTABLE]	= "unevictable",
	[KPF_HWPOISON]		= "hwpoison",
	[KPF_NOPAGE]		= "nopage",
	[KPF_KSM]		= "ksm",
	[KPF_THP]		= "thp",
	[KPF_OFFLINE]		= "offline",
	[KPF_ZERO_PAGE]		= "zero page",
	[KPF_IDLE]		= "idle",
	[KPF_PGTABLE]		= "pgtable",
	/* zeroed */
	[KPF_RESERVED]		= "reserved",
	[KPF_MLOCKED]		= "mlocked",
	[KPF_MAPPEDTODISK]	= "mapped to disk",
	[KPF_PRIVATE]		= "private",
	[KPF_PRIVATE_2]		= "private 2",
	[KPF_OWNER_PRIVATE]	= "owner private",
	[KPF_ARCH]		= "arch",
	[KPF_UNCACHED]		= "uncached",
	[KPF_SOFTDIRTY]		= "soft dirty",
	[KPF_ARCH_2]		= "arch 2",
	/* zeroed */
	[KPF_ANON_EXCLUSIVE]	= "anon exclusive",
	[KPF_READAHEAD]		= "readahead",
	[KPF_SLOB_FREE]		= "slob free",
	[KPF_SLUB_FROZEN]	= "slub frozen",
	[KPF_SLUB_DEBUG]	= "slub debug",
	[KPF_FILE]		= "file",
	[KPF_SWAP]		= "swap",
	[KPF_MMAP_EXCLUSIVE]	= "mmap exclusive",
};

static int verbose;
static int hide_empty;
static int hide_soft_dirty_only;
static int page_size;
static int pagemap_fd;
static int kpagecount_fd;
static int kpageflags_fd;
static int kpagecgroup_fd;


static int empty_pm(uint64_t pm)
{
	return pm == 0 || (hide_soft_dirty_only && pm == BIT(PM_PTE_SOFT_DIRTY));
}

static int kpagecgroup(void)
{
	return kpagecgroup_fd >= 0;
}

static void print_empty(unsigned long addr)
{
	fprintf(stdout, "  %0*lx -\n", 2 * (int)sizeof(unsigned long), addr);
}

static void print_line(unsigned long addr, uint64_t pm, uint64_t kpc, uint64_t kpf, uint64_t kpcg)
{
	if (kpagecgroup())
		fprintf(stdout, "  %0*lx pm %016" PRIx64 " pc %016" PRIx64 " pf %016" PRIx64 " cg %016" PRIx64 "\n", 2 * (int)sizeof(unsigned long), addr, pm, kpc, kpf, kpcg);
	else
		fprintf(stdout, "  %0*lx pm %016" PRIx64 " pc %016" PRIx64 " pf %016" PRIx64 "\n", 2 * (int)sizeof(unsigned long), addr, pm, kpc, kpf);
}

static void print_u64_bit(uint64_t kpf, uint64_t bit, const char *desc)
{
	uint64_t val = kpf & (1ULL << bit);
	char mask[20];
	int idx;

	if (!val)
		return;

	snprintf(mask, sizeof(mask), "%016" PRIx64, val);

	for (idx = 0; idx < 2 * sizeof(uint64_t); idx++)
		if (mask[idx] == '0')
			mask[idx] = '.';

	fprintf(stdout, "      %s = %s\n", mask, desc);
}

static void print_pfn(uint64_t pm)
{
	uint64_t pfn;
	char mask[20];

	if (!(pm & BIT(PM_PAGE_PRESENT)))
		return;

	pfn = pm & PM_PAGE_FRAME_NUMBER_MASK;

	snprintf(mask, sizeof(mask), "%016" PRIx64, pfn);
	memset(mask, '.', 2);

	fprintf(stdout, "      %s = page frame number %" PRId64 "\n", mask, pfn);
}

static void print_swap(uint64_t pm)
{
	uint64_t swap_type;
	uint64_t swap_offset;
	char mask[20];

	if (!(pm & BIT(PM_PAGE_SWAPPED)))
		return;

	swap_type = pm & PM_SWAP_TYPE_MASK;
	swap_offset = (pm & PM_SWAP_OFFSET_MASK) >> 5;

	snprintf(mask, sizeof(mask), "%016" PRIx64, swap_type);
	memset(mask, '.', 14);
	fprintf(stdout, "      %s = swap type %" PRId64 "\n", mask, swap_type);

	snprintf(mask, sizeof(mask), "%016" PRIx64, swap_offset);
	memset(mask, '.', 2);
	mask[15] = '.';
	fprintf(stdout, "      %s = swap offset %" PRId64 "\n", mask, swap_offset);
}

static void print_kpf(uint64_t kpf)
{
	char mask[20];
	int idx;

	if (!kpf)
		return;

	fprintf(stdout, "    kpageflags\n");

	for (idx = 0; idx < 64; idx++) {
		uint64_t val = kpf & (1UL << idx);
		char *zero;

		if (!val)
			continue;

		snprintf(mask, sizeof(mask), "%016" PRIx64, val);

		while ((zero = strchr(mask, '0')))
			*zero = '.';

		fprintf(stdout, "      %s = %s\n", mask, kpf_desc[idx] ? kpf_desc[idx] : "?");
	}
}

static void print_full(unsigned long vma_start, unsigned long addr, uint64_t pm, uint64_t kpc, uint64_t kpf, uint64_t kpcg)
{
	if (kpagecgroup())
		fprintf(stdout, "  %0*lx pm %016" PRIx64 " pc %016" PRIx64 " pf %016" PRIx64 " cg %016" PRIx64 "\n", 2 * (int)sizeof(unsigned long), addr, pm, kpc, kpf, kpcg);
	else
		fprintf(stdout, "  %0*lx pm %016" PRIx64 " pc %016" PRIx64 " pf %016" PRIx64 "\n", 2 * (int)sizeof(unsigned long), addr, pm, kpc, kpf);

	fprintf(stdout, "    page\n");
	fprintf(stdout, "      idx %ld @ offset %lx (%ld kB) size %d kB\n", (addr - vma_start) / page_size, addr - vma_start, (addr - vma_start) / 1024, page_size / 1024);
	fprintf(stdout, "    pagemap\n");

	print_u64_bit(pm, PM_PAGE_PRESENT, "present in ram");
	print_pfn(pm);

	print_u64_bit(pm, PM_PAGE_SWAPPED, "swapped");
	print_swap(pm);

	print_u64_bit(pm, PM_PAGE_FILE_OR_SHARED_ANON, "file mapped or shared anonymous");
	print_u64_bit(pm, PM_PTE_UFFD_WRITE_PROTECTED, "userfaultfd write protected");
	print_u64_bit(pm, PM_PAGE_EXCLUSIVELY_MAPPED, "exclusively mapped");
	print_u64_bit(pm, PM_PTE_SOFT_DIRTY, "soft dirty");

	if (kpc) {
		fprintf(stdout, "    kpagecount\n");
		fprintf(stdout, "      %016" PRIx64 " = mapped %" PRId64 " %s\n", kpc, kpc, kpc == 1 ? "time" : "times");
	}

	print_kpf(kpf);

	if (kpagecgroup() && kpcg) {
		fprintf(stdout, "    kpagecgroup\n");
		fprintf(stdout, "      %016" PRIx64 " = memcg inode nr %" PRId64 "\n", kpcg, kpcg);
	}
}

static int read_u64_at_idx(int fd, uint64_t idx, uint64_t *val)
{
	int ret;

	if (fd < 0)
		return 1;

	ret = pread(fd, val, sizeof(uint64_t), idx * sizeof(uint64_t));
	if (ret != sizeof(uint64_t)) {
		fprintf(stderr, "pread() failed: %m\n");
		return 1;
	}

	return 0;
}

static void do_pm(unsigned long vma_start, unsigned long addr, uint64_t pm)
{
	uint64_t kpc = 0;
	uint64_t kpf = 0;
	uint64_t kpcg = 0;

	if (empty_pm(pm)) {
		if (!hide_empty)
			print_empty(addr);

		return;
	}

	if (pm & BIT(PM_PAGE_PRESENT)) {
		uint64_t pfn = pm & PM_PAGE_FRAME_NUMBER_MASK;

		read_u64_at_idx(kpagecount_fd, pfn, &kpc);
		read_u64_at_idx(kpageflags_fd, pfn, &kpf);
		read_u64_at_idx(kpagecgroup_fd, pfn, &kpcg);
	}

	if (verbose)
		print_full(vma_start, addr, pm, kpc, kpf, kpcg);
	else
		print_line(addr, pm, kpc, kpf, kpcg);
}

static int walk_vma_range(unsigned long vma_start, unsigned long start, unsigned long end)
{
	unsigned long nrpages;
	unsigned long idx;
	uint64_t off;

	if (start < vma_start)
		return 1;

	if (end <= start)
		return 1;

	nrpages = (end - start) / page_size;

	idx = start / page_size;
	off = idx * sizeof(uint64_t);
	off = lseek(pagemap_fd, off, SEEK_SET);
	if (off != idx * sizeof(uint64_t)) {
		fprintf(stderr, "lseek() off %lu: %m\n", (unsigned long)off);
		return 1;
	}

	for (idx = 0; idx < nrpages; idx++) {
		int ret;
		unsigned long addr;
		uint64_t pm;

		addr = start + idx * page_size;

		ret = read(pagemap_fd, &pm, sizeof(pm));
		if (ret != sizeof(pm)) {
#if 0
			fprintf(stderr, "read() vma->start %0*lx, off %016" PRIx64 ", %d != %d, %m\n",
				2 * (int)sizeof(unsigned long), start, off, ret, (unsigned int)sizeof(pm));
#endif
			pm = 0;
		}

		do_pm(vma_start, addr, pm);
	}

	return 0;
}

static int scan_vmas(pid_t pid, unsigned long addr)
{
	int ret = 0;
	char buf[1024];
	FILE *maps;

	snprintf(buf, sizeof(buf), "/proc/%d/maps", pid);
	maps = fopen(buf, "r");
	if (!maps) {
		fprintf(stderr, "%s: %m\n", buf);
		return 1;
	}

	while (fgets(buf, sizeof(buf), maps)) {
		unsigned long vma_start, vma_end;

		ret = sscanf(buf, "%lx-%lx", &vma_start, &vma_end);
		if (ret < 2) {
			fprintf(stderr, "can't parse: %s", buf);
			ret = 1;
			break;
		}

		if (addr) {
			ret = 2;

			if (addr >= vma_start && addr < vma_end) {
				fprintf(stdout, "%s", buf);
				ret = walk_vma_range(vma_start, addr, addr + page_size);
				break;
			}
		} else {
			fprintf(stdout, "%s", buf);
			ret = walk_vma_range(vma_start, vma_start, vma_end);
			if (ret)
				break;
		}
	}

	fclose(maps);

	if (ret == 2)
		fprintf(stdout, "%0*lx not found in pid %d vm space\n", 2 * (int)sizeof(unsigned long), addr, pid);

	return ret;
}

static void usage(const char *name, int status)
{
	fprintf(status ? stderr : stdout,
		"%s [-p pid]\n" \
		"options: \n" \
		"  -h\thelp\n" \
		"  -p\ttarget processs pid\n"
		"  -a\tvirtual address from process address space\n"
		"  -e\thide empty areas\n"
		"  -d\thide pages marked as soft dirty only\n"
		"  -v\tverbose\n",
		name);
	exit(status);
}

int main(int argc, char *argv[])
{
	int ret = 1;
	int opt;
	pid_t pid = 0;
	unsigned long addr = 0;
	char path[32];

	hide_empty = 0;
	hide_soft_dirty_only = 0;

	while ((opt = getopt(argc, argv, "hp:a:edv")) != -1) {
		switch (opt) {
			case 'h':
				usage(argv[0], 0);
				break;
			case 'p':
				pid = atoi(optarg);
				break;
			case 'a':
				addr = strtoul(optarg, NULL, 16);
				break;
			case 'e':
				hide_empty = 1;
				break;
			case 'd':
				hide_soft_dirty_only = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			default:
				usage(argv[0], 1);
		}
	}

	if (!pid)
		usage(argv[0], 1);

	if (addr)
		hide_empty = 0;

	page_size = sysconf(_SC_PAGESIZE);

	snprintf(path, sizeof(path), "/proc/%d", pid);
	ret = access(path, F_OK);
	if (ret) {
		fprintf(stderr, "%d: No such process\n", pid);
		return 1;
	}

	/* depends on CONFIG_PROC_PAGE_MONITOR */
	snprintf(path, sizeof(path), "/proc/%d/pagemap", pid);
	ret = access(path, F_OK);
	if (ret) {
		fprintf(stderr, "%s: %m (depends on CONFIG_PROC_PAGE_MONITOR)\n", path);
		return 1;
	}

	ret = access(path, R_OK);
	if (ret) {
		fprintf(stderr, "%s: %m\n", path);
		return 1;
	}

	ret = access("/proc/kpagecount", R_OK);
	if (ret) {
		fprintf(stderr, "/proc/kpagecount: %m\n");
		return 1;
	}

	ret = access("/proc/kpageflags", R_OK);
	if (ret) {
		fprintf(stderr, "/proc/kpageflags: %m\n");
		return 1;
	}

	pagemap_fd = open(path, O_RDONLY);
	if (pagemap_fd == -1) {
		fprintf(stderr, "open %s: %m\n", path);
		return 1;
	}

	kpagecount_fd = open("/proc/kpagecount", O_RDONLY);
	if (kpagecount_fd == -1) {
		fprintf(stderr, "open %s: %m\n", path);
		close(pagemap_fd);
		return 1;
	}

	kpageflags_fd = open("/proc/kpageflags", O_RDONLY);
	if (kpageflags_fd == -1) {
		fprintf(stderr, "open %s: %m\n", path);
		close(kpagecgroup_fd);
		close(pagemap_fd);
		return 1;
	}

	/* can fail, depends on CONFIG_MEMCG */
	kpagecgroup_fd = open("/proc/kpagecgroup", O_RDONLY);

	ret = scan_vmas(pid, addr);

	close(kpagecgroup_fd);
	close(kpageflags_fd);
	close(kpagecount_fd);
	close(pagemap_fd);

	return ret ? 1 : 0;
}
