/*
 * e2fsck.h
 *
 * Copyright (C) 1993, 1994 Theodore Ts'o.  This file may be
 * redistributed under the terms of the GNU Public License.
 *
 */

#ifndef _E2FSCK_H
#define _E2FSCK_H

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <stdlib.h>
#include <time.h>
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#if EXT2_FLAT_INCLUDES
#include "ext2_fs.h"
#include "ext2fs.h"
#include "blkid.h"
#else
#include "ext2fs/ext2_fs.h"
#include "ext2fs/ext2fs.h"
#include "blkid/blkid.h"
#endif

#include "support/profile.h"
#include "support/prof_err.h"

#ifdef ENABLE_NLS
#include <libintl.h>
#include <locale.h>
#define _(a) (gettext (a))
#ifdef gettext_noop
#define N_(a) gettext_noop (a)
#else
#define N_(a) (a)
#endif
#define P_(singular, plural, n) (ngettext (singular, plural, n))
#ifndef NLS_CAT_NAME
#define NLS_CAT_NAME "e2fsprogs"
#endif
#ifndef LOCALEDIR
#define LOCALEDIR "/usr/share/locale"
#endif
#else
#define _(a) (a)
#define N_(a) a
#define P_(singular, plural, n) ((n) == 1 ? (singular) : (plural))
#endif

#ifdef __GNUC__
#define E2FSCK_ATTR(x) __attribute__(x)
#else
#define E2FSCK_ATTR(x)
#endif

#include "support/quotaio.h"

/*
 * Exit codes used by fsck-type programs
 */
#define FSCK_OK          0	/* No errors */
#define FSCK_NONDESTRUCT 1	/* File system errors corrected */
#define FSCK_REBOOT      2	/* System should be rebooted */
#define FSCK_UNCORRECTED 4	/* File system errors left uncorrected */
#define FSCK_ERROR       8	/* Operational error */
#define FSCK_USAGE       16	/* Usage or syntax error */
#define FSCK_CANCELED	 32	/* Aborted with a signal or ^C */
#define FSCK_LIBRARY     128	/* Shared library error */

/*
 * The last ext2fs revision level that this version of e2fsck is able to
 * support
 */
#define E2FSCK_CURRENT_REV	1

/*
 * The directory information structure; stores directory information
 * collected in earlier passes, to avoid disk i/o in fetching the
 * directory information.
 */
struct dir_info {
	ext2_ino_t		ino;	/* Inode number */
	ext2_ino_t		dotdot;	/* Parent according to '..' */
	ext2_ino_t		parent; /* Parent according to treewalk */
};


/*
 * The indexed directory information structure; stores information for
 * directories which contain a hash tree index.
 */
struct dx_dir_info {
	ext2_ino_t		ino;		/* Inode number */
	short			depth;		/* depth of tree (15 bits) */
	__u8			hashversion;
	__u8			casefolded_hash:1;
	blk_t			numblocks;	/* number of blocks in dir */
	struct dx_dirblock_info	*dx_block;	/* Array of size numblocks */
};

#define DX_DIRBLOCK_ROOT	1
#define DX_DIRBLOCK_LEAF	2
#define DX_DIRBLOCK_NODE	3
#define DX_DIRBLOCK_CORRUPT	4
#define DX_DIRBLOCK_CLEARED	8

struct dx_dirblock_info {
	int		type;
	int		flags;
	blk64_t		phys;
	blk64_t		parent;
	blk64_t		previous;
	ext2_dirhash_t	min_hash;
	ext2_dirhash_t	max_hash;
	ext2_dirhash_t	node_min_hash;
	ext2_dirhash_t	node_max_hash;
};

#define DX_FLAG_REFERENCED	1
#define DX_FLAG_DUP_REF		2
#define DX_FLAG_FIRST		4
#define DX_FLAG_LAST		8

#define RESOURCE_TRACK

#ifdef RESOURCE_TRACK
/*
 * This structure is used for keeping track of how much resources have
 * been used for a particular pass of e2fsck.
 */
struct resource_track {
	struct timeval time_start;
	struct timeval user_start;
	struct timeval system_start;
	void	*brk_start;
	unsigned long long bytes_read;
	unsigned long long bytes_written;
};
#endif

/*
 * E2fsck options
 */
#define E2F_OPT_READONLY	0x0001
#define E2F_OPT_PREEN		0x0002
#define E2F_OPT_YES		0x0004
#define E2F_OPT_NO		0x0008
#define E2F_OPT_TIME		0x0010
#define E2F_OPT_TIME2		0x0020
#define E2F_OPT_CHECKBLOCKS	0x0040
#define E2F_OPT_DEBUG		0x0080
#define E2F_OPT_FORCE		0x0100
#define E2F_OPT_WRITECHECK	0x0200
#define E2F_OPT_COMPRESS_DIRS	0x0400
#define E2F_OPT_FRAGCHECK	0x0800
#define E2F_OPT_JOURNAL_ONLY	0x1000 /* only replay the journal */
#define E2F_OPT_DISCARD		0x2000
#define E2F_OPT_CONVERT_BMAP	0x4000 /* convert blockmap to extent */
#define E2F_OPT_FIXES_ONLY	0x8000 /* skip all optimizations */
#define E2F_OPT_NOOPT_EXTENTS	0x10000 /* don't optimize extents */
#define E2F_OPT_ICOUNT_FULLMAP	0x20000 /* use an array for inode counts */
#define E2F_OPT_UNSHARE_BLOCKS  0x40000
#define E2F_OPT_MULTITHREAD	0x100000 /* Use multiple threads to speedup */

/*
 * E2fsck flags
 */
#define E2F_FLAG_ABORT		0x0001 /* Abort signaled */
#define E2F_FLAG_CANCEL		0x0002 /* Cancel signaled */
#define E2F_FLAG_SIGNAL_MASK	(E2F_FLAG_ABORT | E2F_FLAG_CANCEL)
#define E2F_FLAG_RESTART	0x0004 /* Restart signaled */
#define E2F_FLAG_RUN_RETURN	(E2F_FLAG_SIGNAL_MASK | E2F_FLAG_RESTART)
#define E2F_FLAG_RESTART_LATER	0x0008 /* Restart after all iterations done */
#define E2F_FLAG_SETJMP_OK	0x0010 /* Setjmp valid for abort */

#define E2F_FLAG_PROG_BAR	0x0020 /* Progress bar on screen */
#define E2F_FLAG_PROG_SUPPRESS	0x0040 /* Progress suspended */
#define E2F_FLAG_JOURNAL_INODE	0x0080 /* Create a new ext3 journal inode */
#define E2F_FLAG_SB_SPECIFIED	0x0100 /* The superblock was explicitly
					* specified by the user */
#define E2F_FLAG_RESTARTED	0x0200 /* E2fsck has been restarted */
#define E2F_FLAG_RESIZE_INODE	0x0400 /* Request to recreate resize inode */
#define E2F_FLAG_GOT_DEVSIZE	0x0800 /* Device size has been fetched */
#define E2F_FLAG_EXITING	0x1000 /* E2fsck exiting due to errors */
#define E2F_FLAG_TIME_INSANE	0x2000 /* Time is insane */
#define E2F_FLAG_PROBLEMS_FIXED	0x4000 /* At least one problem was fixed */
#define E2F_FLAG_ALLOC_OK	0x8000 /* Can we allocate blocks? */
#define E2F_FLAG_EXPAND_EISIZE	0x10000 /* Expand the inodes (i_extra_isize) */

#define E2F_RESET_FLAGS (E2F_FLAG_TIME_INSANE | E2F_FLAG_PROBLEMS_FIXED)

/*
 * Defines for indicating the e2fsck pass number
 */
#define E2F_PASS_1	1
#define E2F_PASS_2	2
#define E2F_PASS_3	3
#define E2F_PASS_4	4
#define E2F_PASS_5	5
#define E2F_PASS_1B	6

enum shared_opt {
	E2F_SHARED_PRESERVE = 0,
	E2F_SHARED_DELETE,
	E2F_SHARED_LPF
};

enum clone_opt {
	E2F_CLONE_DUP = 0,
	E2F_CLONE_ZERO
};

#define EXT4_FITS_IN_INODE(ext4_inode, einode, field)	\
	((offsetof(typeof(*ext4_inode), field) +	\
	  sizeof(ext4_inode->field)) <=			\
	   (EXT2_GOOD_OLD_INODE_SIZE +			\
	    (einode)->i_extra_isize))			\

#define EXT4_XTIME_FUTURE(ctx, sb, xtime, margin)	\
	(!((ctx)->flags & E2F_FLAG_TIME_INSANE) &&	\
	 (xtime) > (ctx)->now + (margin))
#define EXT4_XTIME_ANCIENT(ctx, sb, xtime, margin)	\
	((sb)->s_mkfs_time > (margin) && (xtime) < (sb)->s_mkfs_time - (margin))

#define BADNESS_NORMAL		1
#define BADNESS_HIGH		2
#define BADNESS_THRESHOLD	8
#define BADNESS_BAD_MODE	100
#define BADNESS_LARGE_FILE	2199023255552ULL

/*
 * Define the extended attribute refcount structure
 */
typedef struct ea_refcount *ext2_refcount_t;

/*
 * This is the global e2fsck structure.
 */
typedef struct e2fsck_struct *e2fsck_t;

#define MAX_EXTENT_DEPTH_COUNT 5

struct e2fsck_struct {
	/* ---- Following fields are never updated during the pass1 ---- */
	/* Global context to get the cancel flag */
	e2fsck_t		global_ctx;
	const char		*program_name;
	char			*filesystem_name;
	char			*device_name;
	char			*io_options;
	int			 options; /* E2F_OPT_* flags */
	int			 blocksize; /* blocksize */
	blk64_t			 use_superblock; /* sb requested by user */
	blk64_t			 superblock; /* sb used to open fs */
	blk64_t			 num_blocks; /* Total number of blocks */
	blk64_t			 free_blocks;
	ext2_ino_t		 free_inodes;
	int			 mount_flags;
	int			 openfs_flags;
	io_manager		 io_manager;
	blkid_cache		 blkid; /* blkid cache */
#ifdef HAVE_SETJMP_H
	jmp_buf			abort_loc;
#endif
#ifdef RESOURCE_TRACK
	/*
	 * For timing purposes
	 */
	struct resource_track	global_rtrack;
#endif
	int			bad_lost_and_found;
	/*
	 * Tuning parameters
	 */
	int			process_inode_size;
	int			inode_buffer_blocks;
	unsigned int		htree_slack_percentage;

	/*
	 * ext3 journal support
	 */
	io_channel		journal_io;
	char			*journal_name;
	/* misc fields */
	time_t			now;
	/* For working around buggy init scripts */
	time_t			time_fudge;

	int			ext_attr_ver;
	int			blocks_per_page;

	/* Expand large inodes to atleast these many bytes */
	int			want_extra_isize;
	/* minimum i_extra_isize found in used inodes. Should not be lesser
	 * than s_min_extra_isize.
	 */
	__u32			min_extra_isize;

	/* misc fields */
	enum shared_opt		shared;
	enum clone_opt		clone;

	/* Are we connected directly to a tty? */
	int			interactive;
	char			start_meta[2], stop_meta[2];
	/*
	 * For the use of callers of the e2fsck functions; not used by
	 * e2fsck functions themselves.
	 */
	void			*priv_data;
	/* Undo file */
	char			*undo_file;
	/* How much are we allowed to readahead? */
	unsigned long long	readahead_kb;
 
	/* ---- Following fields are shared by different threads for pass1 -*/
	/* E2fsck internal flags */
	int			flags;

	int			inode_badness_threshold;

	/*
	 * How we display the progress update (for unix)
	 */
	int			progress_fd;
	int			progress_pos;
	int			progress_last_percent;
	unsigned int		progress_last_time;

	int (*progress)(e2fsck_t ctx, int pass, unsigned long cur,
			unsigned long max);

	/* Metadata blocks */
	ext2fs_block_bitmap	block_metadata_map;
	profile_t		profile;
	/* Reserve blocks for root and l+f re-creation */
	blk64_t			root_repair_block, lnf_repair_block;
	/*
	 * Location of the lost and found directory
	 */
	ext2_ino_t		lost_and_found;

	/* ---- Following fields are seperated for each thread for pass1- */
	ext2_filsys		 fs;
	FILE			*logf;
	char			*log_fn;
	FILE			*problem_logf;
	char			*problem_log_fn;

	/* Inodes which are in use */
	ext2fs_inode_bitmap	inode_used_map;
	/* Inodes which are bad somehow */
	ext2fs_inode_bitmap	inode_bad_map;
	/* Inodes which are directories */
	ext2fs_inode_bitmap	inode_dir_map;
	/* Inodes which are in bad blocks */
	ext2fs_inode_bitmap	inode_bb_map;
	/* AFS inodes */
	ext2fs_inode_bitmap	inode_imagic_map;
	/* Inodes which are regular files */
	ext2fs_inode_bitmap	inode_reg_map;
	/* Inodes to rebuild extent trees */
	ext2fs_inode_bitmap	inodes_to_rebuild;
	/* Blocks which are in use */
	ext2fs_block_bitmap	block_found_map;
	/* Blks referenced more than once */
	ext2fs_block_bitmap	block_dup_map;
	/* Blocks which are used by EA's */
	ext2fs_block_bitmap	block_ea_map;

	ext2fs_inode_bitmap	expand_eisize_map;

	/*
	 * Inode count arrays
	 */
	ext2_icount_t		inode_count;
	ext2_icount_t		inode_link_info;
	ext2_icount_t		inode_badness;

	ext2_refcount_t		refcount;
	ext2_refcount_t		refcount_extra;

	/*
	 * Quota blocks and inodes to be charged for each ea block.
	 */
	ext2_refcount_t		ea_block_quota_blocks;
	ext2_refcount_t		ea_block_quota_inodes;

	/*
	 * ea_inode references from attr entries.
	 */
	ext2_refcount_t		ea_inode_refs;

	/*
	 * Array of flags indicating whether an inode bitmap, block
	 * bitmap, or inode table is invalid
	 */
	int			*invalid_inode_bitmap_flag;
	int 			*invalid_block_bitmap_flag;
	int			*invalid_inode_table_flag;
	/* There are invalid bitmaps/itable */
	int			invalid_bitmaps;

	/*
	 * Block buffer
	 */
	char			*block_buf;

	/*
	 * For pass1_check_directory and pass1_get_blocks
	 */
	ext2_ino_t		stashed_ino;
	struct ext2_inode	*stashed_inode;
	/* Thread index, if global_ctx is null, this field is unused */
	int			thread_index;

	/*
	 * Directory information
	 */
	struct dir_info_db	*dir_info;

	/*
	 * Indexed directory information
	 */
	ext2_ino_t		dx_dir_info_count;
	ext2_ino_t		dx_dir_info_size;
	struct dx_dir_info	*dx_dir_info;

	/*
	 * Directories to hash
	 */
	ext2_u32_list		dirs_to_hash;

	/*
	 * Ext4 quota support
	 */
	ext2_u32_list		encrypted_dirs;

	quota_ctx_t		qctx;

	int			fs_unexpanded_inodes;
	__u32			fs_directory_count;
	__u32			fs_regular_count;
	__u32			fs_blockdev_count;
	__u32			fs_chardev_count;
	__u32			fs_links_count;
	__u32			fs_symlinks_count;
	__u32			fs_fast_symlinks_count;
	__u32			fs_fifo_count;
	__u32			fs_total_count;
	__u32			fs_badblocks_count;
	__u32			fs_sockets_count;
	__u32			fs_ind_count;
	__u32			fs_dind_count;
	__u32			fs_tind_count;
	__u32			fs_fragmented;
	__u32			fs_fragmented_dir;
	__u32			large_files;
	__u32			extent_depth_count[MAX_EXTENT_DEPTH_COUNT];
};

#ifdef CONFIG_PFSCK
struct e2fsck_thread_info {
	/* ID returned by pthread_create() */
	pthread_t		 eti_thread_id;
	/* Application-defined thread index */
	int			 eti_thread_index;
	/* Thread has been started */
	int			 eti_started;
	/* Context used for this thread */
	e2fsck_t		 eti_thread_ctx;
};
#endif

/* Data structures to evaluate whether an extent tree needs rebuilding. */
struct extent_tree_level {
	unsigned int	num_extents;
	unsigned int	max_extents;
};

struct extent_tree_info {
	ext2_ino_t ino;
	int force_rebuild;
	struct extent_tree_level	ext_info[MAX_EXTENT_DEPTH_COUNT];
};

/* Used by the region allocation code */
typedef __u64 region_addr_t;
typedef struct region_struct *region_t;

#ifndef HAVE_STRNLEN
#define strnlen(str, x) e2fsck_strnlen((str),(x))
extern int e2fsck_strnlen(const char * s, int count);
#endif

/*
 * Procedure declarations
 */

extern void e2fsck_pass1(e2fsck_t ctx);
extern void e2fsck_pass1_dupblocks(e2fsck_t ctx, char *block_buf);
extern void e2fsck_pass2(e2fsck_t ctx);
extern void e2fsck_pass3(e2fsck_t ctx);
extern void e2fsck_pass4(e2fsck_t ctx);
extern void e2fsck_pass5(e2fsck_t ctx);

/* e2fsck.c */
extern errcode_t e2fsck_allocate_context(e2fsck_t *ret);
extern errcode_t e2fsck_reset_context(e2fsck_t ctx);
extern void e2fsck_free_context(e2fsck_t ctx);
extern int e2fsck_run(e2fsck_t ctx);


/* badblock.c */
extern void read_bad_blocks_file(e2fsck_t ctx, const char *bad_blocks_file,
				 int replace_bad_blocks);

/* dirinfo.c */
extern void e2fsck_add_dir_info(e2fsck_t ctx, ext2_ino_t ino, ext2_ino_t parent);
extern void e2fsck_free_dir_info(e2fsck_t ctx);
extern int e2fsck_get_num_dirinfo(e2fsck_t ctx);
extern struct dir_info_iter *e2fsck_dir_info_iter_begin(e2fsck_t ctx);
extern struct dir_info *e2fsck_dir_info_iter(e2fsck_t ctx,
					     struct dir_info_iter *);
extern void e2fsck_dir_info_iter_end(e2fsck_t ctx, struct dir_info_iter *);
extern int e2fsck_dir_info_set_parent(e2fsck_t ctx, ext2_ino_t ino,
				      ext2_ino_t parent);
extern int e2fsck_dir_info_set_dotdot(e2fsck_t ctx, ext2_ino_t ino,
				      ext2_ino_t dotdot);
extern int e2fsck_dir_info_get_parent(e2fsck_t ctx, ext2_ino_t ino,
				      ext2_ino_t *parent);
extern int e2fsck_dir_info_get_dotdot(e2fsck_t ctx, ext2_ino_t ino,
				      ext2_ino_t *dotdot);

/* dx_dirinfo.c */
extern void e2fsck_add_dx_dir(e2fsck_t ctx, ext2_ino_t ino,
			      struct ext2_inode *inode, int num_blocks);
extern struct dx_dir_info *e2fsck_get_dx_dir_info(e2fsck_t ctx, ext2_ino_t ino);
extern void e2fsck_free_dx_dir_info(e2fsck_t ctx);
extern ext2_ino_t e2fsck_get_num_dx_dirinfo(e2fsck_t ctx);
extern struct dx_dir_info *e2fsck_dx_dir_info_iter(e2fsck_t ctx,
						   ext2_ino_t *control);

/* ea_refcount.c */
typedef __u64 ea_key_t;
typedef __u64 ea_value_t;

extern errcode_t ea_refcount_create(size_t size, ext2_refcount_t *ret);
extern void ea_refcount_free(ext2_refcount_t refcount);
extern errcode_t ea_refcount_fetch(ext2_refcount_t refcount, ea_key_t ea_key,
				   ea_value_t *ret);
extern errcode_t ea_refcount_increment(ext2_refcount_t refcount,
				       ea_key_t ea_key, ea_value_t *ret);
extern errcode_t ea_refcount_decrement(ext2_refcount_t refcount,
				       ea_key_t ea_key, ea_value_t *ret);
extern errcode_t ea_refcount_store(ext2_refcount_t refcount, ea_key_t ea_key,
				   ea_value_t count);
extern size_t ext2fs_get_refcount_size(ext2_refcount_t refcount);
extern void ea_refcount_intr_begin(ext2_refcount_t refcount);
extern ea_key_t ea_refcount_intr_next(ext2_refcount_t refcount,
				      ea_value_t *ret);

/* ehandler.c */
extern const char *ehandler_operation(const char *op);
extern void ehandler_init(io_channel channel);

/* extents.c */
struct problem_context;
errcode_t e2fsck_rebuild_extents_later(e2fsck_t ctx, ext2_ino_t ino);
int e2fsck_ino_will_be_rebuilt(e2fsck_t ctx, ext2_ino_t ino);
void e2fsck_pass1e(e2fsck_t ctx);
errcode_t e2fsck_check_rebuild_extents(e2fsck_t ctx, ext2_ino_t ino,
				       struct ext2_inode *inode,
				       struct problem_context *pctx);
errcode_t e2fsck_should_rebuild_extents(e2fsck_t ctx,
					struct problem_context *pctx,
					struct extent_tree_info *eti,
					struct ext2_extent_info *info);

/* journal.c */
extern errcode_t e2fsck_check_ext3_journal(e2fsck_t ctx);
extern errcode_t e2fsck_run_ext3_journal(e2fsck_t ctx);
extern void e2fsck_move_ext3_journal(e2fsck_t ctx);
extern int e2fsck_fix_ext3_journal_hint(e2fsck_t ctx);

/* logfile.c */
extern void set_up_logging(e2fsck_t ctx);

/* quota.c */
extern void e2fsck_hide_quota(e2fsck_t ctx);
extern void e2fsck_validate_quota_inodes(e2fsck_t ctx);

/* pass1.c */
extern errcode_t e2fsck_setup_icount(e2fsck_t ctx, const char *icount_name,
				     int flags, ext2_icount_t hint,
				     ext2_icount_t *ret);
extern void e2fsck_use_inode_shortcuts(e2fsck_t ctx, int use_shortcuts);
extern int e2fsck_pass1_check_device_inode(ext2_filsys fs,
					   struct ext2_inode *inode);
extern int e2fsck_pass1_check_symlink(e2fsck_t ctx, ext2_ino_t ino,
				      struct ext2_inode *inode, char *buf);
extern void e2fsck_clear_inode(e2fsck_t ctx, ext2_ino_t ino,
			       struct ext2_inode *inode, int restart_flag,
			       const char *source);
#define e2fsck_mark_inode_bad(ctx, ino, count) \
		e2fsck_mark_inode_bad_loc(ctx, ino, count, __func__, __LINE__)
extern void e2fsck_mark_inode_bad_loc(e2fsck_t ctx, ino_t ino, int count,
				      const char *func, const int line);
extern int is_inode_bad(e2fsck_t ctx, ino_t ino);
extern void e2fsck_intercept_block_allocations(e2fsck_t ctx);

/* pass2.c */
extern int e2fsck_process_bad_inode(e2fsck_t ctx, ext2_ino_t dir,
				    ext2_ino_t ino, char *buf);

/* pass3.c */
extern int e2fsck_reconnect_file(e2fsck_t ctx, ext2_ino_t inode);
extern errcode_t e2fsck_expand_directory(e2fsck_t ctx, ext2_ino_t dir,
					 int num, int gauranteed_size);
extern ext2_ino_t e2fsck_get_lost_and_found(e2fsck_t ctx, int fix);
extern errcode_t e2fsck_adjust_inode_count(e2fsck_t ctx, ext2_ino_t ino,
					   int adj);

/* readahead.c */
#define E2FSCK_READA_SUPER	(0x01)
#define E2FSCK_READA_GDT	(0x02)
#define E2FSCK_READA_BBITMAP	(0x04)
#define E2FSCK_READA_IBITMAP	(0x08)
#define E2FSCK_READA_ITABLE	(0x10)
#define E2FSCK_READA_ALL_FLAGS	(0x1F)
errcode_t e2fsck_readahead(ext2_filsys fs, int flags, dgrp_t start,
			   dgrp_t ngroups);
#define E2FSCK_RA_DBLIST_IGNORE_BLOCKCNT	(0x01)
#define E2FSCK_RA_DBLIST_ALL_FLAGS		(0x01)
errcode_t e2fsck_readahead_dblist(ext2_filsys fs, int flags,
				  ext2_dblist dblist,
				  unsigned long long start,
				  unsigned long long count);
int e2fsck_can_readahead(ext2_filsys fs);
unsigned long long e2fsck_guess_readahead(ext2_filsys fs);

/* region.c */
extern region_t region_create(region_addr_t min, region_addr_t max);
extern void region_free(region_t region);
extern int region_allocate(region_t region, region_addr_t start, int n);

/* rehash.c */
void e2fsck_rehash_dir_later(e2fsck_t ctx, ext2_ino_t ino);
int e2fsck_dir_will_be_rehashed(e2fsck_t ctx, ext2_ino_t ino);
errcode_t e2fsck_rehash_dir(e2fsck_t ctx, ext2_ino_t ino,
			    struct problem_context *pctx);
void e2fsck_rehash_directories(e2fsck_t ctx);

/* sigcatcher.c */
void sigcatcher_setup(void);

/* super.c */
void check_super_block(e2fsck_t ctx);
int check_backup_super_block(e2fsck_t ctx);
void check_resize_inode(e2fsck_t ctx);

/* util.c */
extern void *e2fsck_allocate_memory(e2fsck_t ctx, unsigned long size,
				    const char *description);
extern int ask(e2fsck_t ctx, const char * string, int def);
extern int ask_yn(e2fsck_t ctx, const char * string, int def);
extern void fatal_error(e2fsck_t ctx, const char * fmt_string);
extern void log_out(e2fsck_t ctx, const char *fmt, ...)
	E2FSCK_ATTR((format(printf, 2, 3)));
extern void log_err(e2fsck_t ctx, const char *fmt, ...)
	E2FSCK_ATTR((format(printf, 2, 3)));
extern void e2fsck_read_bitmaps(e2fsck_t ctx);
extern void e2fsck_write_bitmaps(e2fsck_t ctx);
extern void preenhalt(e2fsck_t ctx);
extern char *string_copy(e2fsck_t ctx, const char *str, int len);
extern int fs_proc_check(const char *fs_name);
extern int check_for_modules(const char *fs_name);
#ifdef RESOURCE_TRACK
extern void print_resource_track(e2fsck_t ctx,
				 const char *desc,
				 struct resource_track *track,
				 io_channel channel);
extern void init_resource_track(struct resource_track *track,
				io_channel channel);
#else
#define print_resource_track(ctx, desc, track, channel) do { } while (0)
#define init_resource_track(track, channel) do { } while (0)
#endif
extern int inode_has_valid_blocks(struct ext2_inode *inode);
extern void e2fsck_read_inode(e2fsck_t ctx, unsigned long ino,
			      struct ext2_inode * inode, const char * proc);
extern void e2fsck_read_inode_full(e2fsck_t ctx, unsigned long ino,
				   struct ext2_inode *inode,
				   const int bufsize, const char *proc);
extern void e2fsck_write_inode(e2fsck_t ctx, unsigned long ino,
			       struct ext2_inode * inode, const char * proc);
extern void e2fsck_write_inode_full(e2fsck_t ctx, unsigned long ino,
                               struct ext2_inode * inode, int bufsize,
                               const char *proc);
#ifdef MTRACE
extern void mtrace_print(char *mesg);
#endif
extern blk64_t get_backup_sb(e2fsck_t ctx, ext2_filsys fs,
			   const char *name, io_manager manager);
extern int ext2_file_type(unsigned int mode);
extern int write_all(int fd, char *buf, size_t count);
void dump_mmp_msg(struct mmp_struct *mmp, const char *fmt, ...)
	E2FSCK_ATTR((format(printf, 2, 3)));
errcode_t e2fsck_mmp_update(ext2_filsys fs);

extern void e2fsck_set_bitmap_type(ext2_filsys fs,
				   unsigned int default_type,
				   const char *profile_name,
				   unsigned int *old_type);
extern errcode_t e2fsck_allocate_inode_bitmap(ext2_filsys fs,
					      const char *descr,
					      int default_type,
					      const char *profile_name,
					      ext2fs_inode_bitmap *ret);
extern errcode_t e2fsck_allocate_block_bitmap(ext2_filsys fs,
					      const char *descr,
					      int default_type,
					      const char *profile_name,
					      ext2fs_block_bitmap *ret);
extern errcode_t e2fsck_allocate_subcluster_bitmap(ext2_filsys fs,
						   const char *descr,
						   int default_type,
						   const char *profile_name,
						   ext2fs_block_bitmap *ret);
unsigned long long get_memory_size(void);

/* unix.c */
extern void e2fsck_clear_progbar(e2fsck_t ctx);
extern int e2fsck_simple_progress(e2fsck_t ctx, const char *label,
				  float percent, unsigned int dpynum);

#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))

#endif /* _E2FSCK_H */
