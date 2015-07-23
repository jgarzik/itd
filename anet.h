#ifndef __ANET_H__
#define __ANET_H__

/*
 * Copyright 2010 Red Hat, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>
#include "elist.h"

enum {
	ATCP_MAX_WR_IOV		= 32,		/* max iov per writev(2) */
};

typedef void (*atcp_ev_func)(int, short, void *);

struct atcp_wr_ops {
	int			(*ev_wset)(void *, int, atcp_ev_func, void *);
	int			(*ev_add)(void *, const struct timeval *);
	int			(*ev_del)(void *);
};

struct atcp_wr_state {
	int			fd;		/* our socket */

	bool			writing;	/* actively trying to write? */

	size_t			write_cnt;	/* water level */
	size_t			write_cnt_max;

	struct list_head	write_q;	/* list of async writes */
	struct list_head	write_compl_q;	/* list of done writes */

	void			*priv;		/* untouched by atcp */

	/* various statistics */
	uint64_t		opt_write;	/* optimistic writes */

	const struct atcp_wr_ops *ops;
	void			*ev_info;	/* passed to ops->ev_* */
};

typedef bool (*atcp_write_func)(struct atcp_wr_state *, void *, bool);

struct atcp_write {
	const void		*buf;		/* write buffer pointer */
	int			togo;		/* write buffer remainder */

	int			length;		/* length for accounting */
	atcp_write_func		cb;		/* callback */
	void			*cb_data;	/* data passed to cb */

	struct atcp_wr_state	*wst;		/* our parent */

	struct list_head	node;		/* write_[compl_]q list node */
};

/* setup and teardown atcp write state */
extern void atcp_wr_exit(struct atcp_wr_state *wst);
extern void atcp_wr_init(struct atcp_wr_state *wst,
			  const struct atcp_wr_ops *ops, void *ev_info,
			  void *priv);

/* generic write callback, that call free(cb_data2) */
extern bool atcp_cb_free(struct atcp_wr_state *wst, void *cb_data, bool done);

/* clear all write queues immediately, even if not complete */
extern void atcp_write_free_all(struct atcp_wr_state *wst);

/* complete all writes found on completion queue */
extern bool atcp_write_run_compl(struct atcp_wr_state *wst);

/* initialize internal fd, event setup */
extern void atcp_wr_set_fd(struct atcp_wr_state *wst, int fd);

/* add a buffer to the write queue */
extern int atcp_writeq(struct atcp_wr_state *wst, const void *buf, unsigned int buflen,
	        atcp_write_func cb, void *cb_data);

/* begin pushing write queue to socket */
extern bool atcp_write_start(struct atcp_wr_state *wst);

/* is anything on the write queue at the moment? */
static inline bool atcp_wq_empty(struct atcp_wr_state *wst)
{
	return list_empty(&wst->write_q) ? true : false;
}

/* total number of octets queued at this moment */
static inline size_t atcp_wqueued(struct atcp_wr_state *wst)
{
	return wst->write_cnt;
}

#endif /* __ANET_H__ */
