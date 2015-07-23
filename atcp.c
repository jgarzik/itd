
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

//#include "hail-config.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/uio.h>
#include "anet.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

bool atcp_cb_free(struct atcp_wr_state *wst, void *cb_data, bool done)
{
	free(cb_data);
	return false;
}

static void atcp_write_complete(struct atcp_write *tmp)
{
	struct atcp_wr_state *wst = tmp->wst;

	list_del(&tmp->node);
	list_add_tail(&tmp->node, &wst->write_compl_q);
}

static bool atcp_write_free(struct atcp_write *tmp, bool done)
{
	struct atcp_wr_state *wst = tmp->wst;
	bool rcb = false;

	wst->write_cnt -= tmp->length;
	list_del_init(&tmp->node);
	if (tmp->cb)
		rcb = tmp->cb(wst, tmp->cb_data, done);
	free(tmp);

	return rcb;
}

bool atcp_write_run_compl(struct atcp_wr_state *wst)
{
	struct atcp_write *wr;
	bool do_loop;

	do_loop = false;
	while (!list_empty(&wst->write_compl_q)) {
		wr = list_entry(wst->write_compl_q.next,
				struct atcp_write, node);
		do_loop |= atcp_write_free(wr, true);
	}
	return do_loop;
}

void atcp_write_free_all(struct atcp_wr_state *wst)
{
	struct atcp_write *wr, *tmp;

	atcp_write_run_compl(wst);
	list_for_each_entry_safe(wr, tmp, &wst->write_q, node) {
		atcp_write_free(wr, false);
	}
}

static int atcp_wr_iov(struct atcp_wr_state *wst,
		       struct iovec *iov, int max_iov)
{
	struct atcp_write *tmp;
	int n_iov = 0;

	list_for_each_entry(tmp, &wst->write_q, node) {
		if (n_iov == max_iov)
			break;
		/* bleh, struct iovec should declare iov_base const */
		iov[n_iov].iov_base = (void *) tmp->buf;
		iov[n_iov].iov_len = tmp->togo;
		n_iov++;
	}

	return n_iov;
}

static void atcp_wr_completed(struct atcp_wr_state *wst, ssize_t rc)
{
	/* iterate through write queue, issuing completions based on
	 * amount of data written
	 */
	while (rc > 0) {
		struct atcp_write *tmp;
		int sz;

		/* get pointer to first record on list */
		tmp = list_entry(wst->write_q.next, struct atcp_write, node);

		/* mark data consumed by decreasing tmp->len */
		sz = (tmp->togo < rc) ? tmp->togo : rc;
		tmp->togo -= sz;
		tmp->buf += sz;
		rc -= sz;

		/* if tmp->len reaches zero, write is complete,
		 * so schedule it for clean up (cannot call callback
		 * right away or an endless recursion will result)
		 */
		if (tmp->togo == 0)
			atcp_write_complete(tmp);
	}
}

static bool atcp_writable(struct atcp_wr_state *wst)
{
	int n_iov;
	ssize_t rc;
	struct iovec iov[ATCP_MAX_WR_IOV];

	/* accumulate pending writes into iovec */
	n_iov = atcp_wr_iov(wst, iov, ARRAY_SIZE(iov));

	/* execute non-blocking write */
do_write:
	rc = writev(wst->fd, iov, n_iov);
	if (rc < 0) {
		if (errno == EINTR)
			goto do_write;
		if (errno != EAGAIN)
			goto err_out;
		return true;
	}

	atcp_wr_completed(wst, rc);

	/* if we emptied the queue, clear write notification */
	if (atcp_wq_empty(wst)) {
		wst->writing = false;
		if (wst->ops->ev_del(wst->ev_info) < 0)
			goto err_out;
	}

	return true;

err_out:
	atcp_write_free_all(wst);
	return false;
}

static void atcp_wr_event(int fd, short events, void *userdata)
{
	struct atcp_wr_state *wst = userdata;

	atcp_writable(wst);
	atcp_write_run_compl(wst);
}

void atcp_wr_set_fd(struct atcp_wr_state *wst, int fd)
{
	wst->fd = fd;

	wst->ops->ev_wset(wst->ev_info, wst->fd,
		  atcp_wr_event, wst);
}

bool atcp_write_start(struct atcp_wr_state *wst)
{
	if (atcp_wq_empty(wst))
		return true;		/* loop, not poll */

	/* if write-poll already active, nothing further to do */
	if (wst->writing)
		return false;		/* poll wait */

	/* attempt optimistic write, in hopes of avoiding poll,
	 * or at least refill the write buffers so as to not
	 * get -immediately- called again by the kernel
	 */
	atcp_writable(wst);
	if (atcp_wq_empty(wst)) {
		wst->opt_write++;
		return true;		/* loop, not poll */
	}

	if (wst->ops->ev_add(wst->ev_info, NULL) < 0)
		return true;		/* loop, not poll */

	wst->writing = true;

	return false;			/* poll wait */
}

int atcp_writeq(struct atcp_wr_state *wst, const void *buf, unsigned int buflen,
	        atcp_write_func cb, void *cb_data)
{
	struct atcp_write *wr;

	if (!buf || !buflen)
		return -EINVAL;

	wr = calloc(1, sizeof(struct atcp_write));
	if (!wr)
		return -ENOMEM;

	wr->buf = buf;
	wr->togo = buflen;
	wr->length = buflen;
	wr->cb = cb;
	wr->cb_data = cb_data;
	wr->wst = wst;
	list_add_tail(&wr->node, &wst->write_q);
	wst->write_cnt += buflen;
	if (wst->write_cnt > wst->write_cnt_max)
		wst->write_cnt_max = wst->write_cnt;

	return 0;
}

void atcp_wr_exit(struct atcp_wr_state *wst)
{
	if (!wst)
		return;

	if (wst->writing)
		wst->ops->ev_del(wst->ev_info);
	
	atcp_write_free_all(wst);
}

void atcp_wr_init(struct atcp_wr_state *wst,
		  const struct atcp_wr_ops *ops, void *ev_info,
		  void *priv)
{
	memset(wst, 0, sizeof(*wst));

	INIT_LIST_HEAD(&wst->write_q);
	INIT_LIST_HEAD(&wst->write_compl_q);

	wst->fd = -1;

	wst->ops = ops;
	wst->ev_info = ev_info;
	wst->priv = priv;
}

