/****************************************************************************
 * net/netdev/netdown_notifier.c
 *
 *   Copyright (C) 2018 Gregory Nutt. All rights reserved.
 *   Author: Gregory Nutt <gnutt@nuttx.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name NuttX nor the names of its contributors may be
 *    used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>

#include <nuttx/signal.h>
#include <nuttx/mm/iob.h>
#include <nuttx/net/netdev.h>

#include "netdev/netdev.h"

#ifdef CONFIG_NETDOWN_NOTIFIER

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: netdown_notifier_setup
 *
 * Description:
 *   Set up to notify the specified PID with the provided signal number.
 *
 *   NOTE: To avoid race conditions, the caller should set the sigprocmask
 *   to block signal delivery.  The signal will be delivered once the
 *   signal is removed from the sigprocmask.
 *
 * Input Parameters:
 *   pid   - The PID to be notified.  If a zero value is provided, then the
 *           PID of the calling thread will be used.
 *   signo - The signal number to use with the notification.
 *   dev   - The network driver to be monitored
 *
 * Returned Value:
 *   > 0   - The signal notification is in place.  The returned value is a
 *           key that may be used later in a call to
 *           netdown_notifier_teardown().
 *   == 0  - The the device is already down.  No signal notification will
 *           be provided.
 *   < 0   - An unexpected error occurred and no signal will be sent.  The
 *           returned value is a negated errno value that indicates the
 *           nature of the failure.
 *
 ****************************************************************************/

int netdown_notifier_setup(int pid, int signo, FAR struct net_driver_s *dev)
{
  /* If network driver is already down, then return zero without setting up
   * the notification.
   */

  if ((dev->d_flags & IFF_UP) == 0)
    {
      return 0;
    }

  /* Otherwise, this is just a simple wrapper around nxsig_notifer_setup(). */

  return nxsig_notifier_setup(pid, signo, NXSIG_NET_DOWN, dev);
}

/****************************************************************************
 * Name: netdown_notifier_teardown
 *
 * Description:
 *   Eliminate a TCP read-ahead notification previously setup by
 *   netdown_notifier_setup().  This function should only be called if the
 *   notification should be aborted prior to the notification.  The
 *   notification will automatically be torn down after the signal is sent.
 *
 * Input Parameters:
 *   key - The key value returned from a previous call to
 *         netdown_notifier_setup().
 *
 * Returned Value:
 *   Zero (OK) is returned on success; a negated errno value is returned on
 *   any failure.
 *
 ****************************************************************************/

int netdown_notifier_teardown(int key)
{
  /* This is just a simple wrapper around nxsig_notifier_teardown(). */

  return nxsig_notifier_teardown(key);
}

/****************************************************************************
 * Name: netdown_notifier_signal
 *
 * Description:
 *   Read-ahead data has been buffered.  Signal all threads waiting for
 *   read-ahead data to become available.
 *
 *   When the read-ahead data becomes available, *all* of the waiters in
 *   this thread will be signaled.  If there are multiple waiters then only
 *   the highest priority thread will get the data.  Lower priority threads
 *   will need to call netdown_notifier_setup() once again.
 *
 * Input Parameters:
 *   dev  - The TCP connection where read-ahead data was just buffered.
 *
 * Returned Value:
 *   None.
 *
 ****************************************************************************/

void netdown_notifier_signal(FAR struct net_driver_s *dev)
{
  /* This is just a simple wrapper around nxsig_notifier_signal(). */

  return nxsig_notifier_signal(NXSIG_NET_DOWN, dev);
}

#endif /* CONFIG_NETDOWN_NOTIFIER */
