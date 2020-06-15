/****************************************************************************
 * drivers/syslog/tracer_driver.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <sched.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>

#include <nuttx/sched.h>
#include <nuttx/sched_note.h>
#include <nuttx/sched_tracer.h>
#include <nuttx/clock.h>

#include <nuttx/fs/fs.h>

#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#if defined(CONFIG_SCHED_INSTRUMENTATION_TRACER) && \
    defined(CONFIG_DRIVER_TRACER)

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int tracer_open(FAR struct file *filep);
static ssize_t tracer_read(FAR struct file *filep, FAR char *buffer,
                 size_t buflen);
static ssize_t tracer_write(FAR struct file *filep, FAR const char *buffer,
                 size_t buflen);
static int tracer_ioctl(struct file *filep, int cmd, unsigned long arg);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const struct file_operations tracer_fops =
{
  tracer_open,   /* open */
  0,             /* close */
  tracer_read,   /* read */
  tracer_write,  /* write */
  0,             /* seek */
  tracer_ioctl   /* ioctl */
#ifndef CONFIG_DISABLE_POLL
  , 0            /* poll */
#endif
#ifndef CONFIG_DISABLE_PSEUDOFS_OPERATIONS
  , 0            /* unlink */
#endif
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: tracer_open
 ****************************************************************************/

static int tracer_open(FAR struct file *filep)
{
  if ((filep->f_oflags & O_ACCMODE) != O_WRONLY)
    {
      /* Stop tracing and reset the pointer to read the trace data */

      sched_tracer_stop();
    }

  return OK;
}

/****************************************************************************
 * Name: tracer_read
 ****************************************************************************/

static ssize_t tracer_read(FAR struct file *filep, FAR char *buffer,
                           size_t buflen)
{
  ssize_t len;
  ssize_t retlen;
  bool first = true;

  DEBUGASSERT(filep != 0 && buffer != NULL && buflen > 0);

  /* Adding as many trace events as possible to the user buffer. */

  retlen = 0;
  sched_lock();

  while (true)
    {
      /* Get the next trace event (removing it from the buffer) */

      len = sched_tracer_get((FAR uint8_t *)buffer, buflen, first);
      if (len <= 0)
        {
          /* We were unable to read the next trace event probably because
           * it will not fit into the user buffer.
           */

          if (len < 0 && retlen == 0)
            {
              /* If nothing was read then report the error.  Otherwise,
               * just silently drop the trace event.
               */

             retlen = len;
            }

          break;
        }

      /* Subsequent sched_tracer_get() retains the trace event data bigger
       * than the provided user buffer. Because the data will be read by
       * the next read() call.
       */

      first = false;

      /* Update pointers from the trace event that was transferred */

      retlen += len;
      buffer += len;
      buflen -= len;
    }

  sched_unlock();
  return retlen;
}

/****************************************************************************
 * Name: tracer_write
 ****************************************************************************/

static ssize_t tracer_write(FAR struct file *filep, FAR const char *buffer,
                 size_t buflen)
{
  char msg[UCHAR_MAX];
  char *msgp = msg;
  size_t msglen = 0;
  const char *bufp;
  size_t len;

  for (bufp = buffer, len = buflen; len > 0; bufp++, len--)
    {
      if (*bufp != '\n')
        {
          /* Copy the given message strings into the buffer */

          if (msglen < sizeof msg - 1)
            {
              *msgp = *bufp;
              msgp++;
              msglen++;
            }
        }
      else
        {
          /* Record the buffer as the user message trace events */

          *msgp = '\0';
          sched_tracer_message("%s", msg);
          msgp = msg;
          msglen = 0;
        }
    }

  return buflen;
}

/****************************************************************************
 * Name: tracer_ioctl
 ****************************************************************************/

static int tracer_ioctl(struct file *filep, int cmd, unsigned long arg)
{
  int ret = -ENOSYS;

  /* Handle the ioctl commands */

  switch (cmd)
    {
      /* TRIOC_START
       *      - Start task tracing
       *        Argument: Ignored
       */

      case TRIOC_START:
        {
          sched_tracer_start();
          ret = OK;
        }
        break;

      /* TRIOC_STOP
       *      - Stop task tracing
       *        Argument: Ignored
       */

      case TRIOC_STOP:
        {
          sched_tracer_stop();
          ret = OK;
        }
        break;

      /* TRIOC_GETMODE
       *      - Get task trace mode
       *        Argument: A writable pointer to struct tracer_mode_s
       */

      case TRIOC_GETMODE:
        {
          struct tracer_mode_s *mode = (struct tracer_mode_s *)arg;

          if (mode == NULL)
            {
              ret = -EINVAL;
            }
          else
            {
              *mode = *sched_tracer_mode(NULL);
              ret = OK;
            }
        }
        break;

      /* TRIOC_SETMODE
       *      - Set task trace mode
       *        Argument: A read-only pointer to struct tracer_mode_s
       */

      case TRIOC_SETMODE:
        {
          struct tracer_mode_s *mode = (struct tracer_mode_s *)arg;

          if (mode == NULL)
            {
              ret = -EINVAL;
            }
          else
            {
              sched_tracer_mode(mode);
              ret = OK;
            }
        }
        break;

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
      /* TRIOC_GETSYSCALLFILTER
       *      - Get syscall trace filter setting
       *        Argument: A writable pointer to struct tracer_syscallfilter_s
       *                  If 0, no data is written.
       *        Result:   The required size of struct tracer_syscallfilter_s
       *                  to get current setting.
       */

      case TRIOC_GETSYSCALLFILTER:
        {
          struct tracer_syscallfilter_s *filter;

          filter = (struct tracer_syscallfilter_s *)arg;
          ret = sched_tracer_syscallfilter(filter, NULL);
        }
        break;

      /* TRIOC_SETSYSCALLFILTER
       *      - Set syscall trace filter setting
       *        Argument: A read-only pointer to
       *                  struct tracer_syscallfilter_s
       */

      case TRIOC_SETSYSCALLFILTER:
        {
          struct tracer_syscallfilter_s *filter;

          filter = (struct tracer_syscallfilter_s *)arg;
          ret = sched_tracer_syscallfilter(NULL, filter);
        }
        break;
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
      /* TRIOC_GETIRQFILTER
       *      - Get IRQ trace filter setting
       *        Argument: A writable pointer to struct tracer_irqfilter_s
       *                  If 0, no data is written.
       *        Result:   The required size of struct tracer_irqfilter_s
       *                  to get current setting.
       */

      case TRIOC_GETIRQFILTER:
        {
          struct tracer_irqfilter_s *filter;

          filter = (struct tracer_irqfilter_s *)arg;
          ret = sched_tracer_irqfilter(filter, NULL);
        }
        break;

      /* TRIOC_SETIRQFILTER
       *      - Set IRQ trace filter setting
       *        Argument: A read-only pointer to struct tracer_irqfilter_s
       */

      case TRIOC_SETIRQFILTER:
        {
          struct tracer_irqfilter_s *filter;

          filter = (struct tracer_irqfilter_s *)arg;
          ret = sched_tracer_irqfilter(NULL, filter);
        }
        break;
#endif

      default:
          break;
    }

  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: tracer_register
 *
 * Description:
 *   Register a character driver at /dev/tracer that can be used by an
 *   application to read trace event data and control the trace behaviors.
 *
 * Input Parameters:
 *   None.
 *
 * Returned Value:
 *   Zero on succress. A negated errno value is returned on a failure.
 *
 ****************************************************************************/

int tracer_register(void)
{
  return register_driver("/dev/tracer", &tracer_fops, 0666, NULL);
}

#endif /* CONFIG_SCHED_INSTRUMENTATION_TRACER && CONFIG_DRIVER_TRACER */
