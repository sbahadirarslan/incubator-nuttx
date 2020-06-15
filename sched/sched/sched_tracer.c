/****************************************************************************
 * sched/sched/sched_tracer.c
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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

/* For system call numbers definition */

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
#ifdef CONFIG_LIB_SYSCALL
#include <syscall.h>
#else
#define CONFIG_LIB_SYSCALL
#include <syscall.h>
#undef CONFIG_LIB_SYSCALL
#endif
#endif

#include <nuttx/irq.h>
#include <nuttx/sched.h>
#include <nuttx/clock.h>
#include <nuttx/spinlock.h>
#include <nuttx/sched_note.h>
#include <nuttx/sched_tracer.h>
#include <nuttx/sched_unaligned.h>

#include "sched/sched.h"

#ifdef CONFIG_SCHED_INSTRUMENTATION_TRACER

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#ifndef CONFIG_SCHED_TRACER_BUFSIZE
#define CONFIG_SCHED_TRACER_BUFSIZE 4096
#endif

#if CONFIG_TASK_NAME_SIZE > 0
#ifndef CONFIG_SCHED_TRACER_TASKNAME_BUFSIZE
#define CONFIG_SCHED_TRACER_TASKNAME_BUFSIZE 128
#endif
#endif

/* Bit mask operation macros */

#define BITMASK_ITEMS(nr) (((nr) + 7) / 8)
#define BITMASK_SET(ar, nr) (ar)[(nr) / 8] |= (1 << ((nr) % 8))
#define BITMASK_CLR(ar, nr) (ar)[(nr) / 8] &= ~(1 << ((nr) % 8))
#define BITMASK_CHECK(ar, nr) ((ar)[(nr) / 8] & (1 << ((nr) % 8)))

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct tracer_filter_s
{
  bool enable;
  struct tracer_mode_s mode;
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  uint8_t irqhandler_mask[BITMASK_ITEMS(NR_IRQS)];
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  uint8_t syscall_mask[BITMASK_ITEMS(SYS_nsyscalls)];
#endif
};

struct tracer_info_s
{
  int read_first_cpu;
  volatile unsigned int head;
  volatile unsigned int tail;
  volatile unsigned int read;
  time_t head_time;
  time_t tail_time;
  time_t read_time;
  uint8_t buffer[CONFIG_SCHED_TRACER_BUFSIZE];
};

#if CONFIG_TASK_NAME_SIZE > 0
struct tracer_taskname_s
{
  pid_t pid;
  uint16_t offset;
};

struct tracer_taskname_info_s
{
  uint16_t buffer_used;
  uint16_t n_tasks;
  union
    {
      struct tracer_taskname_s task[0];
      char buffer[CONFIG_SCHED_TRACER_TASKNAME_BUFSIZE];
    }
    b;
};
#endif

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static size_t tracer_unpack_first(FAR union tracer_packed_union_u *p,
                                  FAR union tracer_union_u *u);
static size_t tracer_unpack_message(FAR union tracer_packed_union_u *p,
                                    FAR union tracer_union_u *u);
static size_t tracer_unpack_start(FAR union tracer_packed_union_u *p,
                                  FAR union tracer_union_u *u);
static size_t tracer_unpack_stop(FAR union tracer_packed_union_u *p,
                                 FAR union tracer_union_u *u);
static size_t tracer_unpack_suspend(FAR union tracer_packed_union_u *p,
                                    FAR union tracer_union_u *u);
static size_t tracer_unpack_resume(FAR union tracer_packed_union_u *p,
                                   FAR union tracer_union_u *u);
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
static size_t tracer_unpack_syscall_enter(FAR union tracer_packed_union_u *p,
                                          FAR union tracer_union_u *u);
static size_t tracer_unpack_syscall_leave(FAR union tracer_packed_union_u *p,
                                          FAR union tracer_union_u *u);
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
static size_t tracer_unpack_irqhandler_enter(
  FAR union tracer_packed_union_u *p, FAR union tracer_union_u *u);
static size_t tracer_unpack_irqhandler_leave(
  FAR union tracer_packed_union_u *p, FAR union tracer_union_u *u);
#endif

/****************************************************************************
 * Private Data
 ****************************************************************************/

static struct tracer_filter_s g_tracer_filter;
static struct tracer_info_s g_tracer_info;
#if CONFIG_TASK_NAME_SIZE > 0
static struct tracer_taskname_info_s g_taskname_info;
#endif
#ifdef CONFIG_SMP
static volatile spinlock_t g_tracer_lock;
#endif

static size_t (*const g_unpack[])(FAR union tracer_packed_union_u *p,
                                  FAR union tracer_union_u *u) =
{
  [TRACER_FIRST]                  = tracer_unpack_first,
  [TRACER_MESSAGE]                = tracer_unpack_message,
  [TRACER_START]                  = tracer_unpack_start,
  [TRACER_STOP]                   = tracer_unpack_stop,
  [TRACER_SUSPEND]                = tracer_unpack_suspend,
  [TRACER_RESUME]                 = tracer_unpack_resume,
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  [TRACER_SYSCALL_ENTER]          = tracer_unpack_syscall_enter,
  [TRACER_SYSCALL_LEAVE]          = tracer_unpack_syscall_leave,
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  [TRACER_IRQHANDLER_ENTER]       = tracer_unpack_irqhandler_enter,
  [TRACER_IRQHANDLER_LEAVE]       = tracer_unpack_irqhandler_leave,
#endif
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

#if CONFIG_TASK_NAME_SIZE > 0

/****************************************************************************
 * Name: tracer_taskname_init
 *
 * Description:
 *   Initialize the task name buffer
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

static void tracer_taskname_init(void)
{
  g_taskname_info.buffer_used = sizeof g_taskname_info.b.buffer;
  g_taskname_info.n_tasks = 0;
}

/****************************************************************************
 * Name: tracer_taskname_get
 *
 * Description:
 *   Get the task name string of the specified PID in the buffer
 *
 * Input Parameters:
 *   PID - Task ID
 *
 * Returned Value:
 *   Pointer to the task name string
 *   If the corresponding name doesn't exist in the buffer, "<unknown>"
 *   is returned.
 *
 ****************************************************************************/

static char *tracer_taskname_get(pid_t pid)
{
  int i;

  for (i = 0; i < g_taskname_info.n_tasks; i++)
    {
      if (g_taskname_info.b.task[i].pid == pid)
        {
          return &g_taskname_info.b.buffer[g_taskname_info.b.task[i].offset];
        }
    }

  return "<unknown>";
}

/****************************************************************************
 * Name: tracer_taskname_put
 *
 * Description:
 *   Record the task name string of the specified PID into the buffer
 *
 * Input Parameters:
 *   PID  - Task ID
 *   name - Task name string
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

static void tracer_taskname_put(pid_t pid, const char *name)
{
  int i;
  struct tracer_taskname_s *task;
  int new_offset;
  char *buffer;

#ifdef CONFIG_SMP
  irqstate_t flags = up_irq_save();
  spin_lock_wo_note(&g_tracer_lock);
#endif

  for (i = 0; i < g_taskname_info.n_tasks; i++)
    {
      if (g_taskname_info.b.task[i].pid == pid)
        {
          /* The PID already exists in the buffer */

          goto unlock_and_exit;
        }
    }

  /* Adding new PID record and task name string into the buffer */

  /* New PID record will be added from the top of the buffer */

  task = &g_taskname_info.b.task[g_taskname_info.n_tasks];

  /* New task name string will be added from the bottom of the buffer */

  new_offset = g_taskname_info.buffer_used - (strlen(name) + 1);
  buffer = &g_taskname_info.b.buffer[new_offset];

  if ((char *)&task[1] > buffer)
    {
      /* If both data are overlapped, the buffer has been used up and
       * the task name cannot be stored.
       */

      goto unlock_and_exit;
    }

  /* Add new entries and update the indices */

  strcpy(buffer, name);
  g_taskname_info.buffer_used = new_offset;
  task->pid = pid;
  task->offset = new_offset;
  g_taskname_info.n_tasks++;

unlock_and_exit:
#ifdef CONFIG_SMP
  spin_unlock_wo_note(&g_tracer_lock);
  up_irq_restore(flags);
#endif

  return;
}

#endif

/****************************************************************************
 * Name: tracer_next
 *
 * Description:
 *   Return the circular buffer index at offset from the specified index
 *   value, handling wraparound
 *
 * Input Parameters:
 *   ndx    - Old circular buffer index
 *   offset - Offset value to be added to the index
 *
 * Returned Value:
 *   New circular buffer index
 *
 ****************************************************************************/

static inline unsigned int tracer_next(unsigned int ndx, unsigned int offset)
{
  ndx += offset;
  if (ndx >= CONFIG_SCHED_TRACER_BUFSIZE)
    {
      ndx -= CONFIG_SCHED_TRACER_BUFSIZE;
    }

  return ndx;
}

/****************************************************************************
 * Name: tracer_length
 *
 * Description:
 *   Length of data currently in circular buffer.
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   Length of data currently in circular buffer.
 *
 ****************************************************************************/

static unsigned int tracer_length(unsigned int tail)
{
  unsigned int head = g_tracer_info.head;

  if (tail > head)
    {
      head += CONFIG_SCHED_TRACER_BUFSIZE;
    }

  return head - tail;
}

/****************************************************************************
 * Name: tracer_remove
 *
 * Description:
 *   Remove the variable length trace event from the tail of the circular
 *   buffer
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   We are within a critical section.
 *
 ****************************************************************************/

static void tracer_remove(void)
{
  unsigned int tail;
  unsigned int length;
  uint8_t type;

  /* Get the tail index of the circular buffer */

  tail = g_tracer_info.tail;
  DEBUGASSERT(tail < CONFIG_SCHED_TRACER_BUFSIZE);

  /* Get the length of the trace event at the tail index */

  length = g_tracer_info.buffer[tail];
  DEBUGASSERT(length <= tracer_length(tail));

  type = g_tracer_info.buffer[tracer_next(tail, 1)];

  if (type == TRACER_TIMESEC)
    {
      size_t remaining;
      struct tracer_packed_timesec_s timesec;
      uint8_t *p;

      /* If the trace event to be removed is TRACER_TIMESEC, the time stamp
       * of the tail entry needs update.
       */

      p = (uint8_t *)&timesec;
      for (remaining = length; remaining > 0; remaining--)
        {
          *p++ = g_tracer_info.buffer[tail];
          tail = tracer_next(tail, 1);
        }

      g_tracer_info.tail_time = (time_t)get_ua_uintptr(&timesec.systimesec);
    }
  else
    {
      /* Increment the tail index to remove the entire trace entry from the
       * circular buffer.
       */

      tail = tracer_next(tail, length);
    }

  g_tracer_info.tail = tail;
}

/****************************************************************************
 * Name: tracer_add
 *
 * Description:
 *   Add the variable length trace event to the head of the circular buffer
 *
 * Input Parameters:
 *   note    - Pointer to the trace event to be added
 *   notelen - Length of the trace event
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   We are within a critical section.
 *
 ****************************************************************************/

static void tracer_add(FAR const uint8_t *note, uint8_t notelen)
{
  unsigned int head;
  unsigned int next;

#ifdef CONFIG_SMP
  /* Ignore notes that are not in the set of monitored CPUs */

  if ((CONFIG_SCHED_INSTRUMENTATION_CPUSET & (1 << this_cpu())) == 0)
    {
      /* Not in the set of monitored CPUs.  Do not log the note. */

      return;
    }
#endif

#ifdef CONFIG_SMP
  irqstate_t flags = up_irq_save();
  spin_lock_wo_note(&g_tracer_lock);
#endif

  /* Get the index to the head of the circular buffer */

  DEBUGASSERT(note != NULL && notelen < CONFIG_SCHED_TRACER_BUFSIZE);
  head = g_tracer_info.head;

  /* Loop until all bytes have been transferred to the circular buffer */

  while (notelen > 0)
    {
      /* Get the next head index.  Would it collide with the current tail
       * index?
       */

      next = tracer_next(head, 1);
      if (next == g_tracer_info.tail)
        {
          if (g_tracer_filter.mode.flag & TRIOC_MODE_FLAG_ONESHOT)
            {
              /* Just stop tracing if one shot trace mode */

              g_tracer_filter.enable = false;
              return;
            }

          /* Yes, then remove the note at the tail index */

          tracer_remove();
        }

      /* Save the next byte at the head index */

      g_tracer_info.buffer[head] = *note++;

      head = next;
      notelen--;
    }

  g_tracer_info.head = head;

#ifdef CONFIG_SMP
  spin_unlock_wo_note(&g_tracer_lock);
  up_irq_restore(flags);
#endif
}

/****************************************************************************
 * Name: tracer_get_first_pid
 *
 * Description:
 *   Get PID of the first trace event. This is needed to get the trace
 *   context for the beginning of the trace dump.
 *
 * Input Parameters:
 *   cpu - CPU No. of the context
 *
 * Returned Value:
 *   PID of the first trace event
 *
 ****************************************************************************/

static pid_t tracer_get_first_pid(int cpu)
{
  unsigned int tail;
  unsigned int length;
  uint8_t type;

  /* Get the tail index of the circular buffer */

  tail = g_tracer_info.tail;
  DEBUGASSERT(tail < CONFIG_SCHED_TRACER_BUFSIZE);

  while (tracer_length(tail) > 0)
    {
      /* Get the length of the trace event at the tail index */

      length = g_tracer_info.buffer[tail];
      DEBUGASSERT(length <= tracer_length(tail));

      type = g_tracer_info.buffer[tracer_next(tail, 1)];

      if (type == TRACER_STOP || type == TRACER_SUSPEND)
        {
          size_t remaining;
          union tracer_packed_union_u packed;
          uint8_t *p;

          /* TRACE_STOP and TRACE_SUSPEND mean that the task to be stopped or
           * suspended had been running till these trace event. So such task
           * is treated as the context of the beginning of the trace dump.
           */

          p = packed.bytes;
          for (remaining = length; remaining > 0; remaining--)
            {
              *p++ = g_tracer_info.buffer[tail];
              tail = tracer_next(tail, 1);
            }

#ifdef CONFIG_SMP
          if (packed.common.cpu != cpu)
            {
              continue;
            }
#endif

          if (type == TRACER_STOP)
            {
              return get_ua_uint16(&packed.stop.pid);
            }
          else if (type == TRACER_SUSPEND)
            {
              return get_ua_uint16(&packed.suspend.pid);
            }
        }
      else
        {
          /* Increment the tail index to get next trace event */

          tail = tracer_next(tail, length);
        }
    }

  return 0;
}

/****************************************************************************
 * Name: tracer_common
 *
 * Description:
 *   Fill in some of the common fields in the packed trace event structure.
 *
 * Input Parameters:
 *   tracer - The common trace event structure to use
 *   length - The total length of the trace event structure
 *   type   - The type of the trace event
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

static void tracer_common(FAR struct tracer_packed_common_s *tracer,
                          uint8_t length, uint8_t type)
{
  struct timespec ts;

  clock_systime_timespec(&ts);
  put_ua_uint32(&tracer->systimensec, ts.tv_nsec);
  tracer->length = length;
  tracer->type = type;
#ifdef CONFIG_SMP
  tracer->cpu = this_cpu();
#endif

  if (ts.tv_sec != g_tracer_info.head_time)
    {
      struct tracer_packed_timesec_s timesec;

      /* The packed trace event holds only nanosec part of the system time.
       * If sec part is updated, insert an additional event to update
       * the system time.
       */

      g_tracer_info.head_time = ts.tv_sec;
      timesec.length = sizeof timesec;
      timesec.type = TRACER_TIMESEC;
      put_ua_uintptr(&timesec.systimesec, g_tracer_info.head_time);
      tracer_add((FAR const uint8_t *)&timesec, sizeof timesec);
    }
}

/****************************************************************************
 * Name: tracer_unpack_*
 *
 * Description:
 *   These are the functions to unpack the packed trace event structures
 *   for each trace events.
 *
 * Input Parameters:
 *   p      - The packed trace event data
 *   u      - The unpacked output buffer
 *            If NULL, the unpacked data is not written.
 *
 * Returned Value:
 *   Length of the unpacked trace event data
 *
 ****************************************************************************/

static size_t tracer_unpack_first(FAR union tracer_packed_union_u *p,
                                  FAR union tracer_union_u *u)
{
  size_t size;
  pid_t pid;
#if CONFIG_TASK_NAME_SIZE > 0
  char *taskname;
  size_t tasknamelen;
#endif

  pid = get_ua_uint16(&p->first.pid);
  size = sizeof u->first;
#if CONFIG_TASK_NAME_SIZE > 0
  taskname = tracer_taskname_get(pid);
  tasknamelen = strlen(taskname) + 1;
  size += tasknamelen;
#endif

  if (u)
    {
      u->first.pid = pid;
#if CONFIG_TASK_NAME_SIZE > 0
      strncpy(u->first.name, taskname, tasknamelen);
#endif
    }

  return size;
}

static size_t tracer_unpack_message(FAR union tracer_packed_union_u *p,
                                    FAR union tracer_union_u *u)
{
  size_t size;
  size_t msgsize;

  msgsize = p->common.length - sizeof p->message;
  size = sizeof u->message + msgsize;

  if (u)
    {
      memcpy(u->message.message, p->message.message, msgsize);
    }

  return size;
}

static size_t tracer_unpack_start(FAR union tracer_packed_union_u *p,
                                  FAR union tracer_union_u *u)
{
  size_t size;
  pid_t pid;
#if CONFIG_TASK_NAME_SIZE > 0
  char *taskname;
  size_t tasknamelen;
#endif

  pid = get_ua_uint16(&p->start.pid);
  size = sizeof u->start;
#if CONFIG_TASK_NAME_SIZE > 0
  taskname = tracer_taskname_get(pid);
  tasknamelen = strlen(taskname) + 1;
  size += tasknamelen;
#endif

  if (u)
    {
      u->start.pid = pid;
#if CONFIG_TASK_NAME_SIZE > 0
      strncpy(u->start.name, taskname, tasknamelen);
#endif
    }

  return size;
}

static size_t tracer_unpack_stop(FAR union tracer_packed_union_u *p,
                                 FAR union tracer_union_u *u)
{
  size_t size;
  pid_t pid;
#if CONFIG_TASK_NAME_SIZE > 0
  char *taskname;
  size_t tasknamelen;
#endif

  pid = get_ua_uint16(&p->stop.pid);
  size = sizeof u->stop;
#if CONFIG_TASK_NAME_SIZE > 0
  taskname = tracer_taskname_get(pid);
  tasknamelen = strlen(taskname) + 1;
  size += tasknamelen;
#endif

  if (u)
    {
      u->stop.pid = pid;
      u->stop.state = p->stop.state;
#if CONFIG_TASK_NAME_SIZE > 0
      strncpy(u->stop.name, taskname, tasknamelen);
#endif
    }

  return size;
}

static size_t tracer_unpack_suspend(FAR union tracer_packed_union_u *p,
                                    FAR union tracer_union_u *u)
{
  size_t size;
  pid_t pid;
#if CONFIG_TASK_NAME_SIZE > 0
  char *taskname;
  size_t tasknamelen;
#endif

  pid = get_ua_uint16(&p->suspend.pid);
  size = sizeof u->suspend;
#if CONFIG_TASK_NAME_SIZE > 0
  taskname = tracer_taskname_get(pid);
  tasknamelen = strlen(taskname) + 1;
  size += tasknamelen;
#endif

  if (u)
    {
      u->suspend.pid = pid;
      u->suspend.state = p->suspend.state;
#if CONFIG_TASK_NAME_SIZE > 0
      strncpy(u->suspend.name, taskname, tasknamelen);
#endif
    }

  return size;
}

static size_t tracer_unpack_resume(FAR union tracer_packed_union_u *p,
                                   FAR union tracer_union_u *u)
{
  size_t size;
  pid_t pid;
#if CONFIG_TASK_NAME_SIZE > 0
  char *taskname;
  size_t tasknamelen;
#endif

  pid = get_ua_uint16(&p->resume.pid);
  size = sizeof u->resume;
#if CONFIG_TASK_NAME_SIZE > 0
  taskname = tracer_taskname_get(pid);
  tasknamelen = strlen(taskname) + 1;
  size += tasknamelen;
#endif

  if (u)
    {
      u->resume.pid = pid;
#if CONFIG_TASK_NAME_SIZE > 0
      strncpy(u->resume.name, taskname, tasknamelen);
#endif
    }

  return size;
}

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
static size_t tracer_unpack_syscall_enter(FAR union tracer_packed_union_u *p,
                                          FAR union tracer_union_u *u)
{
  size_t size;
  int i;

  size = sizeof u->syscall_enter +
         (sizeof(uintptr_t) * p->syscall_enter.argc);

  if (u)
    {
      u->syscall_enter.nr = p->syscall_enter.nr;
      u->syscall_enter.argc = p->syscall_enter.argc;
      for (i = 0; i < p->syscall_enter.argc; i++)
        {
          u->syscall_enter.argv[i] =
            get_ua_uintptr(&p->syscall_enter.argv[i]);
        }
    }

  return size;
}

static size_t tracer_unpack_syscall_leave(FAR union tracer_packed_union_u *p,
                                          FAR union tracer_union_u *u)
{
  size_t size;

  size = sizeof u->syscall_leave;

  if (u)
    {
      u->syscall_leave.nr = p->syscall_leave.nr;
      u->syscall_leave.result = get_ua_uintptr(&p->syscall_leave.result);
    }

  return size;
}
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
static size_t tracer_unpack_irqhandler_enter(
  FAR union tracer_packed_union_u *p, FAR union tracer_union_u *u)
{
  size_t size;

  size = sizeof u->irqhandler_enter;

  if (u)
    {
      u->irqhandler_enter.irq = p->irqhandler_enter.irq;
      u->irqhandler_enter.handler =
        (void *)get_ua_uintptr(&p->irqhandler_enter.handler);
    }

  return size;
}

static size_t tracer_unpack_irqhandler_leave(
  FAR union tracer_packed_union_u *p, FAR union tracer_union_u *u)
{
  size_t size;

  size = sizeof u->irqhandler_leave;

  if (u)
    {
      u->irqhandler_leave.irq = p->irqhandler_leave.irq;
    }

  return size;
}
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: sched_note_*
 *
 * Description:
 *   These are the hooks into the scheduling instrumentation logic.  Each
 *   simply formats the note associated with the schedule event and adds
 *   that note to the circular buffer.
 *
 * Input Parameters:
 *   tcb - The TCB of the thread.
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   We are within a critical section.
 *
 ****************************************************************************/

void sched_note_start(FAR struct tcb_s *tcb)
{
  struct tracer_packed_start_s tracer;

  if (!g_tracer_filter.enable)
    {
      return;
    }

#if CONFIG_TASK_NAME_SIZE > 0
  tracer_taskname_put(tcb->pid, tcb->name);
#endif
  put_ua_uint16(&tracer.pid, tcb->pid);

  tracer_common(&tracer.common, sizeof tracer, TRACER_START);
  tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);
}

void sched_note_stop(FAR struct tcb_s *tcb)
{
  struct tracer_packed_stop_s tracer;

  if (!g_tracer_filter.enable)
    {
      return;
    }

#if CONFIG_TASK_NAME_SIZE > 0
  tracer_taskname_put(tcb->pid, tcb->name);
#endif
  put_ua_uint16(&tracer.pid, tcb->pid);
  tracer.state = tcb->task_state;

  tracer_common(&tracer.common, sizeof tracer, TRACER_STOP);
  tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);
}

void sched_note_suspend(FAR struct tcb_s *tcb)
{
  struct tracer_packed_suspend_s tracer;

  if (!g_tracer_filter.enable)
    {
      return;
    }

#if CONFIG_TASK_NAME_SIZE > 0
  tracer_taskname_put(tcb->pid, tcb->name);
#endif
  put_ua_uint16(&tracer.pid, tcb->pid);
  tracer.state = tcb->task_state;

  tracer_common(&tracer.common, sizeof tracer, TRACER_SUSPEND);
  tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);
}

void sched_note_resume(FAR struct tcb_s *tcb)
{
  struct tracer_packed_resume_s tracer;

  if (!g_tracer_filter.enable)
    {
      return;
    }

#if CONFIG_TASK_NAME_SIZE > 0
  tracer_taskname_put(tcb->pid, tcb->name);
#endif
  put_ua_uint16(&tracer.pid, tcb->pid);

  tracer_common(&tracer.common, sizeof tracer, TRACER_RESUME);
  tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);
}

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
void sched_note_syscall_enter(int nr, int argc, ...)
{
  irqstate_t irq_mask;
#ifdef CONFIG_BUILD_FLAT
  FAR struct tcb_s *tcb = this_task();
#endif
  struct tracer_packed_syscall_enter_s tracer;
  size_t size;
  va_list ap;
  uintptr_t parm;
  int i;
  unsigned int head;

  irq_mask = enter_critical_section();

#ifdef CONFIG_BUILD_FLAT

  /* In the case of BUILD_FLAT model, syscall is just a function call
   * and the hook will be called from not only applications, but interrupt
   * handlers and many kernel APIs. Exclude such situations.
   */

  if (up_interrupt_context())
    {
      leave_critical_section(irq_mask);
      return;
    }

  tcb->syscall_nest++;
  if (tcb->syscall_nest > 1)
    {
      leave_critical_section(irq_mask);
      return;
    }

#endif

  if (!g_tracer_filter.enable)
    {
      leave_critical_section(irq_mask);
      return;
    }

  nr -= CONFIG_SYS_RESERVED;

  /* If the syscall trace is disabled or the syscall number is masked,
   * do nothing.
   */

  if (g_tracer_filter.mode.flag & TRIOC_MODE_FLAG_SYSCALL)
    {
      if (BITMASK_CHECK(g_tracer_filter.syscall_mask, nr))
        {
          leave_critical_section(irq_mask);
          return;
        }
    }
  else
    {
      leave_critical_section(irq_mask);
      return;
    }

  if (!(g_tracer_filter.mode.flag & TRIOC_MODE_FLAG_SYSCALL_ARGS))
    {
      argc = 0;
    }

  tracer.nr = nr;
  tracer.argc = argc;
  size = sizeof tracer + sizeof(uintptr_t) * argc;

  head = g_tracer_info.head;
  tracer_common(&tracer.common, size, TRACER_SYSCALL_ENTER);
  tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);

  /* If needed, retrieve the given syscall arguments and save them into
   * the packed trace event.
   */

  va_start(ap, argc);

  for (i = 0; i < argc; i++)
    {
      parm = (uintptr_t)va_arg(ap, uintptr_t);
      tracer_add((FAR const uint8_t *)&parm, sizeof parm);
    }

  va_end(ap);

  if (!g_tracer_filter.enable)
    {
      /* If the trace buffer had been used up while adding the data and
       * the trace becomes disabled (in the case of one shot mode), restore
       * the head index to the position before adding the event.
       */

      g_tracer_info.head = head;
    }

  leave_critical_section(irq_mask);
}

void sched_note_syscall_leave(int nr, uintptr_t result)
{
  irqstate_t irq_mask;
#ifdef CONFIG_BUILD_FLAT
  FAR struct tcb_s *tcb = this_task();
#endif
  struct tracer_packed_syscall_leave_s tracer;

  irq_mask = enter_critical_section();

#ifdef CONFIG_BUILD_FLAT

  /* In the case of BUILD_FLAT model, syscall is just a function call
   * and the hook will be called from not only applications, but interrupt
   * handlers and many kernel APIs. Exclude such situations.
   */

  if (up_interrupt_context())
    {
      leave_critical_section(irq_mask);
      return;
    }

  tcb->syscall_nest--;
  if (tcb->syscall_nest > 0)
    {
      leave_critical_section(irq_mask);
      return;
    }
  else
    {
      tcb->syscall_nest = 0;
    }

#endif

  if (!g_tracer_filter.enable)
    {
      leave_critical_section(irq_mask);
      return;
    }

  nr -= CONFIG_SYS_RESERVED;

  /* If the syscall trace is disabled or the syscall number is masked,
   * do nothing.
   */

  if (g_tracer_filter.mode.flag & TRIOC_MODE_FLAG_SYSCALL)
    {
      if (BITMASK_CHECK(g_tracer_filter.syscall_mask, nr))
        {
          leave_critical_section(irq_mask);
          return;
        }
    }
  else
    {
      leave_critical_section(irq_mask);
      return;
    }

  tracer.nr = nr;
  put_ua_uintptr(&tracer.result, result);

  tracer_common(&tracer.common, sizeof tracer, TRACER_SYSCALL_LEAVE);
  tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);
  leave_critical_section(irq_mask);
}
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
void sched_note_irqhandler(int irq, FAR void *handler, bool enter)
{
  if (!g_tracer_filter.enable)
    {
      return;
    }

  /* If the IRQ trace is disabled or the IRQ number is masked,
   * do nothing.
   */

  if (g_tracer_filter.mode.flag & TRIOC_MODE_FLAG_IRQ)
    {
      if (BITMASK_CHECK(g_tracer_filter.irqhandler_mask, irq))
        {
          return;
        }
    }
  else
    {
      return;
    }

  if (enter)
    {
      struct tracer_packed_irqhandler_enter_s tracer;

      tracer.irq = irq;
      put_ua_uintptr(&tracer.handler, (uintptr_t)handler);
      tracer_common(&tracer.common, sizeof tracer, TRACER_IRQHANDLER_ENTER);
      tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);
    }
  else
    {
      struct tracer_packed_irqhandler_leave_s tracer;

      tracer.irq = irq;
      tracer_common(&tracer.common, sizeof tracer, TRACER_IRQHANDLER_LEAVE);
      tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);
    }
}
#endif

#ifdef CONFIG_SMP
void sched_note_cpu_start(FAR struct tcb_s *tcb, int cpu)
{
  /* TBD */
}

void sched_note_cpu_started(FAR struct tcb_s *tcb)
{
  /* TBD */
}

void sched_note_cpu_pause(FAR struct tcb_s *tcb, int cpu)
{
  /* TBD */
}

void sched_note_cpu_paused(FAR struct tcb_s *tcb)
{
  /* TBD */
}

void sched_note_cpu_resume(FAR struct tcb_s *tcb, int cpu)
{
  /* TBD */
}

void sched_note_cpu_resumed(FAR struct tcb_s *tcb)
{
  /* TBD */
}
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_PREEMPTION
void sched_note_premption(FAR struct tcb_s *tcb, bool locked)
{
  /* TBD */
}
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_CSECTION
void sched_note_csection(FAR struct tcb_s *tcb, bool enter)
{
  /* TBD */
}
#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_SPINLOCKS
void sched_note_spinlock(FAR struct tcb_s *tcb, FAR volatile void *spinlock)
{
  /* TBD */
}

void sched_note_spinlocked(FAR struct tcb_s *tcb,
                           FAR volatile void *spinlock)
{
  /* TBD */
}

void sched_note_spinunlock(FAR struct tcb_s *tcb,
                           FAR volatile void *spinlock)
{
  /* TBD */
}

void sched_note_spinabort(FAR struct tcb_s *tcb, FAR volatile void *spinlock)
{
  /* TBD */
}
#endif

/****************************************************************************
 * Name: sched_tracer_get
 *
 * Description:
 *   Get the next trace event from the tail of the circular buffer.
 *
 * Input Parameters:
 *   buffer    - Location to return the next trace event
 *   buflen    - The length of the user provided buffer
 *   removebig - Flag whether the trace event bigger than the provided buffer
 *               size is removed
 *
 * Returned Value:
 *   On success, the positive, non-zero length of the return trace event is
 *   provided.  Zero is returned only if ther circular buffer is empty.  A
 *   negated errno value is returned in the event of any failure.
 *
 ****************************************************************************/

ssize_t sched_tracer_get(FAR uint8_t *buffer, size_t buflen, bool removebig)
{
  irqstate_t flags;
  unsigned int tail;
  size_t circlen;
  size_t remaining;
  ssize_t tracelen;
  union tracer_packed_union_u packed;
  uint8_t *p;

  DEBUGASSERT(buffer != NULL);
  flags = enter_critical_section();

  if (g_tracer_filter.enable)
    {
      /* Stop the tracing if enabled */

      sched_tracer_stop();
    }

retry:

  tail = g_tracer_info.read;
  DEBUGASSERT(tail < CONFIG_SCHED_TRACER_BUFSIZE);

  /* Verify that the circular buffer is not empty */

  circlen = tracer_length(tail);
  if (circlen <= 0)
    {
      tracelen = 0;
      goto errout_with_csection;
    }

  if (g_tracer_info.read_first_cpu >= 0)
    {
      pid_t pid;

      /* At the first time, return TRACER_FIRST trace event to inform the
       * trace context of the beginning of the trace data
       */

      pid = tracer_get_first_pid(g_tracer_info.read_first_cpu);
      put_ua_uint16(&packed.first.pid, pid);
      put_ua_uint32(&packed.first.common.systimensec, 0);
      packed.first.common.length = sizeof packed.first;
      packed.first.common.type = TRACER_FIRST;
#ifdef CONFIG_SMP
      packed.first.common.cpu = g_tracer_info.read_first_cpu;

      g_tracer_info.read_first_cpu++;
      if (g_tracer_info.read_first_cpu >= CONFIG_SMP_NCPUS)
        {
          g_tracer_info.read_first_cpu = -1;
        }
#else
      g_tracer_info.read_first_cpu = -1;
#endif
    }
  else
    {
      /* Get the index to the tail of the circular buffer */

      remaining = (size_t)g_tracer_info.buffer[tail];
      DEBUGASSERT(remaining <= circlen);

      /* Loop until the trace event has been transferred to the internal buffer */

      for (p = packed.bytes; remaining > 0; remaining--)
        {
          /* Copy the next byte at the tail index */

          *p++ = g_tracer_info.buffer[tail];

          /* Adjust indices and counts */

          tail = tracer_next(tail, 1);
        }
    }

  /* TRACER_TIMESEC trace event updates the sec part of the system time.
   * It is used only for unpacking process and not passed to the user buffer.
   */

  if (packed.common.type == TRACER_TIMESEC)
    {
      g_tracer_info.read_time =
        (time_t)get_ua_uintptr(&packed.timesec.systimesec);
      g_tracer_info.read = tail;
      goto retry;
    }

  /* Unpack the packed trace event and write it into the user buffer */

  if (packed.common.type < TRACER_NUM_TRACE_TYPES
      && g_unpack[packed.common.type] != NULL)
    {
      const size_t align = sizeof(uintptr_t);

      tracelen = g_unpack[packed.common.type](&packed, NULL);
      tracelen = (tracelen + align - 1) & ~(align - 1);

      if (buflen >= tracelen && tracelen < UCHAR_MAX)
        {
          union tracer_union_u *unpacked;

          unpacked = (FAR union tracer_union_u *)buffer;
          memset(buffer, 0, tracelen);
          unpacked->common.length = tracelen;
          unpacked->common.type = packed.common.type;
#ifdef CONFIG_SMP
          unpacked->common.cpu = packed.common.cpu;
#endif
          unpacked->common.systime.tv_sec = g_tracer_info.read_time;
          unpacked->common.systime.tv_nsec =
            get_ua_uint32(&packed.common.systimensec);
          g_unpack[packed.common.type](&packed, unpacked);
          g_tracer_info.read = tail;
        }
      else
        {
          /* The provided user buffer is too small to hold the trace event */

          tracelen = -EFBIG;
          if (removebig)
            {
              /* Ignore the large event */

              g_tracer_info.read = tail;
            }
        }
    }
  else
    {
      tracelen = -EINVAL;
      g_tracer_info.read = tail;
    }

errout_with_csection:
  leave_critical_section(flags);
  return tracelen;
}

/****************************************************************************
 * Name: sched_tracer_message
 *
 * Description:
 *   Record the user provided message as the trace event.
 *
 * Input Parameters:
 *   fmt - printf() style format string
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void sched_tracer_message(FAR const char *fmt, ...)
{
  irqstate_t irq_mask;
  struct tracer_packed_message_s tracer;
  va_list ap;
  size_t size;
  unsigned int head;
  char message[UCHAR_MAX - sizeof tracer];

  irq_mask = enter_critical_section();

  if (!g_tracer_filter.enable)
    {
      leave_critical_section(irq_mask);
      return;
    }

  va_start(ap, fmt);
  vsnprintf(message, sizeof message, fmt, ap);
  va_end(ap);
  size = sizeof tracer + strlen(message) + 1;

  head = g_tracer_info.head;
  tracer_common(&tracer.common, size, TRACER_MESSAGE);
  tracer_add((FAR const uint8_t *)&tracer, sizeof tracer);
  tracer_add((FAR const uint8_t *)message, strlen(message) + 1);
  if (!g_tracer_filter.enable)
    {
      /* If the trace buffer had been used up while adding the data and
       * the trace becomes disabled (in the case of one shot mode), restore
       * the head index to the position before adding the event.
       */

      g_tracer_info.head = head;
    }

  leave_critical_section(irq_mask);
}

/****************************************************************************
 * Name: sched_tracer_mode
 *
 * Description:
 *   Set and get task trace mode.
 *   (Same as TRIOC_GETMODE / TRIOC_SETMODE ioctls)
 *
 * Input Parameters:
 *   mewm - A read-only pointer to struct tracer_mode_s which holds the
 *          new trace mode
 *          If 0, the trace mode is not updated.
 *
 * Returned Value:
 *   A pointer to struct tracer_mode_s of the current trace mode
 *
 ****************************************************************************/

struct tracer_mode_s *sched_tracer_mode(struct tracer_mode_s *newm)
{
  irqstate_t irq_mask;

  irq_mask = enter_critical_section();

  if (newm != NULL)
    {
      sched_tracer_stop();
      g_tracer_filter.mode = *newm;
    }

  leave_critical_section(irq_mask);
  return &g_tracer_filter.mode;
}

/****************************************************************************
 * Name: sched_tracer_syscallfilter
 *
 * Description:
 *   Set and get syscall trace filter setting
 *   (Same as TRIOC_GETSYSCALLFILTER / TRIOC_SETSYSCALLFILTER ioctls)
 *
 * Input Parameters:
 *   oldf - A writable pointer to struct tracer_syscallfilter_s to get
 *          current syscall trace filter setting
 *          If 0, no data is written.
 *   newf - A read-only pointer to struct tracer_syscallfilter_s of the
 *          new syscall trace filter setting
 *          If 0, the setting is not updated.
 *
 * Returned Value:
 *   The required size of struct tracer_syscallfilter_s to get current
 *   setting
 *
 ****************************************************************************/

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
ssize_t sched_tracer_syscallfilter(struct tracer_syscallfilter_s *oldf,
                                   struct tracer_syscallfilter_s *newf)
{
  irqstate_t irq_mask;
  ssize_t ret;
  int i;
  int nr;

  irq_mask = enter_critical_section();

  if (newf != NULL)
    {
      sched_tracer_stop();

      /* Replace the syscall filter mask by the provided setting */

      memset(g_tracer_filter.syscall_mask, 0,
             sizeof g_tracer_filter.syscall_mask);
      for (i = 0; i < newf->nr_syscalls; i++)
        {
          nr = newf->syscall[i];

          if (nr < SYS_nsyscalls)
            {
              BITMASK_SET(g_tracer_filter.syscall_mask, nr);
            }
        }
    }

  /* Count the number of filtered syscalls to calculate the requied size to
   * get the current setting.
   */

  nr = 0;
  for (i = 0; i < SYS_nsyscalls; i++)
    {
      if (BITMASK_CHECK(g_tracer_filter.syscall_mask, i))
        {
          nr++;
        }
    }

  ret = sizeof(struct tracer_syscallfilter_s) + sizeof(int) * nr;

  if (oldf != NULL)
    {
      /* Return the current filter setting */

      int *p = oldf->syscall;
      oldf->nr_syscalls = nr;
      for (i = 0; i < SYS_nsyscalls; i++)
        {
          if (BITMASK_CHECK(g_tracer_filter.syscall_mask, i))
            {
              *p++ = i;
            }
        }
    }

  leave_critical_section(irq_mask);
  return ret;
}
#endif

/****************************************************************************
 * Name: sched_tracer_irqfilter
 *
 * Description:
 *   Set and get IRQ trace filter setting
 *   (Same as TRIOC_GETIRQFILTER / TRIOC_SETIRQFILTER ioctls)
 *
 * Input Parameters:
 *   oldf - A writable pointer to struct tracer_irqfilter_s to get current
 *          IRQ trace filter setting
 *          If 0, no data is written.
 *   newf - A read-only pointer to struct tracer_irqfilter_s of the new IRQ
 *          trace filter setting
 *          If 0, the setting is not updated.
 *
 * Returned Value:
 *   The required size of struct tracer_irqfilter_s to get current setting
 *
 ****************************************************************************/

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
ssize_t sched_tracer_irqfilter(struct tracer_irqfilter_s *oldf,
                               struct tracer_irqfilter_s *newf)
{
  irqstate_t irq_mask;
  ssize_t ret;
  int i;
  int nr;

  irq_mask = enter_critical_section();

  if (newf != NULL)
    {
      sched_tracer_stop();

      /* Replace the IRQ filter mask by the provided setting */

      memset(g_tracer_filter.irqhandler_mask, 0,
             sizeof g_tracer_filter.irqhandler_mask);
      for (i = 0; i < newf->nr_irqs; i++)
        {
          nr = newf->irq[i];

          if (nr < NR_IRQS)
            {
              BITMASK_SET(g_tracer_filter.irqhandler_mask, nr);
            }
        }
    }

  /* Count the number of filtered IRQs to calculate the requied size to get
   * the current setting.
   */

  nr = 0;
  for (i = 0; i < NR_IRQS; i++)
    {
      if (BITMASK_CHECK(g_tracer_filter.irqhandler_mask, i))
        {
          nr++;
        }
    }

  ret = sizeof(struct tracer_irqfilter_s) + sizeof(int) * nr;

  if (oldf != NULL)
    {
      /* Return the current filter setting */

      int *p = oldf->irq;
      oldf->nr_irqs = nr;
      for (i = 0; i < NR_IRQS; i++)
        {
          if (BITMASK_CHECK(g_tracer_filter.irqhandler_mask, i))
            {
              *p++ = i;
            }
        }
    }

  leave_critical_section(irq_mask);
  return ret;
}
#endif

/****************************************************************************
 * Name: sched_tracer_start
 *
 * Description:
 *   Start task tracing
 *   (Same as TRIOC_START ioctl)
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void sched_tracer_start(void)
{
  irqstate_t irq_mask;
  struct timespec ts;

  irq_mask = enter_critical_section();
  g_tracer_filter.enable = true;
#if CONFIG_TASK_NAME_SIZE > 0
  tracer_taskname_init();
#endif
  clock_systime_timespec(&ts);
  g_tracer_info.head_time = ts.tv_sec;
  g_tracer_info.tail_time = ts.tv_sec;
  g_tracer_info.head = 0;
  g_tracer_info.tail = 0;
  leave_critical_section(irq_mask);
}

/****************************************************************************
 * Name: sched_tracer_stop
 *
 * Description:
 *   Stop task tracing
 *   (Same as TRIOC_STOP ioctl)
 *
 * Input Parameters:
 *   None
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void sched_tracer_stop(void)
{
  irqstate_t irq_mask;

  irq_mask = enter_critical_section();
  g_tracer_filter.enable = false;
  g_tracer_info.read = g_tracer_info.tail;
  g_tracer_info.read_time = g_tracer_info.tail_time;
  g_tracer_info.read_first_cpu = 0;
  leave_critical_section(irq_mask);
}

#endif /* CONFIG_SCHED_INSTRUMENTATION_TRACER */
