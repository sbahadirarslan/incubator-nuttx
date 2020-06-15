/****************************************************************************
 * include/nuttx/sched_tracer.h
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

#ifndef __INCLUDE_NUTTX_SCHED_TRACER_H
#define __INCLUDE_NUTTX_SCHED_TRACER_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <time.h>

#include <nuttx/clock.h>
#include <nuttx/sched.h>
#include <nuttx/sched_note.h>
#include <nuttx/sched_unaligned.h>
#include <nuttx/fs/ioctl.h>

#ifdef CONFIG_SCHED_INSTRUMENTATION_TRACER

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* IOCTL Commands ***********************************************************/

/* TRIOC_START
 *              - Start task tracing
 *                Argument: Ignored
 * TRIOC_STOP
 *              - Stop task tracing
 *                Argument: Ignored
 * TRIOC_GETMODE
 *              - Get task trace mode
 *                Argument: A writable pointer to struct tracer_mode_s
 * TRIOC_SETMODE
 *              - Set task trace mode
 *                Argument: A read-only pointer to struct tracer_mode_s
 * TRIOC_GETSYSCALLFILTER
 *              - Get syscall trace filter setting
 *                Argument: A writable pointer to struct
 *                          tracer_syscallfilter_s
 *                          If 0, no data is written.
 *                Result:   The required size of struct
 *                          tracer_syscallfilter_s to get current setting.
 * TRIOC_SETSYSCALLFILTER
 *              - Set syscall trace filter setting
 *                Argument: A read-only pointer to struct
 *                          tracer_syscallfilter_s
 * TRIOC_GETIRQFILTER
 *              - Get IRQ trace filter setting
 *                Argument: A writable pointer to struct tracer_irqfilter_s
 *                          If 0, no data is written.
 *                Result:   The required size of struct tracer_irqfilter_s
 *                          to get current setting.
 * TRIOC_SETIRQFILTER
 *              - Set IRQ trace filter setting
 *                Argument: A read-only pointer to struct tracer_irqfilter_s
 */

#ifdef CONFIG_DRIVER_TRACER

#define _TRACERBASE        (0xfe00) /* tracer commands */
#define _TRACERIOCVALID(c) (_IOC_TYPE(c) == _TRACERBASE)
#define _TRACERIOC(nr)     _IOC(_TRACERBASE, nr)

#define TRIOC_START            _TRACERIOC(0x01)
#define TRIOC_STOP             _TRACERIOC(0x02)
#define TRIOC_GETMODE          _TRACERIOC(0x03)
#define TRIOC_SETMODE          _TRACERIOC(0x04)
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
#define TRIOC_GETSYSCALLFILTER _TRACERIOC(0x05)
#define TRIOC_SETSYSCALLFILTER _TRACERIOC(0x06)
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
#define TRIOC_GETIRQFILTER     _TRACERIOC(0x07)
#define TRIOC_SETIRQFILTER     _TRACERIOC(0x08)
#endif

#endif

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* This is the type of the argument passed to the TRIOC_GETMODE and
 * TRIOC_SETMODE ioctls
 */

struct tracer_mode_s
{
  unsigned int flag;          /* Trace mode flag */

#define TRIOC_MODE_FLAG_ONESHOT      (1 << 0) /* Enable Oneshot trace */
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
#define TRIOC_MODE_FLAG_SYSCALL      (1 << 1) /* Enable syscall trace */
#define TRIOC_MODE_FLAG_SYSCALL_ARGS (1 << 2) /* Enable collecting syscall arguments */
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
#define TRIOC_MODE_FLAG_IRQ          (1 << 3) /* Enable IRQ trace */
#endif
};

/* This is the type of the argument passed to the TRIOC_GETSYSCALLFILTER and
 * TRIOC_SETSYSCALLFILTER ioctls
 */

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
struct tracer_syscallfilter_s
{
  int nr_syscalls;          /* Number of filtered syscalls */
  int syscall[0];           /* Filtered syscall number list */
};
#endif

/* This is the type of the argument passed to the TRIOC_GETIRQFILTER and
 * TRIOC_SETIRQFILTER ioctls
 */

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
struct tracer_irqfilter_s
{
  int nr_irqs;              /* Number of filtered IRQs */
  int irq[0];               /* Filtered IRQ number list */
};
#endif

/* This type identifies a tracer structure */

enum tracer_type_e
{
  TRACER_TIMESEC           = 0, /* Only used by a packed structure */
  TRACER_FIRST             = 1, /* Only used by sched_tracer_get() */
  TRACER_MESSAGE           = 2,

  TRACER_START             = 3,
  TRACER_STOP              = 4,
  TRACER_SUSPEND           = 5,
  TRACER_RESUME            = 6,
#ifdef CONFIG_SMP
  TRACER_CPU_START         = 7,
  TRACER_CPU_STARTED       = 8,
  TRACER_CPU_PAUSE         = 9,
  TRACER_CPU_PAUSED        = 10,
  TRACER_CPU_RESUME        = 11,
  TRACER_CPU_RESUMED       = 12,
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  TRACER_SYSCALL_ENTER     = 13,
  TRACER_SYSCALL_LEAVE     = 14,
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  TRACER_IRQHANDLER_ENTER  = 15,
  TRACER_IRQHANDLER_LEAVE  = 16,
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_PREEMPTION /* TBD */
  TRACER_PREEMPT_LOCK      = 17,
  TRACER_PREEMPT_UNLOCK    = 18,
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_CSECTION /* TBD */
  TRACER_CSECTION_ENTER    = 19,
  TRACER_CSECTION_LEAVE    = 20,
#endif
#ifdef CONFIG_SCHED_INSTRUMENTATION_SPINLOCKS /* TBD */
  TRACER_SPINLOCK_LOCK     = 21,
  TRACER_SPINLOCK_LOCKED   = 22,
  TRACER_SPINLOCK_UNLOCK   = 23,
  TRACER_SPINLOCK_ABORT    = 24,
#endif
  TRACER_NUM_TRACE_TYPES
};

/* This structure provides the common header of each trace event */

struct tracer_common_s
{
  uint8_t length;                       /* Length of the trace event */
  uint8_t type;                         /* See enum tracer_type_e */
#ifdef CONFIG_SMP
  uint8_t cpu;                          /* CPU thread/task running on */
#endif
  struct timespec systime;              /* System time */
};

/* This is the specific form of the TRACER_FIRST trace event */

struct tracer_first_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  pid_t pid;                            /* PID of the first running task */
#if CONFIG_TASK_NAME_SIZE > 0
  char name[0];                         /* Name of the first running task */
#endif
};

/* This is the specific form of the TRACER_MESSAGE trace event */

struct tracer_message_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  char message[0];                      /* Message string */
};

/* This is the specific form of the TRACER_START trace event */

struct tracer_start_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  pid_t pid;                            /* PID of the task to be started */
#if CONFIG_TASK_NAME_SIZE > 0
  char name[0];                         /* Name of the task to be started */
#endif
};

/* This is the specific form of the TRACER_STOP trace event */

struct tracer_stop_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  pid_t pid;                            /* PID of the task to be terminated */
  uint8_t state;                        /* State of the task to be terminated */
#if CONFIG_TASK_NAME_SIZE > 0
  char name[0];                         /* Name of the task to be terminated */
#endif
};

/* This is the specific form of the TRACER_SUSPEND trace event */

struct tracer_suspend_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  pid_t pid;                            /* PID of the task to be suspended */
  uint8_t state;                        /* State of the task to be suspended */
#if CONFIG_TASK_NAME_SIZE > 0
  char name[0];                         /* Name of the task to be suspended */
#endif
};

/* This is the specific form of the TRACER_RESUME trace event */

struct tracer_resume_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  pid_t pid;                            /* PID of the task to be resumed */
#if CONFIG_TASK_NAME_SIZE > 0
  char name[0];                         /* Name of the task to be resumed */
#endif
};

#ifdef CONFIG_SMP

/* This is the specific form of the TRACER_CPU_START trace event */

struct tracer_cpu_start_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  int target;                           /* CPU being started */
};

/* This is the specific form of the TRACER_CPU_STARTED trace event */

struct tracer_cpu_started_s
{
  struct tracer_common_s common;        /* Common trace parameters */
};

/* This is the specific form of the TRACER_CPU_PAUSE trace event */

struct tracer_cpu_pause_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  int target;                           /* CPU being paused */
};

/* This is the specific form of the TRACER_CPU_PAUSED trace event */

struct tracer_cpu_paused_s
{
  struct tracer_common_s common;        /* Common trace parameters */
};

/* This is the specific form of the TRACER_CPU_RESUME trace event */

struct tracer_cpu_resume_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  int target;                           /* CPU being paused */
};

/* This is the specific form of the TRACER_CPU_RESUMED trace event */

struct tracer_cpu_resumed_s
{
  struct tracer_common_s common;        /* Common trace parameters */
};

#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL

/* This is the specific form of the TRACER_SYSCALL_ENTER trace event */

struct tracer_syscall_enter_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  int nr;                               /* System call number */
  int argc;                             /* Number of system call arguments */
  uintptr_t argv[0];                    /* System call arguments */
};

/* This is the specific form of the TRACER_SYSCALL_LEAVE trace event */

struct tracer_syscall_leave_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  int nr;                               /* System call number */
  uintptr_t result;                     /* Return value of the system call */
};

#endif /* CONFIG_SCHED_INSTRUMENTATION_SYSCALL */

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER

/* This is the specific form of the TRACER_IRQHANDLER_ENTER trace event */

struct tracer_irqhandler_enter_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  int irq;                              /* IRQ number */
  void *handler;                        /* Address of the interrupt handler */
};

/* This is the specific form of the TRACER_IRQHANDLER_LEAVE trace event */

struct tracer_irqhandler_leave_s
{
  struct tracer_common_s common;        /* Common trace parameters */
  int irq;                              /* IRQ number */
};
#endif /* CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER */

union tracer_union_u
{
  struct tracer_common_s            common;
  struct tracer_first_s             first;
  struct tracer_message_s           message;
  struct tracer_start_s             start;
  struct tracer_stop_s              stop;
  struct tracer_suspend_s           suspend;
  struct tracer_resume_s            resume;

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  struct tracer_syscall_enter_s     syscall_enter;
  struct tracer_syscall_leave_s     syscall_leave;
#endif /* CONFIG_SCHED_INSTRUMENTATION_SYSCALL */

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  struct tracer_irqhandler_enter_s  irqhandler_enter;
  struct tracer_irqhandler_leave_s  irqhandler_leave;
#endif /* CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER */
};

#ifdef __KERNEL__

/* Packed structures only used in sched_tracer.c */

/* This structure provides the common header of each trace event */

struct tracer_packed_common_s
{
  uint8_t length;                       /* Length of the trace event */
  uint8_t type;                         /* See enum tracer_type_e */
#ifdef CONFIG_SMP
  uint8_t cpu;                          /* CPU thread/task running on */
#endif
  ua_uint32_t systimensec;              /* System time (usec) */
};

/* This is the specific form of the TRACER_TIMESEC trace event */

struct tracer_packed_timesec_s
{
  uint8_t length;                       /* Length of the trace event */
  uint8_t type;                         /* See enum tracer_type_e */
  ua_uintptr_t systimesec;              /* System time (sec) */
};

/* This is the specific form of the TRACER_FIRST trace event */

struct tracer_packed_first_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  ua_uint16_t pid;                      /* PID of the first running task */
};

/* This is the specific form of the TRACER_MESSAGE trace event */

struct tracer_packed_message_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  char message[0];                      /* Message string */
};

/* This is the specific form of the TRACER_START trace event */

struct tracer_packed_start_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  ua_uint16_t pid;                      /* PID of the task to be started */
};

/* This is the specific form of the TRACER_STOP trace event */

struct tracer_packed_stop_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  ua_uint16_t pid;                      /* PID of the task to be terminated */
  uint8_t state;                        /* State of the task to be terminated */
};

/* This is the specific form of the TRACER_SUSPEND trace event */

struct tracer_packed_suspend_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  ua_uint16_t pid;                      /* PID of the task to be suspended */
  uint8_t state;                        /* State of the task to be suspended */
};

/* This is the specific form of the TRACER_RESUME trace event */

struct tracer_packed_resume_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  ua_uint16_t pid;                      /* PID of the task to be resumed */
};

#ifdef CONFIG_SMP

/* This is the specific form of the TRACER_CPU_START trace event */

struct tracer_cpu_packed_start_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  uint8_t target;                       /* CPU being started */
};

/* This is the specific form of the TRACER_CPU_STARTED trace event */

struct tracer_cpu_packed_started_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
};

/* This is the specific form of the TRACER_CPU_PAUSE trace event */

struct tracer_cpu_packed_pause_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  uint8_t target;                       /* CPU being started */
};

/* This is the specific form of the TRACER_CPU_PAUSED trace event */

struct tracer_cpu_packed_paused_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
};

/* This is the specific form of the TRACER_CPU_RESUME trace event */

struct tracer_cpu_packed_resume_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  uint8_t target;                       /* CPU being started */
};

/* This is the specific form of the TRACER_CPU_RESUMED trace event */

struct tracer_cpu_packed_resumed_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
};

#endif

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL

/* This is the specific form of the TRACER_SYSCALL_ENTER trace event */

struct tracer_packed_syscall_enter_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  uint8_t nr;                           /* System call number */
  uint8_t argc;                         /* Number of system call arguments */
  ua_uintptr_t argv[0];                 /* System call arguments */
};

/* This is the specific form of the TRACER_SYSCALL_LEAVE trace event */

struct tracer_packed_syscall_leave_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  uint8_t nr;                           /* System call number */
  ua_uintptr_t result;                  /* Return value of the system call */
};
#endif /* CONFIG_SCHED_INSTRUMENTATION_SYSCALL */

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER

/* This is the specific form of the TRACER_IRQHANDLER_ENTER trace event */

struct tracer_packed_irqhandler_enter_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  uint8_t irq;                          /* IRQ number */
  ua_uintptr_t handler;                 /* Address of the interrupt handler */
};

/* This is the specific form of the TRACER_IRQHANDLER_LEAVE trace event */

struct tracer_packed_irqhandler_leave_s
{
  struct tracer_packed_common_s common; /* Common trace parameters */
  uint8_t irq;                          /* IRQ number */
};
#endif /* CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER */

union tracer_packed_union_u
{
  uint8_t                                 bytes[UCHAR_MAX];
  struct tracer_packed_common_s           common;
  struct tracer_packed_timesec_s          timesec;
  struct tracer_packed_first_s            first;
  struct tracer_packed_message_s          message;
  struct tracer_packed_start_s            start;
  struct tracer_packed_stop_s             stop;
  struct tracer_packed_suspend_s          suspend;
  struct tracer_packed_resume_s           resume;

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL
  struct tracer_packed_syscall_enter_s    syscall_enter;
  struct tracer_packed_syscall_leave_s    syscall_leave;
#endif /* CONFIG_SCHED_INSTRUMENTATION_SYSCALL */

#ifdef CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER
  struct tracer_packed_irqhandler_enter_s irqhandler_enter;
  struct tracer_packed_irqhandler_leave_s irqhandler_leave;
#endif /* CONFIG_SCHED_INSTRUMENTATION_IRQHANDLER */
};

#endif /* __KERNEL__ */

/****************************************************************************
 * Public Data
 ****************************************************************************/

#ifdef CONFIG_SCHED_INSTRUMENTATION_SYSCALL

extern const char *g_syscallname[];     /* System call name string table */

#endif

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

#if defined(__KERNEL__) || defined(CONFIG_BUILD_FLAT)

/****************************************************************************
 * Name: sched_tracer_get
 *
 * Description:
 *   Remove the next trace event from the tail of the circular buffer.
 *   The trace event is also removed from the circular buffer to make room
 *   for futher trace events.
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

ssize_t sched_tracer_get(FAR uint8_t *buffer, size_t buflen, bool removebig);

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

void sched_tracer_message(FAR const char *fmt, ...);

/****************************************************************************
 * Name: sched_tracer_mode
 *
 * Description:
 *   Set and get task trace mode.
 *   (Same as TRIOC_GETMODE / TRIOC_SETMODE ioctls)
 *
 * Input Parameters:
 *   newm - A read-only pointer to struct tracer_mode_s which holds the
 *          new trace mode
 *          If 0, the trace mode is not updated.
 *
 * Returned Value:
 *   A pointer to struct tracer_mode_s of the current trace mode
 *
 ****************************************************************************/

struct tracer_mode_s *sched_tracer_mode(struct tracer_mode_s *newm);

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
                                   struct tracer_syscallfilter_s *newf);
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
                               struct tracer_irqfilter_s *newf);
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

void sched_tracer_start(void);

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

void sched_tracer_stop(void);

#endif

#ifdef CONFIG_DRIVER_TRACER

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

int tracer_register(void);

#endif

#endif /* CONFIG_SCHED_INSTRUMENTATION_TRACER */
#endif /* __INCLUDE_NUTTX_SCHED_TRACER_H */
