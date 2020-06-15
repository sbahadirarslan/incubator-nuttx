/****************************************************************************
 * include/nuttx/sched_unaligned.h
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

#ifndef __INCLUDE_NUTTX_SCHED_UNALIGNED_H
#define __INCLUDE_NUTTX_SCHED_UNALIGNED_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>
#include <sys/types.h>
#include <stdint.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#if UINTPTR_MAX > UINT32_MAX
#  define put_ua_uintptr(p,v) put_ua_uint64(p,v)
#  define get_ua_uintptr(p)   get_ua_uint64(p)
#else
#  define put_ua_uintptr(p,v) put_ua_uint32(p,v)
#  define get_ua_uintptr(p)   get_ua_uint32(p)
#endif

/****************************************************************************
 * Public Type Definitions
 ****************************************************************************/

/* The structures to hold an unaligned word */

typedef struct
{
  uint8_t value[sizeof(uint16_t)];
} ua_uint16_t;

typedef struct
{
  uint8_t value[sizeof(uint32_t)];
} ua_uint32_t;

typedef struct
{
  uint8_t value[sizeof(uint64_t)];
} ua_uint64_t;

#if UINTPTR_MAX > UINT32_MAX
  typedef ua_uint64_t ua_uintptr_t;
#else
  typedef ua_uint32_t ua_uintptr_t;
#endif

/****************************************************************************
 * Inline Functions
 ****************************************************************************/

/* The inline functions to put/get an unaligned word */

static inline void put_ua_uint16(ua_uint16_t *p, uint16_t v)
{
#ifdef CONFIG_ENDIAN_BIG
  p->value[0] = (uint8_t)((v >> 8) & 0xff);
  p->value[1] = (uint8_t)(v        & 0xff);
#else
  p->value[0] = (uint8_t)(v        & 0xff);
  p->value[1] = (uint8_t)((v >> 8) & 0xff);
#endif
}

static inline void put_ua_uint32(ua_uint32_t *p, uint32_t v)
{
#ifdef CONFIG_ENDIAN_BIG
  p->value[0] = (uint8_t)((v >> 24) & 0xff);
  p->value[1] = (uint8_t)((v >> 16) & 0xff);
  p->value[2] = (uint8_t)((v >> 8)  & 0xff);
  p->value[3] = (uint8_t)(v         & 0xff);
#else
  p->value[0] = (uint8_t)(v         & 0xff);
  p->value[1] = (uint8_t)((v >> 8)  & 0xff);
  p->value[2] = (uint8_t)((v >> 16) & 0xff);
  p->value[3] = (uint8_t)((v >> 24) & 0xff);
#endif
}

static inline void put_ua_uint64(ua_uint64_t *p, uint64_t v)
{
#ifdef CONFIG_ENDIAN_BIG
  p->value[0] = (uint8_t)((v >> 56) & 0xff);
  p->value[1] = (uint8_t)((v >> 48) & 0xff);
  p->value[2] = (uint8_t)((v >> 40) & 0xff);
  p->value[3] = (uint8_t)((v >> 32) & 0xff);
  p->value[4] = (uint8_t)((v >> 24) & 0xff);
  p->value[5] = (uint8_t)((v >> 16) & 0xff);
  p->value[6] = (uint8_t)((v >> 8)  & 0xff);
  p->value[7] = (uint8_t)(v         & 0xff);
#else
  p->value[0] = (uint8_t)(v         & 0xff);
  p->value[1] = (uint8_t)((v >> 8)  & 0xff);
  p->value[2] = (uint8_t)((v >> 16) & 0xff);
  p->value[3] = (uint8_t)((v >> 24) & 0xff);
  p->value[4] = (uint8_t)((v >> 32) & 0xff);
  p->value[5] = (uint8_t)((v >> 40) & 0xff);
  p->value[6] = (uint8_t)((v >> 48) & 0xff);
  p->value[7] = (uint8_t)((v >> 56) & 0xff);
#endif
}

static inline uint16_t get_ua_uint16(ua_uint16_t *p)
{
#ifdef CONFIG_ENDIAN_BIG
  return (p->value[0] << 8) |
          p->value[1];
#else
  return  p->value[0] |
         (p->value[1] << 8);
#endif
}

static inline uint32_t get_ua_uint32(ua_uint32_t *p)
{
#ifdef CONFIG_ENDIAN_BIG
  return (p->value[0] << 24) |
         (p->value[1] << 16) |
         (p->value[2] << 8)  |
          p->value[3];
#else
  return  p->value[0] |
         (p->value[1] << 8)  |
         (p->value[2] << 16) |
         (p->value[3] << 24);
#endif
}

static inline uint64_t get_ua_uint64(ua_uint64_t *p)
{
#ifdef CONFIG_ENDIAN_BIG
  return (p->value[0] << 56) |
         (p->value[1] << 48) |
         (p->value[2] << 40) |
         (p->value[3] << 32) |
         (p->value[4] << 24) |
         (p->value[5] << 16) |
         (p->value[6] << 8)  |
          p->value[7];
#else
  return  p->value[0] |
         (p->value[1] << 8)  |
         (p->value[2] << 16) |
         (p->value[3] << 24) |
         (p->value[4] << 32) |
         (p->value[5] << 40) |
         (p->value[6] << 48) |
         (p->value[7] << 56);
#endif
}

#endif /* __INCLUDE_NUTTX_SCHED_UNALIGNED_H */
