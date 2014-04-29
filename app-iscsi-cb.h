/***********************************************************************

  OCTEON TOOLKITS                                                         
  Copyright (c) 2007 Cavium Networks. All rights reserved.

  This file, which is part of the OCTEON TOOLKIT from Cavium Networks,
  contains proprietary and confidential information of Cavium Networks
  and in some cases its suppliers.

  Any licensed reproduction, distribution, modification, or other use of
  this file or confidential information embodied in this file is subject
  to your license agreement with Cavium Networks. The applicable license
  terms can be found by contacting Cavium Networks or the appropriate
  representative within your company.

  All other use and disclosure is prohibited.

  Contact Cavium Networks at info@caviumnetworks.com for more information.

 ************************************************************************/ 

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "cvm-common-errno.h"

#include "cvmx-config.h"
#include "global-config.h"

#include "cvmx.h"
#include "cvmx-packet.h"
#include "cvmx-pko.h"
#include "cvmx-fau.h"
#include "cvmx-wqe.h"
#include "cvmx-spinlock.h"
#include "cvmx-malloc.h"
#include "cvmx-coremask.h"
#include "cvmx-sysinfo.h"

#include "cvm-ip-in.h"
#include "cvm-ip.h"

#include "socket.h"
#include "socketvar.h"
#include "cvm-socket.h"
#include "cvm-socket-cb.h"

#include "inic.h"

#if defined(CVM_COMBINED_APP_STACK)

int iscsi_init_global ();
int iscsi_init_local ();
int iscsi_main_global ();
int iscsi_main_local ();
int iscsi_timeout_handler ();
int iscsi_notification (uint32_t fd, void* context, uint32_t event_flags);
int iscsi_exit_local ();
int iscsi_exit_global ();

#endif

