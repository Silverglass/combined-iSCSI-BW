#
#  OCTEON TOOLKITS                                                         
#  Copyright (c) 2007 Cavium Networks. All rights reserved.
#
#  This file, which is part of the OCTEON TOOLKIT from Cavium Networks,
#  contains proprietary and confidential information of Cavium Networks
#  and in some cases its suppliers.
#
#  Any licensed reproduction, distribution, modification, or other use of
#  this file or confidential information embodied in this file is subject
#  to your license agreement with Cavium Networks. The applicable license
#  terms can be found by contacting Cavium Networks or the appropriate
#  representative within your company.
#
#  All other use and disclosure is prohibited.
#
#  Contact Cavium Networks at info@caviumnetworks.com for more information.
#

#
#  application Makefile
#
#  $Id: Makefile 33428 2008-04-02 18:53:40Z asehorewala $ $Name$
#
#    subdirectory config/ contains all the configuration header files.
#        for example config/cvmx-config contains the exec/system config,
#        config/global-config contains global config across components,
#

NUM_PROCESSORS = 16
NUM_APP_PROCESSORS = 2

#  default target

#default: inicmain 
#	mips64-octeon-linux-gnu-strip inicmain

#  default target

default: inicmain 
	cp -f inicmain /tftpboot/cb-iscsi


#  standard common Makefile fragment
include $(OCTEON_ROOT)/common.mk

# core masks
CORE_MASKS = -DNUM_PROCESSORS=$(NUM_PROCESSORS) -DNUM_APP_PROCESSORS=$(NUM_APP_PROCESSORS)

#  global debug setting for compile
# DEBUG_FLAGS = -DOCTEON_DEBUG_LEVEL=8
DEBUG_FLAGS = 

ifeq (${CVM_IP6},1)
CC_FLAGS =  -DINET6 -DCVM_IP6_FASTPATH
endif

ifeq (${CVM_VLAN},1)
CC_FLAGS += -DCVM_ENET_VLAN
endif

ifeq (${CVM_TUNNEL},1)
ifeq (${CVM_IP6},1)
CC_FLAGS +=  -DCVM_ENET_TUNNEL
endif
endif

ifeq (${TCP_TPS_SIM},1)
CC_FLAGS += -DTCP_TPS_SIM
NUM_PROCESSORS = 1
NUM_APP_PROCESSORS = 0
endif


COMPILE += -Wall -Wa,-a=$@.list -Wno-unused-parameter -O2 -g -fno-strict-aliasing $(DEBUG_FLAGS) $(CORE_MASKS) $(CC_FLAGS)
COMPILE += -DTEMP_SDK_BUILD_NUMBER=`oct-version | sed -n "s/.* build \(.*\)/\1/p"`

GCC_VER = $(shell $(CC) --version | grep GCC)
SDK_VER = `oct-version`

COMPILE += -DGCC_VERSION=\""$(GCC_VER)\""
COMPILE += -DSDK_VERSION=\""$(SDK_VER)\""

#  include needed component Makefile fragments

dir := $(OCTEON_ROOT)/components/common
include $(dir)/common.mk

dir := $(OCTEON_ROOT)/components/socket
include $(dir)/socket.mk

dir := $(OCTEON_ROOT)/components/tcp
include $(dir)/tcp.mk

dir := $(OCTEON_ROOT)/components/udp
include $(dir)/udp.mk

dir := $(OCTEON_ROOT)/components/ip
include $(dir)/ip.mk

dir := $(OCTEON_ROOT)/components/enet
include $(dir)/enet.mk

ifeq (${CVM_IP6},1)
dir := $(OCTEON_ROOT)/components/ip6
include $(dir)/ip6.mk
endif

dir := $(OCTEON_ROOT)/executive
include $(dir)/cvmx.mk

#  application specification

TARGET        =  inicmain

ECHO_SERVER   = $(OBJ_DIR)/app-echo-server-cb.o
CLIENT_APP    = $(OBJ_DIR)/app-client-cb.o
CLI_APP       = $(OBJ_DIR)/app-cli.o
RMNGR_APP     = $(OBJ_DIR)/inicrmngr.o
ISCSI         = $(OBJ_DIR)/io.o $(OBJ_DIR)/initiator.o $(OBJ_DIR)/iscsi_if.o $(OBJ_DIR)/iscsi_tcp.o $(OBJ_DIR)/login.o $(OBJ_DIR)/netlink.o $(OBJ_DIR)/hosts.o $(OBJ_DIR)/scsi.o $(OBJ_DIR)/scsi_lib.o $(OBJ_DIR)/scsi_scan.o $(OBJ_DIR)/sd.o $(OBJ_DIR)/iSCSI-iface.o $(OBJ_DIR)/app-iscsi-cb.o


OBJS          =	$(OBJ_DIR)/inicmain.o \
		$(OBJ_DIR)/inicdata.o \
		$(OBJ_DIR)/inicapp.o \
		$(ISCSI)

CLI_APP_INCLUDE = $(OCTEON_ROOT)/bootloader/u-boot/include/

CFLAGS_LOCAL = -g -O2 -W -Wall -Wno-unused-parameter -I$(CLI_APP_INCLUDE)
CFLAGS_G = -G $(if $(shell $(CC) --version | grep 3.4),5,7)

ifeq (${OCTEON_TARGET},cvmx_n32)
COMPILE += $(CFLAGS_G)
CFLAGS_LOCAL += $(CFLAGS_G)
endif

include $(OCTEON_ROOT)/application.mk


#  clean target

clean:
	rm -f $(TARGET)
	rm -f $(CVMX_CONFIG)
	rm -fr $(OBJ_DIR)


run:	
	#
	# Run the simulation. All outout will go in output.log but console
	# messages will also display to the user.
	 oct-sim inicmain -quiet -wait=inic_data_loop -serve=2000 -uart1=2001 -memsize=512 -numpps=${NUM_PROCESSORS} -modes=fastboot $(SIMFLAGS)

debug:	
	#
	# Debug the simulation. All outout will go in output.log but console
	# messages will also display to the user.
	oct-debug inicmain -debug -noperf -quiet -serve=2000 -uart1=2001 -memsize=512 -numpps=${NUM_PROCESSORS} -modes=spi0,spi1,fastboot




