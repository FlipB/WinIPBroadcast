// Copyright (C) 2015 Filip Björck

/*
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef _WINIPBROADCAST_H_
#define _WINIPBROADCAST_H_ 1



#include <Winsock2.h>
#include <Ws2tcpip.h>
#include <Iphlpapi.h>

#ifdef WPCAP
#include "wpcap_broadcast.h" // defines wpcap_main();
#else
static void wpcap_main() { } // NOP
#endif


#define IP_HEADER_SIZE 20
#define IP_SRCADDR_POS 12
#define IP_DSTADDR_POS 16
#define UDP_HEADER_SIZE 8
#define UDP_CHECKSUM_POS 6
#define FORWARDTABLE_INITIAL_SIZE 4096


extern void quit(void);
extern void getForwardTable();
extern void relayBroadcast(char *payload, DWORD payloadSize, ULONG srcAddress);
extern void _relayBroadcast(char *payload, DWORD payloadSize, ULONG srcAddress, ULONG captureAddress);

extern ULONG loopbackAddress;
extern ULONG broadcastAddress;
extern PMIB_IPFORWARDTABLE forwardTable;
extern ULONG forwardTableSize;
extern HANDLE relayMutex;





#endif // _WINIPBROADCAST_H_