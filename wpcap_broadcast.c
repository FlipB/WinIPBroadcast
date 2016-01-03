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
#include "wpcap_broadcast.h"
#include "WinIPBroadcast.h"

#include <stdio.h>
#include <stdlib.h>
#include <Ws2tcpip.h>
#include <windows.h>
#include <Iphlpapi.h>

#include <Ws2tcpip.h>
#include <windows.h>
#include <Iphlpapi.h>

// WinPCAP includes.
#define HAVE_REMOTE
#include <pcap.h>
#include <process.h>
#include <Netioapi.h>


#define WPCAP_STATE_IDLE 0
#define WPCAP_STATE_STARTED 1
#define WPCAP_STATE_STOPPED 2
#define WPCAP_STATE_UNINITIALIZED -1
#define WPCAP_STATE_BREAK -2


// DEFINITIONS

struct wpcap_interface {
	ULONG address;
	ULONG netmask;
	ULONG index;
	char name[MAX_ADAPTER_NAME_LENGTH + 4];
};

struct wpcap_context {
	pcap_t *handle;
	struct bpf_program filter_code;
	char filter[128]; //"src host %s and ip and udp and dst host 255.255.255.255 and (udp[0:2] = udp[2:2])";
	int state;
};

struct wpcap_thread_args {
	struct wpcap_context *context;
	struct wpcap_interface *adapter;
};

static BOOLEAN _get_interface_details(struct wpcap_interface* const bcast_if);
static BOOLEAN _write_interface_details(IP_ADAPTER_ADDRESSES* adapter_addresses, struct wpcap_interface* const bcast_if);
static inline void printError(struct wpcap_context* context, int error_code, char* msg);

static BOOLEAN wpcap_init(struct wpcap_context *context);
//void wpcap_destroy(struct wpcap_context *wpcap_context);
static void wpcap_start();
static void wpcap_update();
static void wpcap_stop();

static struct wpcap_context* wpcap_get_global_context();
static struct wpcap_interface* wpcap_get_global_interface();

static unsigned int wpcap_get_num_devices();
static BOOLEAN wpcap_set_filter(struct wpcap_context *context, struct wpcap_interface* bcast_if);

static void wpcap_loop(struct wpcap_thread_args* args);
static void wpcap_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

static BOOLEAN get_broadcast_interface(struct wpcap_interface* const bcast_if);
static void get_interface_changes(struct wpcap_interface* const bcast_if);

static void init_callbacks(struct wpcap_interface * const broadcast_interface, PHANDLE route_cb, PHANDLE interface_cb, PHANDLE address_cb);
static void WINAPI interface_update_callback(PVOID ptr, PMIB_IPINTERFACE_ROW data, MIB_NOTIFICATION_TYPE t);
static void WINAPI address_update_callback(PVOID ptr, PMIB_UNICASTIPADDRESS_ROW data, MIB_NOTIFICATION_TYPE t);
static void WINAPI route_update_callback(PVOID ptr, PMIB_IPFORWARD_ROW2 data, MIB_NOTIFICATION_TYPE t);


// GLOBALS
static struct wpcap_context wpcap_context = { 0 };
static struct wpcap_interface wpcap_broadcast_interface = { 0 };
static HANDLE broadcast_interface_mutex;
static uintptr_t wpcap_thread;







struct wpcap_context* wpcap_get_global_context() {
	return &wpcap_context;
}

struct wpcap_interface* wpcap_get_global_interface() {
	return &wpcap_broadcast_interface;
}

void wpcap_main() {
	static HANDLE callback_route;
	static HANDLE callback_interface;
	static HANDLE callback_address;
	struct wpcap_context *context = wpcap_get_global_context();
	struct wpcap_interface *broadcast_if = wpcap_get_global_interface();

	get_broadcast_interface(broadcast_if);
	init_callbacks(broadcast_if, &callback_route, &callback_interface, &callback_address);

	//fprintf(stderr, "wpcap_main.\n");

	broadcast_interface_mutex = CreateMutex(NULL, FALSE, TEXT("WinPCAP Interface mutex"));

	
	if (wpcap_init(context)) {
		wpcap_start();
	}
}


static void wpcap_start() {
	struct wpcap_context *context = wpcap_get_global_context();
	struct wpcap_interface *broadcast_interface = wpcap_get_global_interface();
	static struct wpcap_thread_args args = { 0 };

	if (context->state == WPCAP_STATE_IDLE || context->state == WPCAP_STATE_STOPPED) {
		args.adapter = broadcast_interface;
		args.context = context;
		context->state = WPCAP_STATE_IDLE;
		wpcap_thread = _beginthread(wpcap_loop, 0, &args);
	}
	else {
		printf("Error: Trying to start WinPCAP with state %d\n", context->state);
	}
}

static void wpcap_update() {
	struct wpcap_context* context = wpcap_get_global_context();
	if (context->state == WPCAP_STATE_STARTED && context->handle != NULL) {
		pcap_breakloop(context->handle);
	}
	else if (context->state == WPCAP_STATE_STOPPED) {
		// thread terminated.
		// we have new interface details now, maybe they will work better. Start new thread.
		wpcap_start();
	}
}

static void wpcap_stop() {
	struct wpcap_context* context = wpcap_get_global_context();
	if (context->state == WPCAP_STATE_STARTED && context->handle != NULL) {
		context->state = WPCAP_STATE_BREAK;
		pcap_breakloop(context->handle);
	}
	//else {
	//	printf("Error: Trying to stop WinPCAP with state #%d\n", wpcap_context.state);
	//}
}

static BOOLEAN wpcap_init(struct wpcap_context *wpcap_context) {
	wpcap_context->state = WPCAP_STATE_UNINITIALIZED;

	snprintf(wpcap_context->filter, 128, "src host %%s and ip and udp and dst host 255.255.255.255 and (udp[0:2] = udp[2:2])");

	unsigned int num_devices = wpcap_get_num_devices(wpcap_context);
	if (num_devices == 0) {
		fwprintf(stderr, TEXT("No WinPCAP devices found. Is WinPCAP installed?\n"));
		return FALSE;
	}

	wpcap_context->state = WPCAP_STATE_IDLE;
	return TRUE;
}

static void wpcap_loop(struct wpcap_thread_args* args) {
	struct wpcap_context *wpcap_context = args->context;

	struct wpcap_interface capture_interface;

	int return_code;
	int loop_error = 0;
	char source[MAX_ADAPTER_NAME_LENGTH + 4 + 22];
	char tmp[PCAP_ERRBUF_SIZE];

	if (wpcap_context->state != WPCAP_STATE_IDLE) {
		return;
	}
	wpcap_context->state = WPCAP_STATE_STARTED;

	while (wpcap_context->state == WPCAP_STATE_STARTED) {

		WaitForSingleObject(broadcast_interface_mutex, INFINITE);
		if (args->adapter->address != 0 && *args->adapter->name != '\0') {
			// create local copy so we can release the mutex.
			capture_interface.address = args->adapter->address;
			capture_interface.netmask = args->adapter->netmask;
			capture_interface.index = args->adapter->index;
			strncpy_s(capture_interface.name, (MAX_ADAPTER_NAME_LENGTH + 4), args->adapter->name, (MAX_ADAPTER_NAME_LENGTH + 4));
		} else {
			loop_error = 1;
			break;
		}
		ReleaseMutex(broadcast_interface_mutex);

		// Generate WPCAP device string from Windows device name.
		snprintf(source, MAX_ADAPTER_NAME_LENGTH + 4 + 22, "rpcap://\\Device\\NPF_%s", capture_interface.name);

		// Open capture device
		if ((wpcap_context->handle = pcap_open(source, 65536, PCAP_OPENFLAG_NOCAPTURE_LOCAL, 1000, NULL, tmp)) == NULL) {
			loop_error = 2;
			break;
		}

		// Check the link layer. We support only Ethernet for simplicity. 
		if (pcap_datalink(wpcap_context->handle) != DLT_EN10MB)
		{
			loop_error = 3;
			break;
		}

		if (wpcap_set_filter(wpcap_context, &capture_interface) == FALSE) {
			loop_error = 4;
			break;
		}
		/*
		char ip[20];
		char mask[20];
		wpcap_iptos(capture_interface.address, ip);
		wpcap_iptos(capture_interface.netmask, mask);
		printf("DEBUG: %s/%s on (_%s_)\n", ip, mask, capture_interface.name);
		*/

		if (wpcap_context->state == WPCAP_STATE_BREAK) {
			break; // wpcap_stop() called.
		}

		return_code = pcap_loop(wpcap_context->handle, -1, wpcap_packet_handler, (u_char *)&capture_interface);
		// return_code == -2 when breakloop() is called.
		if (return_code == -1) {
			loop_error = 5;
			break;
		}
	}

	// report error
	char msg[48];
	_itoa_s(return_code, msg, 48, 10);
	printError(wpcap_context, loop_error, msg);

	// Clean up
	if (&wpcap_context->filter_code != NULL)
		pcap_freecode(&wpcap_context->filter_code);
	if (wpcap_context->handle != NULL)
		pcap_close(wpcap_context->handle);
	wpcap_context->handle = NULL;
	//fprintf(stderr, "Ending thread.\n");
	wpcap_context->state = WPCAP_STATE_STOPPED;
	_endthread();
}


static inline void printError(struct wpcap_context* context, int error_code, char* msg) {
	switch (error_code) {
	case 1:
		fprintf(stderr, "Error: Unable to find Broadcast adapter.\n");
		break;
	case 2:
		fprintf(stderr, "Error: Unable to open adapter. Device not supported by WinPap.\n");
		break;
	case 3:
		fprintf(stderr, "Error: Detected Broadcast adapter is non-Ethernet. Ethernet adapter required.\n");
		break;
	case 4:
		fprintf(stderr, "Error: Setting packet filter on WinPCAP device failed.\n");
		break;
	case 5:

		pcap_perror(context->handle, "wpcap_open: ");
		break;
	default:
		fprintf(stderr, "pcap_loop: UNKNOWN ERROR: %s", msg);
		break;
	}
}


static unsigned int wpcap_get_num_devices() {
	unsigned int num_devices = 0;
	pcap_if_t *wpcap_devices;
	char tmp[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &wpcap_devices, tmp) == -1)
		return 0;

	if (wpcap_devices != NULL) {
		for (; wpcap_devices; wpcap_devices = wpcap_devices->next) {
			num_devices++;
		}
	}

	pcap_freealldevs(wpcap_devices);
	return num_devices;
}


static BOOLEAN wpcap_set_filter(struct wpcap_context *context, struct wpcap_interface* bcast_if) {
	char filter[128];
	char adapter_ip[3 * 4 + 3 + 1];
	wpcap_iptos(bcast_if->address, adapter_ip);
	snprintf(filter, 128, context->filter, adapter_ip);
	if (pcap_compile(context->handle, &context->filter_code, filter, 1, bcast_if->netmask) < 0) {
		return FALSE;
	}
	if (pcap_setfilter(context->handle, &context->filter_code) < 0)
	{
		return FALSE;
	}
	return TRUE;
}


/* Callback function invoked by libpcap for every incoming packet */
static void wpcap_packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct wpcap_interface* bcast_if = (struct wpcap_interface*)(param); // copied structure

	char *payload = (char *)(pkt_data + 14); // 14 for ethernet header - skip this.
	DWORD payloadSize = (header->len) - 14 - IP_HEADER_SIZE;
	ULONG srcAddress = (ULONG)payload[IP_SRCADDR_POS];
	
	/*
	ULONG dstAddress = (ULONG)payload[IP_DSTADDR_POS]; // used for debug only
	char src[20];
	char dst[20];
	wpcap_iptos(srcAddress, src);
	wpcap_iptos(dstAddress, dst);
	printf("DEBUG: %s -> %s\n", src, dst);
	*/

	WaitForSingleObject(relayMutex, INFINITE);
	_relayBroadcast(payload + IP_HEADER_SIZE, payloadSize, srcAddress, bcast_if->address);
	ReleaseMutex(relayMutex);
}

/* From tcptraceroute, convert a numeric IP address to a string */
// modified to write to a pointer.
extern void wpcap_iptos(u_long in, char* ip_out)
{
	//char output[3 * 4 + 3 + 1];
	u_char *p;

	p = (u_char *)&in;
	snprintf(ip_out, 3 * 4 + 3 + 1, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
}





static BOOLEAN get_broadcast_interface(struct wpcap_interface* const bcast_if) {
	MIB_IPFORWARD_ROW2 default_bcast_row;
	SOCKADDR_INET default_bcast_source_addr;
	SOCKADDR_INET sockaddr = { 0 };


	ULONG bcastAddr = broadcastAddress; // global variable

	sockaddr.si_family = AF_INET;
	sockaddr.Ipv4.sin_addr.S_un.S_addr = bcastAddr;

	DWORD bcastInterfaceIndex = 0;
	GetBestInterface(bcastAddr, &bcastInterfaceIndex);

	DWORD retval = GetBestRoute2(NULL, bcastInterfaceIndex, NULL, &sockaddr, 0, &default_bcast_row, &default_bcast_source_addr);
	if (retval == NO_ERROR) {
		bcast_if->address = default_bcast_source_addr.Ipv4.sin_addr.S_un.S_addr;
		bcast_if->index = default_bcast_row.InterfaceIndex;
		return _get_interface_details(bcast_if);
	}
	return FALSE;
}

static BOOLEAN _get_interface_details(struct wpcap_interface* const bcast_if) {
	unsigned int return_val = FALSE;
	ULONG retval;
	IP_ADAPTER_ADDRESSES *buffer = { 0 };

	int bufferSize = 1024;

	unsigned int num_retry = 0;
	unsigned int num_retry_max = 3;

retry:
	buffer = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), 0, bufferSize);
	if (buffer != NULL) {
		retval = GetAdaptersAddresses(AF_INET, 0, (void *) NULL, buffer, &bufferSize);
		if (retval == ERROR_SUCCESS) {
			// buffer has been filled.
			return_val = _write_interface_details(buffer, bcast_if);
		}
		else if (retval == ERROR_BUFFER_OVERFLOW && num_retry < num_retry_max) {
			// buffer needs resizing. bufferSize should have been updated.
			HeapFree(GetProcessHeap(), 0, buffer);
			num_retry++;
			goto retry;
		}
		else {
			return_val = FALSE;
		}
	}

	HeapFree(GetProcessHeap(), 0, buffer);
	return return_val;
}

static BOOLEAN _write_interface_details(IP_ADAPTER_ADDRESSES* adapter_addresses, struct wpcap_interface* const bcast_if) {
	PIP_ADAPTER_UNICAST_ADDRESS addresses;

	for (IP_ADAPTER_ADDRESSES *adapters = adapter_addresses; adapters; adapters = adapters->Next) {

		if (adapters->IfIndex != bcast_if->index)
			continue;

		strcpy_s(bcast_if->name, MAX_ADAPTER_NAME_LENGTH + 4, adapters->AdapterName);
		for (addresses = adapters->FirstUnicastAddress; addresses; addresses = addresses->Next) {

			ULONG address = ((struct sockaddr_in *)(addresses->Address.lpSockaddr))->sin_addr.s_addr;
			if (bcast_if->address == address) {
				ConvertLengthToIpv4Mask(adapters->FirstUnicastAddress->OnLinkPrefixLength, &bcast_if->netmask);
				return TRUE;
				break;
			}
		}
		break;
	}
	return FALSE;
}




static void get_interface_changes(struct wpcap_interface* const bcast_if) {

	struct wpcap_interface new_bcast_if = {0};
	int if_change = 0;

	WaitForSingleObject(broadcast_interface_mutex, INFINITE);

	if (get_broadcast_interface(&new_bcast_if) == TRUE) {
		if (strncmp(new_bcast_if.name, bcast_if->name, MAX_ADAPTER_NAME_LENGTH + 4) != 0)
			if_change++;
		if (new_bcast_if.address != bcast_if->address)
			if_change++;
		if (new_bcast_if.netmask != bcast_if->netmask)
			if_change++;
		if (new_bcast_if.index != bcast_if->index)
			if_change++;

		if (if_change > 0) {
			// at least 1 change.
			bcast_if->address = new_bcast_if.address;
			bcast_if->index = new_bcast_if.index;
			bcast_if->netmask = new_bcast_if.netmask;
			strncpy_s(bcast_if->name, sizeof(char)*MAX_ADAPTER_NAME_LENGTH + 4, new_bcast_if.name, MAX_ADAPTER_NAME_LENGTH + 4);
		}
	}
	else {
		bcast_if->address = 0;
		bcast_if->index = 0;
		bcast_if->netmask = 0;
		*bcast_if->name = '\0';
	}

	ReleaseMutex(broadcast_interface_mutex);

	wpcap_update(bcast_if);
}


static void init_callbacks(struct wpcap_interface * const broadcast_interface, PHANDLE route_cb, PHANDLE interface_cb, PHANDLE address_cb) {
	NotifyRouteChange2(AF_INET, (PIPFORWARD_CHANGE_CALLBACK)&route_update_callback, (void *)broadcast_interface, false, interface_cb);
	NotifyIpInterfaceChange(AF_INET, &interface_update_callback, (void *)broadcast_interface, false, route_cb);
	NotifyUnicastIpAddressChange(AF_INET, &address_update_callback, (void *)broadcast_interface, false, address_cb);
}

static void WINAPI route_update_callback(PVOID ptr, PMIB_IPFORWARD_ROW2 route_upd_row, MIB_NOTIFICATION_TYPE t) {
	if (route_upd_row == NULL) return;

	struct wpcap_interface* bcast_if = (struct wpcap_interface *) ptr;

	if (route_upd_row->InterfaceIndex == bcast_if->index) {
		get_interface_changes(bcast_if);
	}

	//printf("DEBUG: NotifyRouteChange callback.\n");
}

static void WINAPI interface_update_callback(PVOID ptr, PMIB_IPINTERFACE_ROW if_upd_row, MIB_NOTIFICATION_TYPE t) {
	if (if_upd_row == NULL) return;

	struct wpcap_interface* bcast_if = (struct wpcap_interface *) ptr;
	//GetIpInterfaceEntry(if_upd_row);

	get_interface_changes(bcast_if);

	//printf("DEBUG: NotifyInterfaceChange callback.\n");
}

static void WINAPI address_update_callback(PVOID ptr, PMIB_UNICASTIPADDRESS_ROW uni_upd_row, MIB_NOTIFICATION_TYPE t) {
	if (uni_upd_row == NULL) return;

	struct wpcap_interface* bcast_if = (struct wpcap_interface *) ptr;

	// interface ip address has changed.
	if (uni_upd_row->InterfaceIndex == bcast_if->index) {
		if (uni_upd_row->Address.si_family == AF_INET) {
			get_interface_changes(bcast_if);
		}
	}

	//printf("DEBUG: NotifyAddressChange callback.\n");
}