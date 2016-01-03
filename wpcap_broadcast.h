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
#ifndef _WPCAP_BROADCAST_H_
#define _WPCAP_BROADCAST_H_ 1


#include <winsock2.h>

extern void wpcap_iptos(u_long in, char* ip_out);
extern void wpcap_main();




#endif // _WPCAP_BROADCAST_H_