#include <string>
#include <boost/asio.hpp>
#include <fstream>
#include <iostream>
#include <vector>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>


using namespace boost::asio;
using namespace std;
static int fd;

#ifndef SCAN_H
#define SCAN_H


/**
 * Usage:
* This utility generates the ip addresses in the given network address range for scan purposes
*
* arguments
* network_range string     The IPv6 CIDR range to scan.

*/

ip::address_v6_range generate_ip_addresses(string network_range);



/**
 * Usage:
* This utility scans for live hosts over IPv6 ip list. The output contains the ip address and the reachability as a pari
*
* arguments
* ip_list vector<string>      The list of IPV6 ips to be scanned.

*/
vector<pair<string,string>> scan_ip_list(vector<string> ip_list);



/**
 * Usage:
* This utility scans for live hosts over IPv6 based on the network range you specify. If no range is
* specified, then this utility scans the global IPv6 address space (e.g. 2000::/4). The scanning process
* generates candidate addresses, scans for them, tests the network ranges where live addresses are found
* for aliased conditions, and adds legitimate discovered IPv6 addresses to an output list
*
* arguments
* network string     The IPv6 CIDR range to scan.
* output_path string       The path to save the responses in json format

*/
void scan(string network, string output_path);

#endif