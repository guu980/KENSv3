/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>


#include <E/E_TimerModule.hpp>

#include <set>
#include <map>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

	const static int MAX_PORT_NUM = 65536;
	std::set<int> fd_set;
	std::set<uint32_t> ip_set[MAX_PORT_NUM];
	bool is_addr_any[MAX_PORT_NUM];
	std::map<int, std::pair<uint32_t, unsigned short int>> fd_info;
	std::map<int, std::pair<struct sockaddr, socklen_t>> fd_info_raw;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();


	void syscall_socket(UUID syscallUUID, int pid,
		int domain, int protocol);
	void syscall_close(UUID syscallUUID, int pid,
		int fd);
	void syscall_bind(UUID syscallUUID, int pid, 
		int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	void syscall_getsockname(UUID syscallUUID, int pid, 
		int sockfd, struct sockaddr *addr, socklen_t *addrlen);


protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
