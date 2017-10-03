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

#include <unordered_set>
#include <unordered_map>
#include <queue>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

	const static int MAX_PORT_NUM = 65536;

	enum tcp_state {
		ST_INACTIVE, 	/* Only for server. Before LISTEN. */

		ST_LISTEN,		/* Connect ready. */
		ST_SYN_SENT,	/* 3-way handshake, client. */
		ST_SYN_RCVD,	/* 3-way handshake, server. */
		ST_ESTAB,		/* Connection established. */

		ST_FIN_WAIT_1,	/* 4-way handshake, client. */
		ST_FIN_WAIT_2,
		ST_TIMED_WAIT,
		ST_CLOSE_WAIT,	/* 4-way handshake, server. */
		ST_LAST_ACK,
		ST_CLOSED		/* Finally closed. */
	};

	struct proc_entry {
		std::unordered_set<int> fd_set;
		std::unordered_map<int, std::pair<sockaddr, socklen_t>> fd_info;

		struct blocked_accept {
			UUID syscallUUID;
			int sockfd;
			struct sockaddr *addr;
			socklen_t *addrlen;
		};

		struct blocked_connect {
			UUID syscallUUID;
			int sockfd;
			const struct sockaddr *addr;
			socklen_t addrlen;
		};

		std::queue<blocked_accept> accept_queue;
		std::queue<blocked_connect> connect_queue;
	};
	
	std::unordered_set<in_addr_t> ip_set[MAX_PORT_NUM];
	bool is_addr_any[MAX_PORT_NUM];
	std::unordered_map<int, proc_entry> proc_table;

	std::pair<in_addr_t, in_port_t> addr_ip_port(const sockaddr addr);

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

	void syscall_accept(UUID syscallUUID, int pid,
		int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_connect(UUID syscallUUID, int pid,
		int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	void syscall_getpeername(UUID syscallUUID, int pid,
		int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	void syscall_listen(UUID syscallUUID, int pid,
		int sockfd, int backlog);


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
