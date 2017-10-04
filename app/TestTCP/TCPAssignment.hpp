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

	enum TCPState
	{
		ST_READY, 		/* Socket is ready. */
		ST_BOUND,		/* Socket is bound. */
		ST_LISTEN,		/* Connect ready. Only for server. */
		ST_SYN_SENT,	/* 3-way handshake, client. */
		ST_SYN_RCVD,	/* 3-way handshake, server. */
		ST_ESTAB,		/* Connection established. */

		ST_FIN_WAIT_1,	/* 4-way handshake, active close. */
		ST_FIN_WAIT_2,
		ST_TIME_WAIT,
		ST_CLOSE_WAIT,	/* 4-way handshake, passive close. */
		ST_LAST_ACK,

		ST_CLOSING		/* Recieved FIN after sending FIN. */
	};

	class PassiveQueue
	{
	public:
		std::queue<Packet *> listen_queue;
		std::queue<std::pair<struct sockaddr_in, struct sockaddr_in>> accept_queue;
		int backlog;

		PassiveQueue(int backlog);
		~PassiveQueue();
	};

	class TCPSocket
	{
	public:
		int domain;		/* This is always AF_INET in KENSv3. */
		enum TCPState state;
		struct sockaddr_in local_addr;
		struct sockaddr_in remote_addr;

		PassiveQueue *queues;	/* Only used for LISTENing. */

		TCPSocket(int domain);
		~TCPSocket();
		void setLocalAddr(in_addr_t addr, in_port_t port);
		void setRemoteAddr(in_addr_t addr, in_port_t port);
		void handlePacket(Packet *packet);
	};

	class PCBEntry
	{
	public:
		std::unordered_map<int, TCPSocket> fd_info;

		bool blocked;
		enum SystemCall syscall;
		union blocked_syscall {
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
		};

		PCBEntry();
		~PCBEntry();
	};
	
	std::unordered_map<in_addr_t, std::pair<int, int>> ip_set[MAX_PORT_NUM];
	std::unordered_map<int, PCBEntry> proc_table;

	static inline std::pair<in_addr_t, in_port_t> addr_ip_port(struct sockaddr_in *addr)
	{
		return { ntohl(addr->sin_addr.s_addr), ntohs(addr->sin_port) };
	}

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
