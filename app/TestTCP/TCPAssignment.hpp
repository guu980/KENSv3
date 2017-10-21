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
#include <functional>

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

	const static int MAX_PORT_NUM = 65536;

	const int ACK = 1 << 4;
	const int RST = 1 << 2;
	const int SYN = 1 << 1;
	const int FIN = 1 << 0;

	enum TCPState
	{
		ST_READY, 			/* Socket is ready. */
		ST_BOUND,			/* Socket is bound. */
		ST_LISTEN,			/* Connect ready. Only for server. */
		ST_SYN_SENT,		/* 3-way handshake, client. */
		ST_SYN_RCVD,		/* 3-way handshake, server. */
		ST_SYN_RCVD_SIM,	/* Simultaneous connect. */
		ST_ESTAB,			/* Connection established. */

		ST_FIN_WAIT_1,		/* 4-way handshake, active close. */
		ST_FIN_WAIT_2,
		ST_TIME_WAIT,
		ST_CLOSE_WAIT,		/* 4-way handshake, passive close. */
		ST_LAST_ACK,

		ST_CLOSING			/* Recieved FIN after sending FIN. */
	};

	class TCPContext
	{
	public:
		sockaddr local_addr;
		sockaddr remote_addr;
		uint32_t seq_num;
		uint32_t ack_num;

		bool operator==(const TCPContext &context) const
		{
			return unpack_addr(local_addr) == unpack_addr(context.local_addr)
			&& unpack_addr(remote_addr) == unpack_addr(context.remote_addr);
		}

		TCPContext();
		TCPContext(sockaddr local_addr, sockaddr remote_addr);
		~TCPContext();
	};

	static std::pair<in_addr_t, in_port_t> unpack_addr(sockaddr addr);
	static sockaddr pack_addr(in_addr_t ip, in_port_t port);

	struct ContextHash
	{
		std::size_t operator()(const TCPContext &context) const
		{
			std::size_t h1 = std::hash<std::pair<in_addr_t, in_port_t>>{}(unpack_addr(context.local_addr));
			std::size_t h2 = std::hash<std::pair<in_addr_t, in_port_t>>{}(unpack_addr(context.remote_addr));
			return h1 ^ (h2 << 1);
		}
	};

	class PCBEntry;
	class TCPSocket;

	class ListenModule
	{
	public:
		sockaddr listen_addr;

		std::unordered_map<TCPContext, TCPSocket *, ContextHash> pending_map;
		std::queue<TCPSocket *> accept_queue;
		int backlog;

		ListenModule(sockaddr listen_addr, int backlog);
		~ListenModule();
	};

	class TCPSocket
	{
	private:
		PCBEntry *pcb;
	public:
		int domain;		/* This is always AF_INET in KENSv3. */
		enum TCPState state;
		TCPContext context;
		uint32_t seq_num;
		uint32_t ack_num;

		//std::queue<Packet *> temp_buffer;

		ListenModule *listen;	/* Only used for LISTENing. */

		TCPSocket(PCBEntry *pcb, int domain);
		~TCPSocket();
		PCBEntry *getHostPCB();
	};

	class PCBEntry
	{
	private:
		int pid;
	public:
		std::unordered_map<int, TCPSocket *> fd_info;

		bool blocked;
		enum SystemCall syscall;
		UUID syscallUUID;
		union syscallParam
		{
			struct
			{
				int fd;
			} closeParam;
			struct
			{
				int sockfd;
				struct sockaddr *addr;
				socklen_t *addrlen;
			} acceptParam;
			struct
			{
				int sockfd;
				const struct sockaddr *addr;
				socklen_t addrlen;
			} connectParam;
		} param;

		PCBEntry(int pid);
		~PCBEntry();
		void blockSyscall(enum SystemCall syscall, UUID syscallUUID, syscallParam &param);
		void unblockSyscall();
		int getpid();
	};

	std::unordered_map<TCPContext, TCPSocket *, ContextHash> conn_map;
	std::unordered_map<std::pair<in_addr_t, in_port_t>, TCPSocket *> listen_map;
	std::unordered_map<in_port_t, std::unordered_map<in_addr_t, size_t>> ip_set;
	std::unordered_map<int, PCBEntry *> proc_table;

	void add_addr(in_addr_t ip, in_port_t port);
	void remove_addr(in_addr_t ip, in_port_t port);

	uint32_t rand_seq_num();

	Packet *make_packet(TCPSocket *sock, uint8_t flag);

	PCBEntry *getPCBEntry(int pid);

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
