/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee, Minkyu Jo, Joonhyung Shin
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

namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

	const static int MAX_PORT_NUM = 65536;

	const static int NS = 1 << 8;
	const static int CWR = 1 << 7;
	const static int ECE = 1 << 6;
	const static int URG = 1 << 5;
	const static int ACK = 1 << 4;
	const static int PSH = 1 << 3;
	const static int RST = 1 << 2;
	const static int SYN = 1 << 1;
	const static int FIN = 1 << 0;

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

	enum TCPTimer
	{
		TM_RETRANSMIT,		/* Retransmission Timer. */
		TM_PERSISTENCE,		/* Persistence Timer. */
		TM_KEEPALIVE,		/* Keepalive Timer. */
		TM_TIME_WAIT		/* TIME_WAIT Timer. */
	};

	class TCPContext
	{
	public:
		sockaddr local_addr;
		sockaddr remote_addr;

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

	class TimerPayload
	{
	public:
		enum TCPTimer type;
		Time sent;
		Time timeAfter;
		UUID timerUUID;

		TCPSocket *sock;
		uint32_t seq;
		Packet *packet;

		TimerPayload(enum TCPTimer type);
		~TimerPayload();
	};

	class ListenModule
	{
	public:
		std::unordered_map<TCPContext, TCPSocket *, ContextHash> pending_map;
		std::queue<TCPSocket *> accept_queue;
		int backlog;

		ListenModule(int backlog);
		~ListenModule();
	};

	class PacketReader
	{
	private:
		Packet *packet;

		const size_t ip_start = 14;
		size_t tcp_start;
		size_t data_start;
		size_t data_len;

	public:
		PacketReader(Packet *packet);
		~PacketReader();
		in_addr_t readIPAddress(bool src);
		in_port_t readPort(bool src);
		void recvAddress(TCPContext &context);
		uint32_t readSeqNum();
		uint32_t readAckNum();
		uint16_t readFlag();
		size_t readWindowSize();
		size_t readData(size_t offset, void *buf, size_t count);

		size_t getDataLen();
		size_t getSegmentLen();
		uint32_t getNextSeqNum();
	};

	class PacketWriter
	{
	private:
		Packet *packet;

		const size_t ip_start = 14;
		size_t tcp_start;
		size_t data_start;
		size_t data_len;

	public:
		PacketWriter(Packet *packet, size_t ihl, size_t thl, size_t data_len);
		~PacketWriter();
		void writeIPAddress(bool src, in_addr_t ip);
		void writePort(bool src, in_port_t port);
		void sendAddress(TCPContext &context);
		void writeSeqNum(uint32_t seq_num);
		void writeAckNum(uint32_t ack_num);
		void writeFlag(uint16_t flag);
		void writeWindowSize(size_t rwnd);
		size_t writeData(size_t offset, const void *buf, size_t count);
		void writeChecksum();
	};

	class TransmissionModule
	{
	public:
		const uint32_t SEQ_MAX = UINT32_MAX;
		const size_t RWND_MAX = UINT16_MAX;
		const Real alpha = 0.125;
		const Real beta = 0.25;

		/*************************/
		/***  Sending Module.  ***/
		/*************************/
		uint32_t seq_num;
		size_t mss;		/* Maximum segment size. */
		size_t rwnd;	/* Receiver window size. */
		size_t cwnd;	/* Congestion window size. */
		size_t ssthresh;	/* Slow start threshold. */
		uint32_t rt_start_seq;
		bool rtt_passed;
		Real estimate_rtt;	/* Estimated RTT in nanoseconds. */
		Real dev_rtt;		/* Deviation RTT in nanoseconds. */
		Time timeout;		/* Timeout in nanoseconds. */
		int dup_ack_cnt;
		std::queue<TimerPayload *> in_flight;

		/*************************/
		/*** Receiving Module. ***/
		/*************************/

		/*
		 *    awnd
		 *  -------------->            <-----------
		 *  +--------------+----------+-----------+
		 *  |Pv4 Module ///|  To App  |//// From I|
		 *  +--------------+----------+-----------+
		 *                            ^
		 *                        rcv_base
		 */
		uint32_t ack_num;
		uint8_t *rcv_buf;
		size_t rcv_size;
		size_t awnd;		/* Advertising window size. */
		size_t rcv_base;
		std::unordered_map<uint32_t, uint32_t> unacked;

		bool fin_rcvd;
		uint32_t fin_seq;	/* Sequence number which FIN was received. */

		TransmissionModule(size_t rcv_size);
		~TransmissionModule();

		uint32_t getLastAcked();
		void calcTimeout(Time current);
		void increaseCWND();
		void decreaseCWND(bool fast);
		size_t senderAvailable();

		bool inRcvdWindow(uint32_t seq);
		bool isValidSegment(uint32_t seq, size_t seg_len);
		size_t readData(void *buf, size_t count);
		void recvData(PacketReader &reader);
	};

	class TCPSocket
	{
	private:
		PCBEntry *pcb;
	public:
		int domain;		/* This is always AF_INET in KENSv3. */
		enum TCPState state;
		TCPContext context;

		ListenModule *listen;	/* Only used for LISTENing. */
		TransmissionModule *trans;	/* Only used for peer-peer communication. */

		TCPSocket(PCBEntry *pcb, int domain);
		~TCPSocket();
		PCBEntry *getHostPCB();
	};

	size_t writeData(TCPSocket *sock, const void *buf, size_t count);
	size_t readData(TCPSocket *sock, void *buf, size_t count);
	void transmitPacket(TCPSocket *sock, Packet *packet, size_t seg_len);
	void recvPacket(TCPSocket *sock, PacketReader &reader);
	void listenPacket(TCPSocket *sock, PacketReader &reader);
	void retransmit(TimerPayload *payload, bool fast);
	void resetConnection(TCPContext &context, uint32_t seq_num, uint32_t ack_num);

	void closeListen(TCPSocket *sock);
	void closeTransmission(TCPSocket *sock);

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
			struct
			{
				int fd;
				void *buf;
				size_t count;
			} readParam;
			struct
			{
				int fd;
				const void *buf;
				size_t count;
			} writeParam;
		} param;

		PCBEntry(int pid);
		~PCBEntry();
		void blockSyscall(enum SystemCall syscall, UUID syscallUUID, syscallParam &param);
		void unblockSyscall();
		int getpid();
	};

	std::unordered_set<TCPSocket *> sock_set;
	std::unordered_map<UUID, TimerPayload *> timer_map;

	std::unordered_set<Packet *> packet_set;

	std::unordered_map<TCPContext, TCPSocket *, ContextHash> conn_map;
	std::unordered_map<std::pair<in_addr_t, in_port_t>, TCPSocket *> listen_map;
	std::unordered_map<in_port_t, std::unordered_map<in_addr_t, size_t>> ip_set;
	std::unordered_map<int, PCBEntry *> proc_table;

	TCPSocket *createSocket(PCBEntry *pcb, int domain);
	void destroySocket(TCPSocket *sock);

	UUID setTimeout(TimerPayload *payload, Time timeAfter);
	void clearTimeout(UUID timerUUID);

	void add_addr(in_addr_t ip, in_port_t port);
	void remove_addr(in_addr_t ip, in_port_t port);

	TCPSocket *findListenSocket(in_addr_t ip, in_port_t port);

	static uint32_t rand_seq_num();
	static bool inSegment(uint32_t seq_begin, uint32_t seq_end, uint32_t seq);

	Packet *make_packet(TCPSocket *sock, uint16_t flag, const void *buf, size_t count);

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

	void syscall_read(UUID syscallUUID, int pid,
		int fd, void *buf, size_t count);
	void syscall_write(UUID syscallUUID, int pid,
		int fd, const void *buf, size_t count);

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
