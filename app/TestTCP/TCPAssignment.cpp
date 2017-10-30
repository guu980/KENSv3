/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee, Minkyu Jo, Joonhyung Shin
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/E_TimeUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem()),
		sock_set(), conn_map(), listen_map(), ip_set(), proc_table()
{

}

TCPAssignment::~TCPAssignment()
{
	for(auto sock : sock_set)
	{
		delete sock;
	}

	for(auto pid_pcb : proc_table)
	{
		delete pid_pcb.second;
	}
}

void TCPAssignment::initialize()
{
	srand(time(NULL));
}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	//fprintf(stderr, "System call %d, %lu at pid %d\n", param.syscallNumber,syscallUUID, pid);
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param3_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		this->syscall_connect(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				(socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	assert(fromModule == "IPv4");
	/* Packet arrived from IPv4 Module!
	 * (1) Read from packet local and remote addresses.
	 * (2) Forward the packet to corresponding TCPSocket.
	 * (3) Handle the packet according to the state of the socket.
	 */

	const size_t ip_start = 14;  /* Size of Ethernet header */

	uint8_t ihl_buffer;
	uint16_t tot_buffer;
	packet->readData(ip_start, &ihl_buffer, 1);
	packet->readData(ip_start + 2, &tot_buffer, 2);
	size_t ihl = (ihl_buffer & 0x0f) * 4;  /* Size of the IP header */
	size_t tot_len = ntohs(tot_buffer);

	size_t tcp_start = ip_start + ihl;
	uint32_t ip_buffer;
	uint16_t port_buffer;

	packet->readData(ip_start + 12, &ip_buffer, 4);
	packet->readData(tcp_start + 0, &port_buffer, 2);
	in_addr_t remote_ip = (in_addr_t)ntohl(ip_buffer);
	in_port_t remote_port = (in_port_t)ntohs(port_buffer);
	sockaddr remote_addr = pack_addr(remote_ip, remote_port);

	packet->readData(ip_start + 16, &ip_buffer, 4);
	packet->readData(tcp_start + 2, &port_buffer, 2);
	in_addr_t local_ip = (in_addr_t)ntohl(ip_buffer);
	in_port_t local_port = (in_port_t)ntohs(port_buffer);
	sockaddr local_addr = pack_addr(local_ip, local_port);

	TCPSocket *sock;
	TCPContext context(local_addr, remote_addr);

	auto sock_it = conn_map.find(context);
	if(sock_it != conn_map.end())
	{
		sock = sock_it->second;
	}
	else
	{
		auto addr_sock_it = listen_map.find({ INADDR_ANY, local_port });
		if(addr_sock_it == listen_map.end())
			addr_sock_it = listen_map.find({ local_ip, local_port });

		if(addr_sock_it == listen_map.end())
		{
			this->freePacket(packet);

			return;
		}

		sock = addr_sock_it->second;
	}

	uint32_t seq_num;
	packet->readData(tcp_start + 4, &seq_num, 4);
	seq_num = ntohl(seq_num);
	uint32_t ack_num;
	packet->readData(tcp_start + 8, &ack_num, 4);
	ack_num = ntohl(ack_num);

	uint8_t data_ofs_ns;
	packet->readData(tcp_start + 12, &data_ofs_ns, 1);
	size_t data_ofs = tcp_start + (data_ofs_ns >> 4) * 4;
	size_t data_len = ip_start + tot_len - data_ofs;

	uint8_t flag;
	packet->readData(tcp_start + 13, &flag, 1);

	this->freePacket(packet);

	switch(sock->state)
	{
		case ST_READY: 		/* Socket is ready. */
		case ST_BOUND:		/* Socket is bound. */
			break;

		case ST_LISTEN:		/* Connect ready. Only for server. */
			assert(sock->listen != nullptr);

			if((int)sock->listen->pending_map.size() < sock->listen->backlog && (flag & SYN))
			{
				auto conn_sock = createSocket(sock->getHostPCB(), sock->domain);
				conn_sock->state = ST_SYN_RCVD;
				conn_sock->context = context;
				conn_sock->trans = new TransmissionModule();
				conn_sock->trans->seq_num = rand_seq_num();
				conn_sock->trans->ack_num = seq_num + 1;

				conn_map[context] = conn_sock;
				sock->listen->pending_map[context] = conn_sock;
				add_addr(local_ip, local_port);

				sendPacket("IPv4", make_packet(conn_sock, SYN | ACK));

				conn_sock->trans->seq_num++;
			}
			break;

		case ST_SYN_SENT:	/* 3-way handshake, client. */

			if((flag & SYN) && (flag & ACK))
			{
				auto pcb = sock->getHostPCB();

				assert(pcb->blocked && pcb->syscall == CONNECT);

				if(ack_num != sock->trans->seq_num)
				{
					// connect fail
					sock->state = ST_BOUND;

					this->returnSystemCall(pcb->syscallUUID, -1);
					pcb->unblockSyscall();
					break;
				}

				sock->trans->ack_num = seq_num + 1;

				sendPacket("IPv4", make_packet(sock, ACK));

				sock->state = ST_ESTAB;

				this->returnSystemCall(pcb->syscallUUID, 0);
				pcb->unblockSyscall();
			}
			else if(flag & SYN)
			{
				sock->trans->ack_num = seq_num + 1;

				sendPacket("IPv4", make_packet(sock, ACK));

				sock->state = ST_SYN_RCVD_SIM;
			}
			else
			{
				auto pcb = sock->getHostPCB();

				assert(pcb->blocked && pcb->syscall == CONNECT);

				sock->state = ST_BOUND;

				this->returnSystemCall(pcb->syscallUUID, -1);
				pcb->unblockSyscall();
			}
			break;

		case ST_SYN_RCVD:	/* 3-way handshake, server. */
			if(flag & ACK)
			{
				auto pcb = sock->getHostPCB();

				auto listen_it = listen_map.find({ INADDR_ANY, local_port });
				if(listen_it == listen_map.end())
					listen_it = listen_map.find({ local_ip, local_port });

				assert(listen_it != listen_map.end());

				auto listen_sock = listen_it->second;
				assert(listen_sock->listen->pending_map.find(context)
					   != listen_sock->listen->pending_map.end());

				if(ack_num != sock->trans->seq_num)
				{
					listen_sock->listen->pending_map.erase(context);
					conn_map.erase(context);
					remove_addr(local_ip, local_port);

					destroySocket(sock);

					break;
				}

				sock->state = ST_ESTAB;

				listen_sock->listen->pending_map.erase(context);

				if(pcb->blocked)
				{
					assert(pcb->syscall == ACCEPT);

					int connfd = this->createFileDescriptor(pcb->getpid());

					if(connfd != -1)
					{
						auto &param = pcb->param.acceptParam;
						pcb->fd_info.insert({ connfd, sock });

						*param.addr = remote_addr;
						*param.addrlen = sizeof(*param.addr);
					}

					this->returnSystemCall(pcb->syscallUUID, connfd);
					pcb->unblockSyscall();
				}
				else
					listen_sock->listen->accept_queue.push(sock);
			}
			break;

		case ST_SYN_RCVD_SIM:
			if(flag & ACK)
			{
				auto pcb = sock->getHostPCB();

				assert(pcb->blocked && pcb->syscall == CONNECT);

				if(ack_num != sock->trans->seq_num)
				{
					// connect fail
					this->returnSystemCall(pcb->syscallUUID, -1);
					sock->state = ST_BOUND;
					break;
				}

				sock->state = ST_ESTAB;

				this->returnSystemCall(pcb->syscallUUID, 0);
				pcb->unblockSyscall();
			}
			else
			{
				auto pcb = sock->getHostPCB();

				assert(pcb->blocked && pcb->syscall == CONNECT);

				this->returnSystemCall(pcb->syscallUUID, -1);
				sock->state = ST_BOUND;
			}
			break;

		case ST_ESTAB:		/* Connection established. */
			if(flag & FIN)
			{
				sock->trans->ack_num = seq_num + 1;

				this->sendPacket("IPv4", make_packet(sock, ACK));

				sock->state = ST_CLOSE_WAIT;
			}
			else
				;//assert(0);  '// Read/Write not implemented!'
			break;

		case ST_FIN_WAIT_1:	/* 4-way handshake, active close. */
			if(flag & ACK)
			{
				if(ack_num != sock->trans->seq_num)
					break;

				sock->state = ST_FIN_WAIT_2;
			}
			else if(flag & FIN)
			{
				sock->trans->ack_num = seq_num + 1;

				this->sendPacket("IPv4", make_packet(sock, ACK));

				sock->state = ST_CLOSING;
			}
			break;

		case ST_FIN_WAIT_2:
			if(flag & FIN)
			{
				sock->trans->ack_num = seq_num + 1;

				this->sendPacket("IPv4", make_packet(sock, ACK));

				sock->state = ST_TIME_WAIT;

				this->addTimer(sock, TimeUtil::makeTime(4, TimeUtil::MINUTE));
			}
			break;

		case ST_TIME_WAIT:
		case ST_CLOSE_WAIT:	/* 4-way handshake, passive close. */
			/* If the peer resends the packet, then we should resend ACK too,
			   but this is not implemented here. */
			break;

		case ST_LAST_ACK:
			if(flag & ACK)
			{
				if(ack_num != sock->trans->seq_num)
				{
					break;
				}

				conn_map.erase(sock->context);
				remove_addr(local_ip, local_port);

				destroySocket(sock);
			}
			break;

		case ST_CLOSING:	/* Recieved FIN after sending FIN. */
			if(flag & ACK)
			{
				if(ack_num != sock->trans->seq_num)
					break;

				sock->state = ST_TIME_WAIT;

				this->addTimer(sock, TimeUtil::makeTime(4, TimeUtil::MINUTE));
			}
			break;

		default:
			assert(0);
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	auto sock = (TCPSocket *)payload;

	assert(sock->state == ST_TIME_WAIT);

	in_addr_t local_ip;
	in_port_t local_port;
	std::tie(local_ip, local_port) = unpack_addr(sock->context.local_addr);

	conn_map.erase(sock->context);
	remove_addr(local_ip, local_port);

	destroySocket(sock);
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid,
		int domain, int protocol)
{
	if(protocol != IPPROTO_TCP)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	int fd = this->createFileDescriptor(pid);

	if(fd != -1)
	{
		auto pcb = getPCBEntry(pid);
		pcb->fd_info.insert({ fd, createSocket(pcb, domain) });
	}

	this->returnSystemCall(syscallUUID, fd);
}

/* Need to be updated */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid,
	int fd)
{
	auto pcb = getPCBEntry(pid);
	auto &fd_info = pcb->fd_info;

	auto sock_it = fd_info.find(fd);
	if(sock_it == fd_info.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	if(sock->state == ST_ESTAB)
	{
		sock->trans->ack_num = 0;

		this->sendPacket("IPv4", make_packet(sock, FIN));

		sock->trans->seq_num++;
		sock->state = ST_FIN_WAIT_1;
	}
	else if(sock->state == ST_CLOSE_WAIT)
	{
		sock->trans->ack_num = 0;

		this->sendPacket("IPv4", make_packet(sock, FIN));

		sock->trans->seq_num++;
		sock->state = ST_LAST_ACK;
	}
	else
	{
		if(sock->state == ST_BOUND || sock->state == ST_LISTEN)
		{
			in_addr_t ip;
			in_port_t port;
			std::tie(ip, port) = unpack_addr(sock->context.local_addr);

			if(sock->state == ST_LISTEN)
			{
				for(auto context_sock : sock->listen->pending_map)
				{
					auto conn_sock = context_sock.second;

					this->sendPacket("IPv4", make_packet(conn_sock, FIN));

					conn_sock->trans->seq_num++;
					conn_sock->state = ST_FIN_WAIT_1;
				}

				while(!sock->listen->accept_queue.empty())
				{
					auto conn_sock = sock->listen->accept_queue.front();
					sock->listen->accept_queue.pop();

					this->sendPacket("IPv4", make_packet(conn_sock, FIN));

					conn_sock->trans->seq_num++;
					conn_sock->state = ST_FIN_WAIT_1;
				}

				listen_map.erase(unpack_addr(sock->context.local_addr));
			}

			remove_addr(ip, port);
		}

		destroySocket(sock);
	}

	fd_info.erase(sock_it);

	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	auto &fd_info = getPCBEntry(pid)->fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state != ST_READY)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	in_addr_t ip;
	in_port_t port;
	std::tie(ip, port) = unpack_addr(*addr);

	if(ip_set.find(port) != ip_set.end()
		&& ((ip == INADDR_ANY && !ip_set[port].empty())
			|| ip_set[port].find(INADDR_ANY) != ip_set[port].end()
			|| ip_set[port].find(ip) != ip_set[port].end()))
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	sock->context.local_addr = pack_addr(ip, port);
	sock->state = ST_BOUND;
	add_addr(ip, port);

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto &fd_info = getPCBEntry(pid)->fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state == ST_READY)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	*addr = sock->context.local_addr;
	*addrlen = (socklen_t)sizeof(*addr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto pcb = getPCBEntry(pid);
	auto &fd_info = pcb->fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end()
		|| (sock_it->second->state != ST_LISTEN
			&& sock_it->second->state != ST_SYN_RCVD))
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	auto &accept_queue = sock->listen->accept_queue;

	if(accept_queue.empty())
	{
		PCBEntry::syscallParam param;
		param.acceptParam = { sockfd, addr, addrlen };
		pcb->blockSyscall(ACCEPT, syscallUUID, param);
		return;
	}

	int connfd = this->createFileDescriptor(pid);
	if(connfd != -1)
	{
		auto sock_accept = accept_queue.front(); accept_queue.pop();

		fd_info.insert({ connfd, sock_accept });

		*addr = sock_accept->context.remote_addr;
		*addrlen = sizeof(*addr);
	}

	this->returnSystemCall(syscallUUID, connfd);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	auto pcb = getPCBEntry(pid);
	auto &fd_info = pcb->fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state == ST_ESTAB)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	in_addr_t remote_ip;
	in_port_t remote_port;
	std::tie(remote_ip, remote_port) = unpack_addr(*addr);
	sock->context.remote_addr = *addr;

	in_addr_t local_ip;
	in_port_t local_port;

	if(sock->state == ST_READY)
	{
		int table_port = this->getHost()->getRoutingTable((uint8_t *)&remote_ip);
		if(!this->getHost()->getIPAddr((uint8_t *)&local_ip, table_port))
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
		local_ip = be32toh(local_ip);

		while(true)
		{
			local_port = rand() % 65536;
			if(ip_set.find(local_port) == ip_set.end()
				|| (ip_set[local_port].find(INADDR_ANY) == ip_set[local_port].end()
					&& ip_set[local_port].find(local_ip) == ip_set[local_port].end()))
				break;
		}
		sock->context.local_addr = pack_addr(local_ip, local_port);
		sock->state = ST_BOUND;

		add_addr(local_ip, local_port);
	}
	else
		std::tie(local_ip, local_port) = unpack_addr(sock->context.local_addr);

	sock->trans = new TransmissionModule();
	sock->trans->seq_num = rand_seq_num();
	sock->trans->ack_num = 0;

	this->sendPacket("IPv4", make_packet(sock, SYN));

	sock->trans->seq_num++;
	sock->state = ST_SYN_SENT;

	conn_map[sock->context] = sock;

	PCBEntry::syscallParam param;
	param.connectParam = { sockfd, addr, addrlen };
	pcb->blockSyscall(CONNECT, syscallUUID, param);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto &fd_info = getPCBEntry(pid)->fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state != ST_ESTAB)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	*addr = sock->context.remote_addr;
	*addrlen = (socklen_t)sizeof(sock->context.remote_addr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid,
	int sockfd, int backlog)
{
	auto &fd_info = getPCBEntry(pid)->fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state != ST_BOUND)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	sock->state = ST_LISTEN;
	sock->listen = new ListenModule(backlog);
	listen_map[unpack_addr(sock->context.local_addr)] = sock;

	this->returnSystemCall(syscallUUID, 0);
}

Packet *TCPAssignment::make_packet(TCPSocket *sock, uint8_t flag)
{
	TCPContext &context = sock->context;
	in_addr_t local_ip, remote_ip;
	in_port_t local_port, remote_port;
	std::tie(local_ip, local_port) = unpack_addr(context.local_addr);
	std::tie(remote_ip, remote_port) = unpack_addr(context.remote_addr);

	size_t ip_start = 14;
	size_t tcp_start = 34;
	size_t data_ofs = 20;

	Packet *packet = this->allocatePacket(tcp_start + data_ofs);

	uint32_t ip_buffer = htonl(local_ip);
	packet->writeData(ip_start + 12, &ip_buffer, 4);
	ip_buffer = htonl(remote_ip);
	packet->writeData(ip_start + 16, &ip_buffer, 4);

	uint16_t port_buffer = htons(local_port);
	packet->writeData(tcp_start + 0, &port_buffer, 2);
	port_buffer = htons(remote_port);
	packet->writeData(tcp_start + 2, &port_buffer, 2);

	uint8_t new_data_ofs_ns = 5 << 4;
	uint16_t window_size = htons(51200);
	packet->writeData(tcp_start + 12, &new_data_ofs_ns, 1);
	packet->writeData(tcp_start + 14, &window_size, 2);
	packet->writeData(tcp_start + 13, &flag, 1);

	uint32_t new_seq_num = htonl(sock->trans->seq_num);
	packet->writeData(tcp_start + 4, &new_seq_num, 4);

	uint32_t new_ack_num = htonl(sock->trans->ack_num);
	packet->writeData(tcp_start + 8, &new_ack_num, 4);

	uint8_t tcp_header_buffer[20];
	packet->readData(tcp_start, tcp_header_buffer, 20);
	uint16_t checksum = NetworkUtil::tcp_sum(htonl(local_ip), htonl(remote_ip), tcp_header_buffer, 20);
	checksum = ~checksum;
	checksum = htons(checksum);
	packet->writeData(tcp_start + 16, (uint8_t *)&checksum, 2);

	return packet;
}

TCPAssignment::PCBEntry *TCPAssignment::getPCBEntry(int pid)
{
	if(proc_table.find(pid) == proc_table.end())
		proc_table[pid] = new PCBEntry(pid);
	return proc_table[pid];
}

TCPAssignment::TCPSocket *TCPAssignment::createSocket(PCBEntry *pcb, int domain)
{
	auto sock = new TCPSocket(pcb, domain);
	sock_set.insert(sock);
	return sock;
}

void TCPAssignment::destroySocket(TCPSocket *sock)
{
	sock_set.erase(sock);
	delete sock;
}

void TCPAssignment::add_addr(in_addr_t ip, in_port_t port)
{
	ip_set[port][ip]++;
}

void TCPAssignment::remove_addr(in_addr_t ip, in_port_t port)
{
	ip_set[port][ip]--;
	if(!ip_set[port][ip])
	{
		ip_set[port].erase(ip);
		if(ip_set[port].empty())
			ip_set.erase(port);
	}
}


TCPAssignment::TCPContext::TCPContext() : seq_num(), ack_num()
{
	memset(&this->local_addr, 0, sizeof(this->local_addr));
	memset(&this->remote_addr, 0, sizeof(this->local_addr));
}
TCPAssignment::TCPContext::TCPContext(sockaddr local_addr, sockaddr remote_addr) : local_addr(local_addr), remote_addr(remote_addr), seq_num(), ack_num()
{

}
TCPAssignment::TCPContext::~TCPContext()
{

}


TCPAssignment::ListenModule::ListenModule(int backlog) : pending_map(), accept_queue(), backlog(backlog)
{

}
TCPAssignment::ListenModule::~ListenModule()
{

}

TCPAssignment::TransmissionModule::TransmissionModule()
{

}
TCPAssignment::TransmissionModule::~TransmissionModule()
{

}

TCPAssignment::DataBuffer::DataBuffer(size_t size) : buffer(size), ofs()
{

}
TCPAssignment::DataBuffer::~DataBuffer()
{

}

TCPAssignment::TCPSocket::TCPSocket(PCBEntry *pcb, int domain) : context()
{
	this->pcb = pcb;
	this->domain = domain;
	this->state = ST_READY;
	this->listen = nullptr;
	this->trans = nullptr;
}
TCPAssignment::TCPSocket::~TCPSocket()
{
	delete listen;
	delete trans;
}
TCPAssignment::PCBEntry *TCPAssignment::TCPSocket::getHostPCB()
{
	return this->pcb;
}

TCPAssignment::PCBEntry::PCBEntry(int pid)
{
	this->pid = pid;
	this->fd_info.clear();
	this->blocked = false;
}
TCPAssignment::PCBEntry::~PCBEntry()
{

}
void TCPAssignment::PCBEntry::blockSyscall(enum SystemCall syscall, UUID syscallUUID, syscallParam &param)
{
	this->blocked = true;
	this->syscall = syscall;
	this->syscallUUID = syscallUUID;
	switch(syscall)
	{
		case CLOSE:
			this->param.closeParam = param.closeParam;
			break;
		case ACCEPT:
			this->param.acceptParam = param.acceptParam;
			break;
		case CONNECT:
			this->param.connectParam = param.connectParam;
			break;
		default:
			assert(0);
	}
}
void TCPAssignment::PCBEntry::unblockSyscall()
{
	this->blocked = false;
}
int TCPAssignment::PCBEntry::getpid()
{
	return this->pid;
}


uint32_t TCPAssignment::rand_seq_num()
{
	return rand();
}

std::pair<in_addr_t, in_port_t> TCPAssignment::unpack_addr(sockaddr addr)
{
	return { ntohl(((sockaddr_in *)&addr)->sin_addr.s_addr), ntohs(((sockaddr_in *)&addr)->sin_port) };
}

sockaddr TCPAssignment::pack_addr(in_addr_t ip, in_port_t port)
{
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(ip);
	return *(sockaddr *)(&addr);
}

}
