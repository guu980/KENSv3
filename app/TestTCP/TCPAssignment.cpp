/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/E_TimeUtil.hpp>
#include "TCPAssignment.hpp"

#include <tuple>
#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <ctime>

#define VOID_RETURN 0

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{
	/* Perhaps we can believe STL? */
	proc_table.clear();
	ip_set.clear();
	srand(time(NULL));
}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
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
	packet->readData(ip_start, &ihl_buffer, 1);
	size_t ihl = (ihl_buffer & 0x0f) * 4;  /* Size of the IP header */

	size_t tcp_start = ip_start + ihl;
	uint32_t ip_buffer;
	uint16_t port_buffer;

	packet->readData(ip_start + 12, &ip_buffer, 4);
	packet->readData(tcp_start + 0, &port_buffer, 2);
	in_addr_t remote_ip = (in_addr_t)ntohl(ip_buffer);
	in_port_t remote_port = (in_port_t)ntohs(port_buffer);
	sockaddr remote_addr = tie_addr(remote_ip, remote_port);

	packet->readData(ip_start + 16, &ip_buffer, 4);
	packet->readData(tcp_start + 2, &port_buffer, 2);
	in_addr_t local_ip = (in_addr_t)ntohl(ip_buffer);
	in_port_t local_port = (in_port_t)ntohs(port_buffer);
	sockaddr local_addr = tie_addr(local_ip, local_port);

	auto ip_it = ip_set.find(local_port);
	if (ip_it == ip_set.end())
	{
		this->freePacket(packet);
		return;
	}
	auto &sock_map = ip_it->second;
	auto addr_sock_it = sock_map.find(INADDR_ANY);
	if(addr_sock_it == sock_map.end())
		addr_sock_it = sock_map.find(local_ip);
	if(addr_sock_it == sock_map.end())
	{
		this->freePacket(packet);
		return;
	}

	int pid, fd;
	std::tie(pid, fd) = addr_sock_it->second;
	auto &pcb = proc_table[pid];
	auto sock = pcb.fd_info[fd];

	if (sock->state == ST_LISTEN || sock->state == ST_SYN_RCVD)
	{
		auto accept_it = sock->queue->accept_map.find({ remote_ip, remote_port });
		if (accept_it != sock->queue->accept_map.end())
			sock = accept_it->second;
	}

	uint32_t seq_num;
	packet->readData(tcp_start + 4, &seq_num, 4);
	seq_num = ntohl(seq_num);
	uint32_t ack_num;
	packet->readData(tcp_start + 8, &ack_num, 4);
	ack_num = ntohl(ack_num);

	uint8_t data_ofs_ns;
	packet->readData(tcp_start + 12, &data_ofs_ns, 1);
	//size_t data_ofs = (data_ofs_ns >> 4) * 4;

	uint8_t flag;
	packet->readData(tcp_start + 13, &flag, 1);

	switch(sock->state)
	{
		case ST_READY: 		/* Socket is ready. */
			this->freePacket(packet);
			break;

		case ST_BOUND:		/* Socket is bound. */
			this->freePacket(packet);
			break;

		case ST_LISTEN:		/* Connect ready. Only for server. */
			this->freePacket(packet);
			if(flag & SYN)
			{
				sock->context.local_addr = local_addr;
				sock->context.remote_addr = remote_addr;
				sock->context.seq_num = rand_seq_num();
				sock->context.ack_num = seq_num + 1;

				sendPacket("IPv4", make_packet(sock->context, SYN | ACK));

				sock->state = ST_SYN_RCVD;
			}
			break;

		case ST_SYN_SENT:	/* 3-way handshake, client. */
			this->freePacket(packet);
			if( untie_addr(sock->context.local_addr) == std::make_pair(local_ip, local_port) &&
				untie_addr(sock->context.remote_addr) == std::make_pair(remote_ip, remote_port))
			{
				if((flag & SYN) && (flag & ACK))
				{
					if(ack_num != sock->context.seq_num + 1)
					{
						// connect fail
						this->returnSystemCall(pcb.syscallUUID, -1);
						sock->state = ST_BOUND;
						break;
					}

					sock->context.seq_num = 0;
					sock->context.ack_num = seq_num + 1;

					sendPacket("IPv4", make_packet(sock->context, ACK));

					assert(pcb.blocked && pcb.syscall == CONNECT);

					sock->state = ST_ESTAB;

					this->returnSystemCall(pcb.syscallUUID, 0);
					pcb.unblockSyscall();
				}
				else if(flag & SYN)
					;//assert(0);  // Simultaneous open not considered
			}
			break;

		case ST_SYN_RCVD:	/* 3-way handshake, server. */
			if( untie_addr(sock->context.local_addr) == std::make_pair(local_ip, local_port) &&
				untie_addr(sock->context.remote_addr) == std::make_pair(remote_ip, remote_port))
			{
				this->freePacket(packet);

				if(flag & ACK)
				{
					if(ack_num != sock->context.seq_num + 1)
					{
						break;
					}

					auto sock_accept = new TCPSocket(sock->domain);
					sock_accept->state = ST_ESTAB;
					sock_accept->context = sock->context;

					sock->queue->accept_map[{ remote_ip, remote_port }] = sock_accept;

					if(pcb.blocked)
					{
						assert(pcb.syscall == ACCEPT);
						int connfd = this->createFileDescriptor(pid);

						if (connfd != -1)
						{
							auto &param = pcb.param.acceptParam;
							pcb.fd_info.insert({ connfd, sock_accept });

							*param.addr = sock_accept->context.remote_addr;
							*param.addrlen = sizeof(*param.addr);
						}

						this->returnSystemCall(pcb.syscallUUID, connfd);
						pcb.unblockSyscall();
					}
					else
						sock->queue->accept_queue.push(sock_accept);

					sock->state = ST_LISTEN;

					if(!sock->queue->listen_queue.empty())
					{
						Packet *new_packet = sock->queue->listen_queue.front();
						sock->queue->listen_queue.pop();
						packetArrived("IPv4", new_packet);
					}
				}
			}
			else
			{
				if(flag & SYN)
				{
					if((int)sock->queue->listen_queue.size() + 1 < sock->queue->backlog)
					{
						Packet *new_packet = clonePacket(packet);
						sock->queue->listen_queue.push(new_packet);
					}
				}
				this->freePacket(packet);
			}
			break;

		case ST_ESTAB:		/* Connection established. */
			this->freePacket(packet);


			if( untie_addr(sock->context.local_addr) == std::make_pair(local_ip, local_port) &&
				untie_addr(sock->context.remote_addr) == std::make_pair(remote_ip, remote_port))
			{
				if (flag & FIN)
				{
					sock->context.seq_num = 0;
					sock->context.ack_num = seq_num + 1;

					this->sendPacket("IPv4", make_packet(sock->context, ACK));

					sock->state = ST_CLOSE_WAIT;
				}
				else
					;//assert(0);  '// Read/Write not implemented!'
			}
			break;

		case ST_FIN_WAIT_1:	/* 4-way handshake, active close. */
			this->freePacket(packet);
			if( untie_addr(sock->context.local_addr) == std::make_pair(local_ip, local_port) &&
				untie_addr(sock->context.remote_addr) == std::make_pair(remote_ip, remote_port))
			{
				if (flag & ACK)
				{
					if(ack_num != sock->context.seq_num + 1)
					{
						break;
					}

					assert(pcb.blocked && pcb.syscall == CLOSE);

					sock->state = ST_FIN_WAIT_2;
				}
				else if (flag & FIN)
				{
					sock->context.seq_num = 0;
					sock->context.ack_num = seq_num + 1;

					this->sendPacket("IPv4", make_packet(sock->context, ACK));

					sock->state = ST_CLOSING;
				}
			}
			break;
		case ST_FIN_WAIT_2:
			this->freePacket(packet);
			if( untie_addr(sock->context.local_addr) == std::make_pair(local_ip, local_port) &&
				untie_addr(sock->context.remote_addr) == std::make_pair(remote_ip, remote_port))
			{
				if (flag & FIN)
				{
					assert(pcb.blocked && pcb.syscall == CLOSE);

					sock->context.seq_num = 0;
					sock->context.ack_num = seq_num + 1;

					this->sendPacket("IPv4", make_packet(sock->context, ACK));

					sock->state = ST_TIME_WAIT;

					this->addTimer((void *)(new std::pair<int, int>(pid, pcb.param.closeParam.fd)), TimeUtil::makeTime(4, TimeUtil::MINUTE));
					this->returnSystemCall(pcb.syscallUUID, 0);
					pcb.unblockSyscall();
				}
			}
			break;
		case ST_TIME_WAIT:
		case ST_CLOSE_WAIT:	/* 4-way handshake, passive close. */
			/* Server and client should not receive anything. */
			this->freePacket(packet);
			break;
		case ST_LAST_ACK:
			this->freePacket(packet);
			if( untie_addr(sock->context.local_addr) == std::make_pair(local_ip, local_port) &&
				untie_addr(sock->context.remote_addr) == std::make_pair(remote_ip, remote_port))
			{
				if (flag & ACK)
				{
					assert(pcb.blocked && pcb.syscall == CLOSE);

					if(ack_num != sock->context.seq_num + 1)
					{
						break;
					}

					fd = pcb.param.closeParam.fd;
					pcb.fd_info.erase(fd);

					this->removeFileDescriptor(pid, fd);
					this->returnSystemCall(pcb.syscallUUID, 0);
					pcb.unblockSyscall();
				}
			}
			break;

		case ST_CLOSING:	/* Recieved FIN after sending FIN. */
			this->freePacket(packet);
			if( untie_addr(sock->context.local_addr) == std::make_pair(local_ip, local_port) &&
				untie_addr(sock->context.remote_addr) == std::make_pair(remote_ip, remote_port))
			{
				if (flag & ACK)
				{
					assert(pcb.blocked && pcb.syscall == CLOSE);

					if(ack_num != sock->context.seq_num + 1)
					{
						break;
					}

					sock->state = ST_TIME_WAIT;

					this->addTimer((void *)(new std::pair<int, int>(pid, pcb.param.closeParam.fd)), TimeUtil::makeTime(4, TimeUtil::MINUTE));
					this->returnSystemCall(pcb.syscallUUID, 0);
					pcb.unblockSyscall();
				}
			}
			break;

		default:
			assert(0);
	}
}

void TCPAssignment::timerCallback(void* payload)
{
	auto pid_fd = (std::pair<int, int> *) payload;
	int pid;
	int fd;
	std::tie(pid, fd) = *pid_fd;
	delete pid_fd;

	auto &pcb = proc_table[pid];
	auto sock = pcb.fd_info[fd];

	assert(sock->state == ST_TIME_WAIT);

	pcb.fd_info.erase(fd);
	delete sock;

	this->removeFileDescriptor(pid, fd);
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid,
		int domain, int protocol)
{
	if(domain != AF_INET || protocol != IPPROTO_TCP)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	int fd = this->createFileDescriptor(pid);

	if(fd != -1)
	{
		proc_table[pid].fd_info.insert({ fd, new TCPSocket(domain) });
	}

	this->returnSystemCall(syscallUUID, fd);
}

/* Need to be updated */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid,
	int fd)
{
	auto &pcb = proc_table[pid];
	auto &fd_info = pcb.fd_info;

	auto sock_it = fd_info.find(fd);
	if(sock_it == fd_info.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	if(sock->state == ST_ESTAB || sock->state == ST_SYN_RCVD)
	{
		sock->context.seq_num = rand_seq_num();
		sock->context.ack_num = 0;

		this->sendPacket("IPv4", make_packet(sock->context, FIN));

		sock->state = ST_FIN_WAIT_1;
	}
	else if(sock->state == ST_CLOSE_WAIT)
	{
		sock->context.seq_num = rand_seq_num();
		sock->context.ack_num = 0;

		this->sendPacket("IPv4", make_packet(sock->context, FIN));

		sock->state = ST_LAST_ACK;
	}
	else if(sock->state == ST_TIME_WAIT)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	else
	{
		if(sock->state == ST_BOUND || sock->state == ST_LISTEN)
		{
			in_addr_t ip;
			in_port_t port;
			std::tie(ip, port) = untie_addr(sock->context.local_addr);

			ip_set[port].erase(ip);
			if (ip_set[port].empty())
				ip_set.erase(port);
		}

		fd_info.erase(sock_it);

		this->removeFileDescriptor(pid, fd);
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	PCBEntry::syscallParam param;
	param.closeParam = { fd };
	pcb.blockSyscall(CLOSE, syscallUUID, param);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	auto &fd_info = proc_table[pid].fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state != ST_READY)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	in_addr_t ip;
	in_port_t port;
	std::tie(ip, port) = untie_addr(*addr);
	auto ip_it = ip_set.find(port);
	if(ip_it != ip_set.end()
		&& !ip_it->second.empty()
		&& (ip == INADDR_ANY
			|| ip_it->second.find(INADDR_ANY) != ip_it->second.end()
			|| ip_it->second.find(ip) != ip_it->second.end()))
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	sock->context.local_addr = tie_addr(ip, port);
	sock->state = ST_BOUND;
	ip_set[port][ip] = { pid, sockfd };

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto &fd_info = proc_table[pid].fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state == ST_READY)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	*addr = sock->context.local_addr;
	*addrlen = (socklen_t)sizeof(sock->context.local_addr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	PCBEntry &pcb = proc_table[pid];
	auto &fd_info = pcb.fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end()
		|| (sock_it->second->state != ST_LISTEN
			&& sock_it->second->state != ST_SYN_RCVD))
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	auto &accept_queue = sock->queue->accept_queue;
	if(accept_queue.empty())
	{
		PCBEntry::syscallParam param;
		param.acceptParam = { sockfd, addr, addrlen };
		pcb.blockSyscall(ACCEPT, syscallUUID, param);
		return;
	}

	int connfd = this->createFileDescriptor(pid);
	if (connfd != -1)
	{
		auto sock_accept = accept_queue.front(); accept_queue.pop();

		fd_info.insert({ connfd, sock_accept });

		in_addr_t remote_ip;
		in_port_t remote_port;
		std::tie(remote_ip, remote_port) = untie_addr(sock_accept->context.remote_addr);
		sock->queue->accept_map[{ remote_ip, remote_port }] = sock_accept;

		*addr = sock_accept->context.remote_addr;
		*addrlen = sizeof(*addr);
	}

	this->returnSystemCall(syscallUUID, connfd);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	auto &pcb = proc_table[pid];
	auto &fd_info = pcb.fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state == ST_ESTAB)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	in_addr_t remote_ip;
	in_port_t remote_port;
	std::tie(remote_ip, remote_port) = untie_addr(*addr);
	sock->context.remote_addr = *addr;

	in_addr_t local_ip;
	in_port_t local_port;

	if(sock->state == ST_READY)
	{
		int table_port = this->getHost()->getRoutingTable((uint8_t *)&remote_ip);
		if (!this->getHost()->getIPAddr((uint8_t *)&local_ip, table_port))
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}
		local_ip = be32toh(local_ip);

		while (true)
		{
			local_port = rand() % 65536;
			if (ip_set.find(local_port) == ip_set.end()
				|| (ip_set[local_port].find(INADDR_ANY) != ip_set[local_port].end()
					&& ip_set[local_port].find(local_ip) != ip_set[local_port].end()))
				break;
		}
		sock->context.local_addr = tie_addr(local_ip, local_port);
		sock->state = ST_BOUND;
		ip_set[local_port][local_ip] = { pid, sockfd };
	}
	else
		std::tie(local_ip, local_port) = untie_addr(sock->context.local_addr);

	sock->context.seq_num = rand_seq_num();
	sock->context.ack_num = 0;

	this->sendPacket("IPv4", make_packet(sock->context, SYN));

	sock->state = ST_SYN_SENT;

	PCBEntry::syscallParam param;
	param.connectParam = { sockfd, addr, addrlen };
	pcb.blockSyscall(CONNECT, syscallUUID, param);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto &fd_info = proc_table[pid].fd_info;

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
	auto &fd_info = proc_table[pid].fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second->state != ST_BOUND)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	sock->state = ST_LISTEN;
	sock->queue = new PassiveQueue(backlog);
	this->returnSystemCall(syscallUUID, 0);
}

Packet *TCPAssignment::make_packet(TCPContext &context, uint8_t flag)
{
	in_addr_t local_ip, remote_ip;
	in_port_t local_port, remote_port;
	std::tie(local_ip, local_port) = untie_addr(context.local_addr);
	std::tie(remote_ip, remote_port) = untie_addr(context.remote_addr);

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

	uint32_t new_seq_num = htonl(context.seq_num);
	packet->writeData(tcp_start + 4, &new_seq_num, 4);

	uint32_t new_ack_num = htonl(context.ack_num);
	packet->writeData(tcp_start + 8, &new_ack_num, 4);

	uint8_t tcp_header_buffer[20];
	packet->readData(tcp_start, tcp_header_buffer, 20);
	uint16_t checksum = NetworkUtil::tcp_sum(htonl(local_ip), htonl(remote_ip), tcp_header_buffer, 20);
	checksum = ~checksum;
	checksum = htons(checksum);
	packet->writeData(tcp_start + 16, (uint8_t *)&checksum, 2);

	return packet;
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


TCPAssignment::PassiveQueue::PassiveQueue(int backlog) : listen_queue(), accept_queue(), temp_buffer(), accept_map()
{
	this->backlog = backlog;
	this->temp_buffer.clear();
}
TCPAssignment::PassiveQueue::~PassiveQueue()
{

}


TCPAssignment::TCPSocket::TCPSocket(int domain) : context()
{
	this->domain = domain;
	this->state = ST_READY;
	this->queue = nullptr;
	this->blocked = false;
}
TCPAssignment::TCPSocket::~TCPSocket()
{
	delete queue;
}

TCPAssignment::PCBEntry::PCBEntry()
{
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


uint32_t TCPAssignment::rand_seq_num()
{
	static uint32_t cnt = 0;
	return cnt++;
}

std::pair<in_addr_t, in_port_t> TCPAssignment::untie_addr(sockaddr addr)
{
	return { ntohl(((sockaddr_in *)&addr)->sin_addr.s_addr), ntohs(((sockaddr_in *)&addr)->sin_port) };
}

sockaddr TCPAssignment::tie_addr(in_addr_t ip, in_port_t port)
{
	sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(ip);
	return *(sockaddr *)(&addr);
}

}
