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
#include "TCPAssignment.hpp"

#include <tuple>
#include <cstdio>
#include <iostream>

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
	if(fromModule.compare("IPv4") == 0)
	{
		/* Packet arrived from IPv4 Module!
		 * (1) Read from packet local and remote addresses.
		 * (2) Forward the packet to corresponding TCPSocket.
		 * (3) Handle the packet according to the state of the socket.
		 */

		/*
		size_t ip_start = 14;
		size_t ihl;
		uint8_t ihl_buffer;
		uint32_t ip_buffer;
		in_addr_t ip;

		size_t tcp_start;
		uint16_t port_buffer;
		in_port_t port;

		packet->readData(ip_start, &ihl_buffer, 1);
		ihl = (ihl_buffer & 0x0f) << 2;
		tcp_start = ip_start + ihl;

		packet->readData(ip_start + 16, &ip_buffer, 4);
		packet->readData(tcp_start + 2, &port_buffer, 2);
		ip = (in_addr_t)ntohl(ip_buffer);
		port = (in_port_t)ntohs(port_buffer);

		int pid, fd;
		auto ip_it = ip_set.find(port);
		if (ip_it != ip_set.end())
		{
			auto &sock_map = ip_it->second;
			if (sock_map.begin()->first == INADDR_ANY)
			{
				std::tie(pid, fd) = sock_map.begin()->second;
				proc_table[pid].fd_info[fd].handlePacket(packet);
			}
			else if (sock_map.find(ip) != sock_map.end())
			{
				std::tie(pid, fd) = sock_map[ip];
				proc_table[pid].fd_info[fd].handlePacket(packet);
			}
		}
		*/

		/* Otherwise, ignore the packet. */
	}
	else
	{
		assert(0);
	}
}

void TCPAssignment::timerCallback(void* payload)
{

}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, 
		int domain, int protocol)
{
	//assert(domain == AF_INET && protocol == IPPROTO_TCP);
	if(protocol != IPPROTO_TCP)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	int fd = this->createFileDescriptor(pid);

	if(fd != -1)
	{
		proc_table[pid].fd_info.insert({ fd, TCPSocket(domain) });
	}

	this->returnSystemCall(syscallUUID, fd);
}

/* Need to be updated */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, 
	int fd)
{
	auto &fd_info = proc_table[pid].fd_info;

	auto sock_it = fd_info.find(fd);
	if(sock_it == fd_info.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	if(sock.state != ST_READY)
	{
		in_addr_t ip;
		in_port_t port;
		std::tie(ip, port) = untie_addr(sock.context.local_addr);

		ip_set[port].erase(ip);
		if (ip_set[port].empty())
			ip_set.erase(port);
	}

	fd_info.erase(sock_it);

	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, 
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	auto &fd_info = proc_table[pid].fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second.state != ST_READY)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	in_addr_t ip;
	in_port_t port;
	std::tie(ip, port) = untie_addr(*addr);
	auto ip_it = ip_set.find(port);
	if(ip_it != ip_set.end()
		&& !ip_it->second.empty()
		&& (ip == INADDR_ANY
			|| ip_it->second.begin()->first == INADDR_ANY
			|| ip_it->second.find(ip) != ip_it->second.end()))
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	sock.context.local_addr = tie_addr(ip, port);
	sock.state = ST_BOUND;
	ip_set[port][ip] = { pid, sockfd };

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, 
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto &fd_info = proc_table[pid].fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second.state == ST_READY)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	*addr = sock.context.local_addr;
	*addrlen = (socklen_t)sizeof(sock.context.local_addr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	PCBEntry &pcb = proc_table[pid];
	auto &fd_info = pcb.fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second.state != ST_LISTEN)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	auto &accept_queue = sock.queue->accept_queue;
	if(accept_queue.empty())
	{
		//pcb.blockSystemCall(ACCEPT, syscallUUID, sockfd);
		return;
	}

	int connfd = this->createFileDescriptor(pid);
	if (connfd != -1)
	{
		fd_info.insert({ connfd, TCPSocket(sock.domain) });
		auto &sock_accept = fd_info[connfd];
		sock_accept.state = ST_ESTAB;
		sock_accept.context = accept_queue.front(); accept_queue.pop();
	}

	this->returnSystemCall(syscallUUID, connfd);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto &fd_info = proc_table[pid].fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second.state != ST_ESTAB)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	*addr = sock.context.remote_addr;
	*addrlen = (socklen_t)sizeof(sock.context.remote_addr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid,
	int sockfd, int backlog)
{
	auto &fd_info = proc_table[pid].fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second.state != ST_BOUND)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	sock.state = ST_LISTEN;
	sock.queue = new PassiveQueue(backlog);
	this->returnSystemCall(syscallUUID, 0);
}



TCPAssignment::TCPContext::TCPContext()
{
	memset(&this->local_addr, 0, sizeof(this->local_addr));
	memset(&this->remote_addr, 0, sizeof(this->local_addr));
}
TCPAssignment::TCPContext::~TCPContext()
{

}


TCPAssignment::PassiveQueue::PassiveQueue(int backlog) : listen_queue(), accept_queue()
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
