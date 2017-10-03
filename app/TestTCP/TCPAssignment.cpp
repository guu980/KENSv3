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
	for(int i = 0; i<MAX_PORT_NUM; i++)
		ip_set[i].clear();
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
	if (protocol != IPPROTO_TCP)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	int fd = this->createFileDescriptor(pid);

	if(fd != -1 && protocol == IPPROTO_TCP)
		proc_table[pid].fd_info.insert({ fd, TCPSocket(domain) });

	this->returnSystemCall(syscallUUID, fd);
}

/* Need to be updated */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, 
	int fd)
{
	auto pcb_it = proc_table.find(pid);
	if (pcb_it == proc_table.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &fd_info = pcb_it->second.fd_info;

	auto sock_it = fd_info.find(fd);
	if(sock_it == fd_info.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	if (sock.state != ST_READY)
	{
		in_addr_t ip;
		in_port_t port;
		std::tie(ip, port) = addr_ip_port(&sock.local_addr);

		ip_set[port].erase(ip);
	}

	fd_info.erase(sock_it);

	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, 
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	auto pcb_it = proc_table.find(pid);
	if (pcb_it == proc_table.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &fd_info = pcb_it->second.fd_info;

	auto sock_it = fd_info.find(sockfd);
	if (sock_it == fd_info.end() || sock_it->second.state != ST_READY)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	in_addr_t ip;
	in_port_t port;
	std::tie(ip, port) = addr_ip_port((struct sockaddr_in *)addr);
	if(!ip_set[port].empty()
		&& (ip == INADDR_ANY
			|| ip_set[port].begin()->first == INADDR_ANY
			|| ip_set[port].find(ip) != ip_set[port].end()))
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	sock.setLocalAddr(ip, port);
	sock.state = ST_BOUND;
	ip_set[port][ip] = { pid, sockfd };

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, 
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto pcb_it = proc_table.find(pid);
	if (pcb_it == proc_table.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &fd_info = pcb_it->second.fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second.state == ST_READY)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	*addr = *((struct sockaddr *)&sock.local_addr);
	*addrlen = (socklen_t)sizeof(sock.local_addr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	// Do something...
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto pcb_it = proc_table.find(pid);
	if (pcb_it == proc_table.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &fd_info = pcb_it->second.fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end() || sock_it->second.state != ST_ESTAB)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	*addr = *((struct sockaddr *)&sock_it->second.remote_addr);
	*addrlen = (socklen_t)sizeof(sock_it->second.remote_addr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid,
	int sockfd, int backlog)
{
	
}

TCPAssignment::TCPSocket::TCPSocket(int domain)
{
	this->domain = domain;
	this->state = ST_READY;
	memset(&this->local_addr, 0, sizeof(this->local_addr));
	memset(&this->remote_addr, 0, sizeof(this->local_addr));
}
TCPAssignment::TCPSocket::~TCPSocket()
{

}
void TCPAssignment::TCPSocket::setLocalAddr(in_addr_t addr, in_port_t port)
{
	local_addr.sin_family = AF_INET;
	local_addr.sin_addr.s_addr = htonl(addr);
	local_addr.sin_port = htons(port);
}
void TCPAssignment::TCPSocket::setRemoteAddr(in_addr_t addr, in_port_t port)
{
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_addr.s_addr = htonl(addr);
	remote_addr.sin_port = htons(port);
}

TCPAssignment::PCBEntry::PCBEntry()
{
	fd_info.clear();
	blocked = false;
}
TCPAssignment::PCBEntry::~PCBEntry()
{

}

}
