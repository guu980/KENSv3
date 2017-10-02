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

#define VOID_RETURN 0

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{
	proc_table.clear();
	for(int i = 0; i<MAX_PORT_NUM; i++)
	{
		ip_set[i].clear();
		is_addr_any[i] = false;
	}
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

}

void TCPAssignment::timerCallback(void* payload)
{

}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, 
		int domain, int protocol)
{
	//assert(domain == AF_INET && protocol == IPPROTO_TCP);
	int fd = this->createFileDescriptor(pid);

	if(fd != -1)
		proc_table[pid].fd_set.insert(fd);

	this->returnSystemCall(syscallUUID, fd);
}

/* Need to be updated */
void TCPAssignment::syscall_close(UUID syscallUUID, int pid, 
	int fd)
{
	auto pe_it = proc_table.find(pid);
	if (pe_it == proc_table.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &pe = pe_it->second;
	auto &fd_set = pe.fd_set;
	auto &fd_info = pe.fd_info;

	auto fd_it = fd_set.find(fd);
	if(fd_it == fd_set.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	fd_set.erase(fd_it);

	auto addr_it = fd_info.find(fd);
	if(addr_it != fd_info.end())
	{
		ip_t ip;
		port_t port;
		std::tie(ip, port) = addr_ip_port(addr_it->second.first);

		fd_info.erase(addr_it);

		if(ip == INADDR_ANY)
			is_addr_any[port] = false;
		else
			ip_set[port].erase(ip);
	}

	this->removeFileDescriptor(pid, fd);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, 
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	auto pe_it = proc_table.find(pid);
	if (pe_it == proc_table.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &pe = pe_it->second;
	auto &fd_set = pe.fd_set;
	auto &fd_info = pe.fd_info;

	if(fd_set.find(sockfd) == fd_set.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	ip_t ip;
	port_t port;
	std::tie(ip, port) = addr_ip_port(*addr);

	if(ip == INADDR_ANY)
	{
		if(is_addr_any[port] || !ip_set[port].empty())
		{
			this->returnSystemCall(syscallUUID, -1);
			return;
		}

		is_addr_any[port] = true;
	}
	else if(is_addr_any[port] || !ip_set[port].insert(ip).second)
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	fd_info[sockfd] = { *addr, addrlen };
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, 
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	auto pe_it = proc_table.find(pid);
	if (pe_it == proc_table.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &pe = pe_it->second;
	auto &fd_info = pe.fd_info;

	auto addr_it = fd_info.find(sockfd);
	if(addr_it == fd_info.end())
	{
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	*addr = addr_it->second.first;
	*addrlen = addr_it->second.second;

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid,
	int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid,
	int sockfd, int backlog)
{
	
}


std::pair<TCPAssignment::ip_t, TCPAssignment::port_t> TCPAssignment::addr_ip_port(const struct sockaddr addr)
{
	return { ((struct sockaddr_in *)(&addr))->sin_addr.s_addr, ((struct sockaddr_in *)(&addr))->sin_port };
}


}
