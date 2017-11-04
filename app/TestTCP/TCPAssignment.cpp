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
		sock_set(), timer_map(), packet_set(),
		conn_map(), listen_map(), ip_set(), proc_table()
{

}

TCPAssignment::~TCPAssignment()
{
	for(auto sock : sock_set)
	{
		delete sock;
	}

	for(auto packet : packet_set)
	{
		this->freePacket(packet);
	}

	for(auto payload : timer_map)
	{
		delete payload.second;
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
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param3_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
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

	PacketReader reader(packet);
	TCPContext context;
	reader.recvAddress(context);
	//	fprintf(stderr, "Packet Hello: %u %hu\n", unpack_addr(context.remote_addr).first, unpack_addr(context.remote_addr).second);

	in_addr_t ip;
	in_port_t port;
	std::tie(ip, port) = unpack_addr(context.local_addr);

	auto sock_it = conn_map.find(context);
	if(sock_it != conn_map.end())
	{
		auto sock = sock_it->second;
		assert(sock && sock->trans);
		auto trans = sock->trans;
		uint16_t flag = reader.readFlag();

		recvPacket(sock, reader);

		switch(sock->state)
		{
		case ST_SYN_SENT:
			if(flag & ACK)
			{
				if(flag & SYN)
				{
					transmitPacket(sock, make_packet(sock, ACK, nullptr, 0), 0);

					sock->state = ST_ESTAB;
					auto pcb = sock->getHostPCB();
					assert(pcb->blocked && pcb->syscall == CONNECT);

					this->returnSystemCall(pcb->syscallUUID, 0);
					pcb->unblockSyscall();
				}
				else
					sock->state = ST_SYN_RCVD_SIM;
			}
			else if(flag & SYN)
				sock->state = ST_SYN_RCVD_SIM;
			break;

		case ST_SYN_RCVD:
			if(flag & ACK)
			{
				auto pcb = sock->getHostPCB();
				auto listen_sock = findListenSocket(ip, port);
				assert(listen_sock && sock->trans);

				assert(trans->in_flight.empty());

				sock->state = ST_ESTAB;
				listen_sock->listen->pending_map.erase(context);

				if(pcb->blocked && pcb->syscall == ACCEPT)
				{
					int connfd = this->createFileDescriptor(pcb->getpid());

					if(connfd != -1)
					{
						auto &param = pcb->param.acceptParam;
						pcb->fd_info.insert({ connfd, sock });

						*param.addr = context.remote_addr;
						*param.addrlen = sizeof(*param.addr);
					}
					else
						errno = EBADF;

					this->returnSystemCall(pcb->syscallUUID, connfd);
					pcb->unblockSyscall();
				}
				else
					listen_sock->listen->accept_queue.push(sock);
			}
			break;

		case ST_SYN_RCVD_SIM:
			if((flag & ACK) || (flag & SYN))
			{
				if(flag & SYN)
					transmitPacket(sock, make_packet(sock, ACK, nullptr, 0), 0);

				sock->state = ST_ESTAB;
				auto pcb = sock->getHostPCB();
				assert(pcb->blocked && pcb->syscall == CONNECT);

				this->returnSystemCall(pcb->syscallUUID, 0);
				pcb->unblockSyscall();
			}
			break;
		case ST_ESTAB:
			if(reader.getSegmentLen() > 0)
				transmitPacket(sock, make_packet(sock, ACK, nullptr, 0), 0);

			if(trans->fin_rcvd && trans->fin_seq + 1 == trans->ack_num)
			{
				assert(trans->in_flight.empty());

				sock->state = ST_CLOSE_WAIT;
			}

			if(trans->awnd < trans->rcv_size)
			{
				auto pcb = sock->getHostPCB();

				if(pcb->blocked && pcb->syscall == READ)
				{
					auto &param = pcb->param.readParam;
					int fd = param.fd;
					if(pcb->fd_info.find(fd) != pcb->fd_info.end()
					   && pcb->fd_info[fd] == sock)
					{
						int ret = (int)readData(sock, param.buf, param.count);
						assert(ret > 0);
						this->returnSystemCall(pcb->syscallUUID, ret);
						pcb->unblockSyscall();
					}
				}
			}

			if(trans->senderAvailable())
			{
				auto pcb = sock->getHostPCB();

				if(pcb->blocked && pcb->syscall == WRITE)
				{
					auto &param = pcb->param.writeParam;
					int fd = param.fd;
					if(pcb->fd_info.find(fd) != pcb->fd_info.end()
					   && pcb->fd_info[fd] == sock)
					{
						int ret = (int)writeData(sock, param.buf, param.count);
						assert(ret > 0);
						this->returnSystemCall(pcb->syscallUUID, ret);
						pcb->unblockSyscall();
					}
				}
			}
			break;

		case ST_FIN_WAIT_1:
			if(flag & ACK)
				sock->state = ST_FIN_WAIT_2;
			else if(flag & FIN)
			{
				transmitPacket(sock, make_packet(sock, ACK, nullptr, 0), 0);
				sock->state = ST_CLOSING;
			}
			break;

		case ST_FIN_WAIT_2:
			if(flag & FIN)
			{
				transmitPacket(sock, make_packet(sock, ACK, nullptr, 0), 0);
				sock->state = ST_TIME_WAIT;

				auto payload = new TimerPayload(TM_TIME_WAIT);
				payload->sock = sock;
				setTimeout(payload, TimeUtil::makeTime(4, TimeUtil::MINUTE));
			}
			break;
		case ST_LAST_ACK:
			if(flag & ACK)
			{
				conn_map.erase(context);
				remove_addr(ip, port);
				destroySocket(sock);
			}
			break;
		case ST_CLOSING:
			if(flag & ACK)
			{
				sock->state = ST_TIME_WAIT;

				auto payload = new TimerPayload(TM_TIME_WAIT);
				payload->sock = sock;
				setTimeout(payload, TimeUtil::makeTime(4, TimeUtil::MINUTE));
			}
			break;
		default:
			;
		}
	}
	else
	{
		TCPSocket *listen_sock;
		if((listen_sock = findListenSocket(ip, port)) == nullptr)
		{
			resetConnection(context, rand_seq_num(), reader.getNextSeqNum());
			return;
		}

		listenPacket(listen_sock, reader);
	}

	this->freePacket(packet);
}

void TCPAssignment::timerCallback(void* payload)
{
	auto load = (TimerPayload *)payload;
	timer_map.erase(load->timerUUID);

	switch(load->type)
	{
	case TM_RETRANSMIT:
		retransmit(load);
		break;
	case TM_PERSISTENCE:
		break;
	case TM_KEEPALIVE:
		break;
	case TM_TIME_WAIT:
	{
		auto sock = load->sock;

		assert(sock->state == ST_TIME_WAIT);

		in_addr_t local_ip;
		in_port_t local_port;
		std::tie(local_ip, local_port) = unpack_addr(sock->context.local_addr);

		conn_map.erase(sock->context);
		remove_addr(local_ip, local_port);

		destroySocket(sock);
		delete load;
		break;
	}
	default:
		assert(0);
	}
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid,
		int domain, int protocol)
{
	if(domain != AF_INET)
	{
		errno = EAFNOSUPPORT;
		this->returnSystemCall(syscallUUID, -1);
	}

	if(protocol != IPPROTO_TCP)
	{
		errno = EPROTONOSUPPORT;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	int fd = this->createFileDescriptor(pid);

	if(fd != -1)
	{
		auto pcb = getPCBEntry(pid);
		pcb->fd_info.insert({ fd, createSocket(pcb, domain) });
	}
	else
		errno = EMFILE;

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
		errno = EBADF;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;

	if(sock->state == ST_ESTAB || sock->state == ST_CLOSE_WAIT)
		closeTransmission(sock);
	else
	{
		if(sock->state == ST_BOUND || sock->state == ST_LISTEN)
		{
			if(sock->state == ST_LISTEN)
			{
				closeListen(sock);
				listen_map.erase(unpack_addr(sock->context.local_addr));
			}

			in_addr_t ip;
			in_port_t port;
			std::tie(ip, port) = unpack_addr(sock->context.local_addr);
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
	if(sock_it == fd_info.end())
	{
		errno = EBADF;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;
	if(sock->state != ST_READY)
	{
		errno = EINVAL;
		this->returnSystemCall(syscallUUID, -1);
	}

	in_addr_t ip;
	in_port_t port;
	std::tie(ip, port) = unpack_addr(*addr);

	if(ip_set.find(port) != ip_set.end()
		&& ((ip == INADDR_ANY && !ip_set[port].empty())
			|| ip_set[port].find(INADDR_ANY) != ip_set[port].end()
			|| ip_set[port].find(ip) != ip_set[port].end()))
	{
		errno = EADDRINUSE;
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
	if(sock_it == fd_info.end())
	{
		errno = EBADF;
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
	if(sock_it == fd_info.end())
	{
		errno = EBADF;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto sock = sock_it->second;
	if(sock->state != ST_LISTEN)
	{
		errno = EINVAL;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

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
	else
		errno = EMFILE;

	this->returnSystemCall(syscallUUID, connfd);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid,
	int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	auto pcb = getPCBEntry(pid);
	auto &fd_info = pcb->fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end())
	{
		errno = EBADF;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;
	if(sock->state != ST_READY && sock->state != ST_BOUND)
	{
		if(sock->state == ST_LISTEN)
			errno = EOPNOTSUPP;
		else
			errno = EISCONN;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

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
			errno = EHOSTUNREACH;
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

	sock->trans = new TransmissionModule(51200);

	transmitPacket(sock, make_packet(sock, SYN, nullptr, 0), 1);

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
	if(sock_it == fd_info.end())
	{
		errno = EBADF;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;
	if(sock->state != ST_ESTAB && sock->state != ST_CLOSE_WAIT)
	{
		errno = ENOTCONN;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}

	*addr = sock->context.remote_addr;
	*addrlen = (socklen_t)sizeof(sock->context.remote_addr);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid,
	int sockfd, int backlog)
{
	auto &fd_info = getPCBEntry(pid)->fd_info;

	auto sock_it = fd_info.find(sockfd);
	if(sock_it == fd_info.end())
	{
		errno = EBADF;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;
	if(sock->state != ST_BOUND)
	{
		errno = EADDRINUSE;
		this->returnSystemCall(syscallUUID, -1);
	}

	sock->state = ST_LISTEN;
	sock->listen = new ListenModule(backlog);
	listen_map[unpack_addr(sock->context.local_addr)] = sock;

	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid,
	int fd, void *buf, size_t count)
{
	auto pcb = getPCBEntry(pid);
	auto &fd_info = pcb->fd_info;

	auto sock_it = fd_info.find(fd);
	if(sock_it == fd_info.end())
	{
		errno = EBADF;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	if(count == 0)
	{
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	int ret;
	if((ret = (int)readData(sock, buf, count)) == 0)
	{
		PCBEntry::syscallParam param;
		param.readParam = { fd, buf, count };
		pcb->blockSyscall(READ, syscallUUID, param);
		return;
	}

	this->returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid,
	int fd, const void *buf, size_t count)
{
	auto pcb = getPCBEntry(pid);
	auto &fd_info = pcb->fd_info;

	auto sock_it = fd_info.find(fd);
	if(sock_it == fd_info.end())
	{
		errno = EBADF;
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	auto &sock = sock_it->second;

	if(count == 0)
	{
		this->returnSystemCall(syscallUUID, 0);
		return;
	}

	int ret;
	if((ret = (int)writeData(sock, buf, count)) == 0)
	{
		PCBEntry::syscallParam param;
		param.writeParam = { fd, buf, count };
		pcb->blockSyscall(WRITE, syscallUUID, param);
		return;
	}

	this->returnSystemCall(syscallUUID, ret);
}

Packet *TCPAssignment::make_packet(TCPSocket *sock, uint16_t flag, const void *buf, size_t count)
{
	Packet *packet = this->allocatePacket(54 + count);
	PacketWriter writer(packet, 20, 20, count);
	writer.sendAddress(sock->context);
	writer.writeSeqNum(sock->trans->seq_num);
	writer.writeAckNum(sock->trans->ack_num);
	writer.writeFlag(flag);
	writer.writeWindowSize(sock->trans->awnd);
	writer.writeData(0, buf, count);
	writer.writeChecksum();

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

UUID TCPAssignment::setTimeout(TimerPayload *payload, Time timeAfter)
{
	payload->sent = this->getHost()->getSystem()->getCurrentTime();
	payload->timeAfter = timeAfter;
	payload->timerUUID = this->addTimer(payload, timeAfter);
	timer_map.insert({ payload->timerUUID, payload });
	return payload->timerUUID;
}

void TCPAssignment::clearTimeout(UUID timerUUID)
{
	this->cancelTimer(timerUUID);
	timer_map.erase(timerUUID);
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

TCPAssignment::TCPSocket *TCPAssignment::findListenSocket(in_addr_t ip, in_port_t port)
{
	auto listen_it = listen_map.find({ INADDR_ANY, port });
	if(listen_it == listen_map.end())
		listen_it = listen_map.find({ ip, port });
	return listen_it == listen_map.end() ? nullptr : listen_it->second;
}

size_t TCPAssignment::writeData(TCPSocket *sock, const void *buf, size_t count)
{
	assert(sock->trans);

	size_t actual_size = 0;
	uint8_t *data = (uint8_t *)buf;
	count = std::min(count, sock->trans->senderAvailable());

	while(count > 0)
	{
		size_t write_len = std::min(count, (size_t)512);
		transmitPacket(sock, make_packet(sock, ACK, data, write_len), write_len);

		count -= write_len;
		actual_size += write_len;
		data += write_len;
	}

	return actual_size;
}

size_t TCPAssignment::readData(TCPSocket *sock, void *buf, size_t count)
{
	assert(sock->trans);
	return sock->trans->readData(buf, count);
}

void TCPAssignment::transmitPacket(TCPSocket *sock, Packet *packet, size_t seg_len)
{
	assert(sock->trans);

	if((int)seg_len == 0)
	{
		/* This indicates pure ACK. */
		this->sendPacket("IPv4", packet);
		return;
	}

	auto trans = sock->trans;
	auto new_packet = this->clonePacket(packet);
	packet_set.insert(new_packet);

	this->sendPacket("IPv4", packet);

	auto payload = new TimerPayload(TM_RETRANSMIT);
	payload->sock = sock;
	payload->seq = trans->seq_num;
	payload->packet = new_packet;
	setTimeout(payload, trans->timeout);

	trans->in_flight.push(payload);
	trans->seq_num += seg_len;
}

void TCPAssignment::recvPacket(TCPSocket *sock, PacketReader &reader)
{
	assert(sock->trans);

	auto trans = sock->trans;
	auto &in_flight = trans->in_flight;
	uint16_t flag = reader.readFlag();
	uint32_t seq_num = reader.readSeqNum();
	size_t seg_len = reader.getSegmentLen();
	size_t data_len = reader.getDataLen();

	if(flag & SYN)
		trans->ack_num = seq_num + 1;
	else if(!trans->isValidSegment(seq_num, seg_len))
		return;

	if((flag & ACK) && !in_flight.empty())
	{
		uint32_t ack = reader.readAckNum();
		if(ack == trans->getLastAcked())
		{
			if(seg_len == 0 && trans->rwnd == reader.readWindowSize())
			{
				trans->dup_ack_cnt++;
				if(trans->dup_ack_cnt == 3)
				{
					/* Fast retransmit. */
					auto payload = in_flight.front();
					clearTimeout(payload->timerUUID);
					retransmit(payload);
					for(int i = 0; i < 3; i++)
						trans->increaseCWND();
				}
				else if(trans->dup_ack_cnt > 3)
					trans->increaseCWND();
			}
			trans->rwnd = reader.readWindowSize();
		}
		else if(inSegment(trans->getLastAcked() + 1, trans->seq_num, ack))
		{
			trans->calcTimeout(this->getHost()->getSystem()->getCurrentTime());

			while(!in_flight.empty()
			      && inSegment(trans->getLastAcked() + 1, trans->seq_num, ack))
			{
				auto payload = in_flight.front();
				in_flight.pop();
				clearTimeout(payload->timerUUID);
				packet_set.erase(payload->packet);
				this->freePacket(payload->packet);
				delete payload;
			}

			trans->increaseCWND();
			trans->rwnd = reader.readWindowSize();
			trans->dup_ack_cnt = 0;
		}
	}

	if(data_len > 0)
		trans->recvData(reader);

	if(flag & FIN)
	{
		trans->fin_rcvd = true;
		trans->fin_seq = seq_num + data_len;
	}

	if(trans->fin_rcvd && trans->ack_num == trans->fin_seq)
		trans->ack_num++;
}

void TCPAssignment::listenPacket(TCPSocket *sock, PacketReader &reader)
{
	assert(sock->listen);

	uint16_t flag = reader.readFlag();
	if(flag & SYN)
	{
		TCPContext context;
		reader.recvAddress(context);

		if((int)sock->listen->pending_map.size() < sock->listen->backlog)
		{
			auto conn_sock = createSocket(sock->getHostPCB(), sock->domain);
			conn_sock->context = context;

			conn_sock->trans = new TransmissionModule(51200);
			conn_map[context] = conn_sock;
			sock->listen->pending_map[context] = conn_sock;

			in_addr_t local_ip;
			in_port_t local_port;
			std::tie(local_ip, local_port) = unpack_addr(conn_sock->context.local_addr);
			add_addr(local_ip, local_port);

			conn_sock->state = ST_BOUND;

			recvPacket(conn_sock, reader);

			conn_sock->state = ST_SYN_RCVD;
			transmitPacket(conn_sock, make_packet(conn_sock, SYN | ACK, nullptr, 0), 1);
		}
		else
			resetConnection(context, rand_seq_num(), reader.getNextSeqNum());
	}
}

void TCPAssignment::retransmit(TimerPayload *payload)
{
	/* TCP Reno: Always set CWND to SSTHRESH. */
	assert(payload->type == TM_RETRANSMIT);

	this->sendPacket("IPv4", this->clonePacket(payload->packet));
	setTimeout(payload, std::min(payload->timeAfter * 2, TimeUtil::makeTime(64, TimeUtil::SEC)));

	auto sock = payload->sock;
	assert(sock->trans);
	sock->trans->decreaseCWND();
}

void TCPAssignment::resetConnection(TCPContext &context, uint32_t seq_num, uint32_t ack_num)
{
	Packet *packet = this->allocatePacket(54);
	PacketWriter writer(packet, 20, 20, 0);
	writer.sendAddress(context);
	writer.writeSeqNum(seq_num);
	writer.writeAckNum(ack_num);
	writer.writeFlag(ACK | RST);
	writer.writeChecksum();

	this->sendPacket("IPv4", packet);
}

void TCPAssignment::closeListen(TCPSocket *sock)
{
	assert(sock->listen);

	auto listen = sock->listen;
	for(auto context_sock : listen->pending_map)
	{
		closeTransmission(context_sock.second);
	}
	while(!listen->accept_queue.empty())
	{
		auto sock = listen->accept_queue.front();
		listen->accept_queue.pop();
		closeTransmission(sock);
	}
}

void TCPAssignment::closeTransmission(TCPSocket *sock)
{
	assert(sock->trans);

	transmitPacket(sock, make_packet(sock, FIN, nullptr, 0), 1);

	if(sock->state == ST_ESTAB)
		sock->state = ST_FIN_WAIT_1;
	else
		sock->state = ST_LAST_ACK;
}


TCPAssignment::TCPContext::TCPContext()
{
	memset(&this->local_addr, 0, sizeof(this->local_addr));
	memset(&this->remote_addr, 0, sizeof(this->local_addr));
}
TCPAssignment::TCPContext::TCPContext(sockaddr local_addr, sockaddr remote_addr) : local_addr(local_addr), remote_addr(remote_addr)
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

TCPAssignment::PacketReader::PacketReader(Packet *packet) : packet(packet)
{
	uint8_t ihl_buffer;
	uint16_t tot_buffer;
	packet->readData(ip_start, &ihl_buffer, 1);
	packet->readData(ip_start + 2, &tot_buffer, 2);
	size_t ihl = (ihl_buffer & 0x0F) * 4;  /* Size of the IP header */
	size_t tot_len = ntohs(tot_buffer);

	this->tcp_start = ip_start + ihl;
	uint8_t data_ofs_ns;
	packet->readData(tcp_start + 12, &data_ofs_ns, 1);
	this->data_start = tcp_start + (data_ofs_ns >> 4) * 4;
	this->data_len = ip_start + tot_len - data_start;
}
TCPAssignment::PacketReader::~PacketReader()
{

}
in_addr_t TCPAssignment::PacketReader::readIPAddress(bool src)
{
	uint32_t ip_buffer;
	packet->readData(ip_start + (src ? 12 : 16), &ip_buffer, 4);
	return (in_addr_t)ntohl(ip_buffer);
}
in_port_t TCPAssignment::PacketReader::readPort(bool src)
{
	uint16_t port_buffer;
	packet->readData(tcp_start + (src ? 0 : 2), &port_buffer, 2);
	return (in_port_t)ntohs(port_buffer);
}
void TCPAssignment::PacketReader::recvAddress(TCPContext &context)
{
	context.local_addr = pack_addr(readIPAddress(false), readPort(false));
	context.remote_addr = pack_addr(readIPAddress(true), readPort(true));
}
uint32_t TCPAssignment::PacketReader::readSeqNum()
{
	uint32_t seq_num;
	packet->readData(tcp_start + 4, &seq_num, 4);
	return ntohl(seq_num);
}
uint32_t TCPAssignment::PacketReader::readAckNum()
{
	uint32_t ack_num;
	packet->readData(tcp_start + 8, &ack_num, 4);
	return ntohl(ack_num);
}
uint16_t TCPAssignment::PacketReader::readFlag()
{
	uint16_t flag;
	packet->readData(tcp_start + 12, &flag, 2);
	return ntohs(flag) & 0x01FF;
}
size_t TCPAssignment::PacketReader::readWindowSize()
{
	uint16_t rwnd;
	packet->readData(tcp_start + 14, &rwnd, 2);
	return (size_t)ntohs(rwnd);
}
size_t TCPAssignment::PacketReader::readData(size_t offset, void *buf, size_t count)
{
	return packet->readData(data_start + offset, buf, count);
}
size_t TCPAssignment::PacketReader::getDataLen()
{
	return data_len;
}
size_t TCPAssignment::PacketReader::getSegmentLen()
{
	size_t len = getDataLen();
	uint16_t flag = readFlag();
	if(flag & SYN)
		len++;
	if(flag & FIN)
		len++;
	return len;
}
uint32_t TCPAssignment::PacketReader::getNextSeqNum()
{
	return readSeqNum() + getSegmentLen();
}

TCPAssignment::PacketWriter::PacketWriter(Packet *packet,
		size_t ihl, size_t thl, size_t data_len) : packet(packet), data_len(data_len)
{
	assert(!(ihl & 3));
	assert(!(thl & 3));

	this->tcp_start = ip_start + ihl;
	this->data_start = tcp_start + thl;
}
TCPAssignment::PacketWriter::~PacketWriter()
{

}
void TCPAssignment::PacketWriter::writeIPAddress(bool src, in_addr_t ip)
{
	uint32_t ip_buffer = (uint32_t)htonl(ip);
	packet->writeData(ip_start + (src ? 12 : 16), &ip_buffer, 4);
}
void TCPAssignment::PacketWriter::writePort(bool src, in_port_t port)
{
	uint16_t port_buffer = (uint16_t)htons(port);
	packet->writeData(tcp_start + (src ? 0 : 2), &port_buffer, 2);
}
void TCPAssignment::PacketWriter::sendAddress(TCPContext &context)
{
	in_addr_t local_ip, remote_ip;
	in_port_t local_port, remote_port;
	std::tie(local_ip, local_port) = unpack_addr(context.local_addr);
	std::tie(remote_ip, remote_port) = unpack_addr(context.remote_addr);
	writeIPAddress(true, local_ip);
	writeIPAddress(false, remote_ip);
	writePort(true, local_port);
	writePort(false, remote_port);
}
void TCPAssignment::PacketWriter::writeSeqNum(uint32_t seq_num)
{
	seq_num = htonl(seq_num);
	packet->writeData(tcp_start + 4, &seq_num, 4);
}
void TCPAssignment::PacketWriter::writeAckNum(uint32_t ack_num)
{
	ack_num = htonl(ack_num);
	packet->writeData(tcp_start + 8, &ack_num, 4);
}
void TCPAssignment::PacketWriter::writeFlag(uint16_t flag)
{
	/* Note: every TCP packet should have at least one flag set.
	   Thus, it is safe to write data offset here, since this
	   function will be called at least once. */
	assert(!(flag & 0xFE00));

	uint16_t data_ofs_word = (data_start - tcp_start) / 4;
	flag |= data_ofs_word << 12;
	flag = htobe16(flag);
	packet->writeData(tcp_start + 12, &flag, 2);
}
void TCPAssignment::PacketWriter::writeWindowSize(size_t rwnd)
{
	uint16_t rwnd_buf = htons((uint16_t)rwnd);
	packet->writeData(tcp_start + 14, &rwnd_buf, 2);
}
size_t TCPAssignment::PacketWriter::writeData(size_t offset, const void *buf, size_t count)
{
	return packet->writeData(data_start + offset, buf, count);
}
void TCPAssignment::PacketWriter::writeChecksum()
{
	uint32_t src_ip_nb, dest_ip_nb;
	size_t data_ofs = data_start - tcp_start;
	uint8_t *tcp_buffer = new uint8_t[data_ofs + data_len];
	packet->readData(ip_start + 12, &src_ip_nb, 4);
	packet->readData(ip_start + 16, &dest_ip_nb, 4);
	packet->readData(tcp_start, tcp_buffer, data_ofs + data_len);
	uint16_t checksum = NetworkUtil::tcp_sum(src_ip_nb, dest_ip_nb, tcp_buffer, data_ofs + data_len);
	checksum = ~checksum;
	checksum = htons(checksum);
	packet->writeData(tcp_start + 16, &checksum, 2);
	delete tcp_buffer;
}

TCPAssignment::TransmissionModule::TransmissionModule(size_t rcv_size) : in_flight(), rcv_size(rcv_size), unacked()
{
	this->seq_num = rand_seq_num();
	this->mss = 512;	/* Default in KENS. */
	this->ssthresh = RWND_MAX;
	this->cwnd = 1 * this->mss;
	this->timeout = TimeUtil::makeTime(100, TimeUtil::MSEC);
	this->estimate_rtt = (Real)this->timeout;
	this->dev_rtt = 0.0;

	this->rcv_buf = new uint8_t[rcv_size];
	this->awnd = rcv_size;
	this->rcv_base = 0;
	this->fin_rcvd = false;
}
TCPAssignment::TransmissionModule::~TransmissionModule()
{
	delete[] rcv_buf;
}
uint32_t TCPAssignment::TransmissionModule::getLastAcked()
{
	return in_flight.empty() ? seq_num : in_flight.front()->seq;
}
void TCPAssignment::TransmissionModule::calcTimeout(Time current)
{
	Time sample_rtt = current - in_flight.front()->sent;
	estimate_rtt = (1 - alpha) * estimate_rtt + alpha * sample_rtt;
	dev_rtt = (1 - beta) * dev_rtt + beta * abs(sample_rtt - estimate_rtt);
	timeout = (Time)ceil(estimate_rtt + 4 * dev_rtt);
}
void TCPAssignment::TransmissionModule::increaseCWND()
{
	if(ssthresh > cwnd)
		cwnd *= 2;
	else
		cwnd = std::min(cwnd + mss, RWND_MAX);
}
void TCPAssignment::TransmissionModule::decreaseCWND()
{
	ssthresh = std::max(cwnd / 2, mss * 2);
	cwnd = ssthresh;
}
size_t TCPAssignment::TransmissionModule::senderAvailable()
{
	size_t wnd = std::min(rwnd, cwnd);
	uint32_t last_ack = getLastAcked();
	size_t used = seq_num >= last_ack ? seq_num - last_ack : SEQ_MAX - seq_num + last_ack;
	return wnd >= used ? wnd - used : 0;
}
size_t TCPAssignment::TransmissionModule::readData(void *buf, size_t count)
{
	size_t app_base = (rcv_base + awnd) % rcv_size;

	if(app_base <= rcv_base)
	{
		size_t data_size = rcv_base - app_base;
		size_t actual_size = std::min(count, data_size);
		memcpy(buf, rcv_buf + app_base, actual_size);

		awnd += actual_size;
		return actual_size;
	}
	else
	{
		size_t rest_size = rcv_size - app_base;
		if(count <= rest_size)
		{
			memcpy(buf, rcv_buf + app_base, count);

			awnd += count;
			return count;
		}
		size_t actual_size = rest_size + std::min(count - rest_size, rcv_base);
		memcpy(buf, rcv_buf + app_base, rest_size);
		memcpy((uint8_t *)buf + rest_size, rcv_buf, actual_size - rest_size);

		awnd += actual_size;
		return actual_size;
	}
}
bool TCPAssignment::TransmissionModule::inRcvdWindow(uint32_t seq)
{
	return inSegment(ack_num - RWND_MAX, ack_num + awnd, seq);
}
bool TCPAssignment::TransmissionModule::isValidSegment(uint32_t seq, size_t seg_len)
{
	uint32_t seq_begin = ack_num;
	uint32_t seq_end = fin_rcvd ? fin_seq : ack_num + awnd;
	if(awnd > 0)
	{
		if(seg_len > 0)
		{
			return inSegment(seq_begin, seq_end - 1, seq)
			       || inSegment(seq_begin, seq_end - 1, seq + seg_len - 1);
		}
		else
			return inSegment(seq_begin, seq_end - 1, seq);
	}
	else
		return seg_len == 0 && seq_begin == seq;
}
void TCPAssignment::TransmissionModule::recvData(PacketReader &reader)
{
	uint32_t seq = reader.readSeqNum();
	size_t count = reader.getDataLen();
	size_t seq_diff = seq >= ack_num ? seq - ack_num : SEQ_MAX - ack_num + seq;
	size_t data_pos = (rcv_base + seq_diff) % rcv_size;
	size_t rest_size = rcv_size - data_pos;
	if (count <= rest_size)
		reader.readData(0, rcv_buf + data_pos, count);
	else
	{
		reader.readData(0, rcv_buf + data_pos, rest_size);
		reader.readData(rest_size, rcv_buf, count - rest_size);
	}

	if(ack_num == seq)
	{
		ack_num += count;
		rcv_base = (rcv_base + count) % rcv_size;
		awnd -= count;
		std::unordered_map<uint32_t, uint32_t>::iterator it;
		while((it = unacked.find(ack_num)) != unacked.end())
		{
			uint32_t new_ack = it->second;
			size_t jmp_size = new_ack >= ack_num ? new_ack - ack_num : SEQ_MAX - ack_num + new_ack;
			rcv_base = (rcv_base + jmp_size) % rcv_size;
			awnd -= jmp_size;
			ack_num = new_ack;
			unacked.erase(it);
		}
	}
	else
		unacked[seq] = seq + count;
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
		case READ:
			this->param.readParam = param.readParam;
			break;
		case WRITE:
			this->param.writeParam = param.writeParam;
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

TCPAssignment::TimerPayload::TimerPayload(enum TCPTimer type)
{
	this->type = type;
}
TCPAssignment::TimerPayload::~TimerPayload()
{

}


uint32_t TCPAssignment::rand_seq_num()
{
	return rand();
}

bool TCPAssignment::inSegment(uint32_t seq_begin, uint32_t seq_end, uint32_t seq)
{
	if(seq_end < seq_begin)
		return seq >= seq_begin || seq <= seq_end;
	else
		return seq >= seq_begin && seq <= seq_end;
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
