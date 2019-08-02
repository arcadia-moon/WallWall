#include <stdio.h>
#include <stdlib.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <arpa/inet.h>

#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
//#include "../header/lib/json-c/json.h"
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "../header/packet.h"
#include "../header/protocol/all.h"
#include "../header/parser/http.h"
std::unordered_map<std::string, bool> rules;

static u_int32_t packetFilter(struct nfq_data *tb, bool *isAccept)
{
	int id = 0;
	int packetIndex = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;
	std::unordered_map<std::string, bool>::iterator rulesIt;
	ph = nfq_get_msg_packet_hdr(tb);
	if (ph)
	{
		id = ntohl(ph->packet_id);

		if (ntohs(ph->hw_protocol) == ETHERTYPE_IP)
		{
			ret = nfq_get_payload(tb, &data);
			if (ret >= 0)
			{
				const ip_header *ip = (ip_header *)data;
				packetIndex += sizeof(ip_header);
				char ipSrc[INET_ADDRSTRLEN];
				char ipDst[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, &(ip->ip_src), ipSrc, INET_ADDRSTRLEN);
				inet_ntop(AF_INET, &(ip->ip_dst), ipDst, INET_ADDRSTRLEN);

				char rulesCheckIpSrc[29];
				sprintf(rulesCheckIpSrc, "DROP IPV4 SRC %s", ipSrc);
				char rulesCheckIpDst[29];
				sprintf(rulesCheckIpDst, "DROP IPV4 DEST %s", ipDst);

				rulesIt = rules.find(rulesCheckIpSrc);
				*isAccept = rulesIt != rules.end() ? false : *isAccept && true;
				rulesIt = rules.find(rulesCheckIpDst);
				*isAccept = rulesIt != rules.end() ? false : *isAccept && true;

				if (ip->ip_p == IPPROTO_TCP)
				{
					const tcp_header *tcp = (tcp_header *)(data + packetIndex);
					packetIndex += sizeof(tcp_header);
					uint32_t tcp_size = (ntohs(ip->ip_len) - ((ip->ip_hl + tcp->th_off) * 4));

					char rulesCheckPortSrc[19];
					sprintf(rulesCheckPortSrc, "DROP TCP SRC %d", ntohs(tcp->th_sport));
					char rulesCheckPortDst[19];
					sprintf(rulesCheckPortDst, "DROP TCP DEST %d", ntohs(tcp->th_dport));

					rulesIt = rules.find(rulesCheckPortSrc);
					*isAccept = rulesIt != rules.end() ? false : *isAccept && true;
					rulesIt = rules.find(rulesCheckPortDst);
					*isAccept = rulesIt != rules.end() ? false : *isAccept && true;
					if (tcp_size > 0)
					{
						if (ntohs(tcp->th_dport) == 80)
						{
							if (isHTTPProtocol(data + packetIndex, tcp_size))
							{
								std::unordered_map<std::string, std::string> httpHeader;
								parseHTTP(data + packetIndex, tcp_size, &httpHeader);
								//printPacket(data + dataIndex, tcp_size);
								std::string host = httpHeader["Host"];
								std::string method = httpHeader["method"];

								char rulesCheckHTTPHost[2014];
								char rulesCheckHTTPMethod[26];
								sprintf(rulesCheckHTTPHost, "DROP HTTP HOST %s", host.c_str());
								sprintf(rulesCheckHTTPMethod, "DROP HTTP METHOD %s", method.c_str());
								rulesIt = rules.find(rulesCheckHTTPHost);
								*isAccept = rulesIt != rules.end() ? false : *isAccept && true;
								if (!*isAccept)
								{
									std::cout << "[*] HTTP HOST BLOCK : " << host << std::endl;
								}
								
								rulesIt = rules.find(rulesCheckHTTPMethod);
								*isAccept = rulesIt != rules.end() ? false : *isAccept && true;
								if (!*isAccept)
								{
									std::cout << "[*] HTTP METHOD BLOCK : " << method << std::endl;
								}
							}
						}
					}
				}
			}
		}
	}

	return id;
}

static int packetCallback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
						  struct nfq_data *nfa, void *data)
{
	bool *isAccept = new bool(true);
	u_int32_t id = packetFilter(nfa, isAccept);
	return nfq_set_verdict(qh, id, *isAccept ? NF_ACCEPT : NF_DROP, 0, NULL);
}

int main(int argc, char *argv[])
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	std::cout << "[*] Opening library handle" << std::endl;
	h = nfq_open();
	if (!h)
	{
		std::cout << "[*] Error during nfq_open()" << std::endl;
		exit(1);
	}

	std::cout << "[*] Unbinding existing nf_queue handler for AF_INET (if any)" << std::endl;
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		std::cout << "[*] error during nfq_unbind_pf()" << std::endl;
		exit(1);
	}

	std::cout << "[*] Binding nfnetlink_queue as nf_queue handler for AF_INET" << std::endl;
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		std::cout << "[*] Error during nfq_bind_pf()" << std::endl;
		exit(1);
	}

	std::cout << "[*] Binding this socket to queue '0'" << std::endl;
	qh = nfq_create_queue(h, 0, &packetCallback, NULL);
	if (!qh)
	{
		std::cout << "[*] Error during nfq_create_queue()" << std::endl;
		exit(1);
	}

	std::cout << "[*] Setting copy_packet mode" << std::endl;
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		std::cout << "[*] Can't set packet_copy mode" << std::endl;
		exit(1);
	}

	std::cout << "[*] Read Rules File..." << std::endl;
	std::cout << argv[0] << std::endl;

	std::string binExeDir(argv[0]);
	std::string binExeDirBase = binExeDir.substr(0, binExeDir.find_last_of("/"));
	std::ifstream ruleFile(binExeDirBase + "/rules.txt");
	if (!ruleFile)
	{
		std::cout << "[*] Rules File Not Exist!" << std::endl;
	}
	std::cout << binExeDirBase + "/rules.txt" << std::endl;

	std::string ruleStr;
	while (std::getline(ruleFile, ruleStr))
	{
		rules.insert(std::make_pair(ruleStr, true));
	}
	std::cout << "[*] Rule Size : " << rules.size() << std::endl;
	std::cout << "[*] Rules Load Success!" << std::endl;
	fd = nfq_fd(h);

	while (true)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		if (rv < 0 && errno == ENOBUFS)
		{
			std::cout << "[*] Losing Packets!" << std::endl;
			continue;
		}
		perror("recv failed");
		break;
	}

	std::cout << "[*] Unbinding from queue 0" << std::endl;
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	std::cout << "[*] Unbinding from AF_INET" << std::endl;
	nfq_unbind_pf(h, AF_INET);
#endif

	std::cout << "[*] Closing library handle" << std::endl;
	nfq_close(h);

	exit(0);
}
