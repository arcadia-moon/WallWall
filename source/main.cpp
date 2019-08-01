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
//struct json_object *rules;

std::unordered_map<std::string, bool> rules;

static u_int32_t packetFilter(struct nfq_data *tb, bool *isAccept)
{
	int id = 0;
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
		hwph = nfq_get_packet_hw(tb);
		if (hwph)
		{
			int packetIndex = 0;
			char macAddrStr[18];
			mac_addr macAddr = *((mac_addr *)&hwph->hw_addr);
			//int hlen = ntohs(hwph->hw_addrlen);
			//sprintf(macAddrStr, "%02X:%02X:%02X:%02X:%02X:%02X", macAddr.oui[0], macAddr.oui[1], macAddr.oui[2], macAddr.nic[0], macAddr.nic[1], macAddr.nic[2]);
			//printf("%s\n",macAddrStr);
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

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h)
	{
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0)
	{
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &packetCallback, NULL);
	if (!qh)
	{
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0)
	{
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	std::cout << "[*] IP Dest Read Rules File..." << std::endl;
	std::cout << argv[0] << std::endl;

	std::string binExeDir(argv[0]);
	std::string binExeDirBase = binExeDir.substr(0, binExeDir.find_last_of("/"));
	std::ifstream rulesFile(binExeDirBase + "/rules.txt");
	if (!rulesFile)
	{
		std::cout << "[*] Rules File Not Exist!" << std::endl;
	}
	std::cout << binExeDirBase + "/rules.txt" << std::endl;

	std::string rulesStr;
	while (std::getline(rulesFile, rulesStr))
	{
		rules.insert(std::make_pair(rulesStr, true));
	}
	std::cout << "[*] Rule Size : " << rules.size() << std::endl;
	std::cout << "[*] Rules Load Success!" << std::endl;

	fd = nfq_fd(h);

	for (;;)
	{
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0)
		{
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS)
		{
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
