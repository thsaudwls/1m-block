#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include <vector>
#include <string>
#include <fstream>
#include <chrono>
#include <memory>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

vector<string> sites;
char hostname[128];

clock_t start_time, end_time, data_start_time, data_end_time;
double diff, data_diff;

void dump(unsigned char* buf, int size) 
{
    for (int i = 0; i < size; i++) {
        if (i != 0 && i % 16 == 0)
            printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

string check_host(unsigned char* buf)
{
    string hostname;
    
    for (int i = 0; i < 128; i++)
    {
        if (buf[i] == 'H' && buf[i + 1] == 'o' && buf[i + 2] == 's' && buf[i + 3] == 't')
        {
            for (int j = i + 6; buf[j] != '\0'; j++)
            {   
				hostname += buf[j];
			}	
			
            break;
        }
    }

    return hostname;
}

int binarySearch(const char* a) {
    string str_a(a);

    int left = 0;
    int right = sites.size() - 1;

    while (left <= right) {
        int mid = left + (right - left) / 2;

        if (!strncmp(sites[mid].c_str(), str_a.c_str(), strlen(sites[mid].c_str()))) {
			printf("\n\nsites = %s, host = %s\n\n", sites[mid].c_str(), str_a.c_str());
            return mid; 
        }

        if (sites[mid] < str_a) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }
    }

    return -1; 
}

static uint32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    uint32_t mark, ifi, uid, gid;
    int ret;
    unsigned char *data, *secdata;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    if (nfq_get_uid(tb, &uid))
        printf("uid=%u ", uid);

    if (nfq_get_gid(tb, &gid))
        printf("gid=%u ", gid);

    ret = nfq_get_secctx(tb, &secdata);
    if (ret > 0)
        printf("secctx=\"%.*s\" ", ret, secdata);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    string want_host = check_host(data);

	// printf("\n\n\n\n%s\n\n\n\n", want_host.c_str());
	start_time = clock();
    if (binarySearch(want_host.c_str()) != -1) {
        printf("Blocked site: %s\n", want_host.c_str());
		end_time = clock();
		diff = (double)(end_time - start_time) / CLOCKS_PER_SEC;
		printf("Blocked Time - %f seconds\n\n\n", diff);
        return 4294967295;
    }
    else
	{
		// printf("\n\n\n\nwant host = %s\n\n\n\n", want_host.c_str());
		return id;
	}
	return id;

}
    

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
    uint32_t id = print_pkt(nfa);
    printf("entering callback\n");
    if (id == 4294967295)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

std::string getMemoryUsage(pid_t pid) {
    std::string result;
    std::string command = "top -b -n 1 -p " + std::to_string(pid) + " | grep " + std::to_string(pid);
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    char mem_buf[128];
    while (fgets(mem_buf, sizeof(mem_buf), pipe.get()) != nullptr) {
        result += mem_buf;
    }
    return result;
}

int main(int argc, char **argv)
{
	pid_t pid = getpid(); 

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    uint32_t queue = 0;
    char buf[4096] __attribute__ ((aligned));

    if (argc != 2) {
        printf("syntax : 1m-block <site list file>\n");
        printf("sample : 1m-block top-1m.txt\n");
        return -1;
    }

	std::string memoryUsageBefore = getMemoryUsage(pid);

	FILE *fp = fopen(argv[1], "r");
	if (!fp)
	{
	    printf("Can't open file\n");
	    return -1;
	}

	char buffer[128];
	data_start_time = clock();
	
	while (fgets(buffer, 128, fp))
	{
	    char* comma_position = strchr(buffer, ',');
	    if (comma_position != NULL) {
	        string site(comma_position + 1); // 쉼표 뒤쪽의 문자열로부터 C++ string 생성
	        site.erase(remove(site.begin(), site.end(), '\n'), site.end()); // 문자열 끝의 개행 문자 제거
	        sites.push_back(site); // 주소를 벡터에 추가
	    }
	}
	data_end_time = clock();
	data_diff = (double)(data_end_time - data_start_time) / CLOCKS_PER_SEC;
	printf("Data Saving Time - %f seconds\n\n\n", data_diff);

	fclose(fp);

    sort(sites.begin(), sites.end());

	std::string memoryUsageAfter = getMemoryUsage(pid);

	printf("Memory usage difference: %ld bytes\n", memoryUsageAfter.size() - memoryUsageBefore.size());

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '%d'\n", queue);
    qh = nfq_create_queue(h, queue, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    	fprintf(stderr, "can't set packet_copy mode\n");
	    exit(1);
	}

    printf("setting flags to request UID and GID\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_UID_GID, NFQA_CFG_F_UID_GID)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve process UID/GID.\n");
	}

	printf("setting flags to request security context\n");
	if (nfq_set_queue_flags(qh, NFQA_CFG_F_SECCTX, NFQA_CFG_F_SECCTX)) {
		fprintf(stderr, "This kernel version does not allow to "
				"retrieve security context.\n");
	}

	printf("Waiting for packets...\n");

	fd = nfq_fd(h);

	for (;;) {
    	if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
        	printf("pkt received\n");
    	    nfq_handle_packet(h, buf, rv);
        	continue;
    	}
    	/* if your application is too slow to digest the packets that
    	 * are sent from kernel-space, the socket buffer that we use
    	 * to enqueue packets may fill up returning ENOBUFS. Depending
    	 * on your application, this error may be ignored. Please, see
    	 * the doxygen documentation of this library on how to improve
    	 * this situation.
    	 */
    	if (rv < 0 && errno == ENOBUFS) {
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
