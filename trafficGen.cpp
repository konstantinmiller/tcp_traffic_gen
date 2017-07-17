/****************************************************************************
 * trafficGen.cpp                                                              *
 ****************************************************************************
 * Copyright (C) 2013 Technische Universitaet Berlin                        *
 *                                                                          *
 * Created on: Aug 30, 2013                                                 *
 * Authors: Konstantin Miller <konstantin.miller@tu-berlin.de>              *
 *                                                                          *
 * This program is free software: you can redistribute it and/or modify     *
 * it under the terms of the GNU General Public License as published by     *
 * the Free Software Foundation, either version 3 of the License, or        *
 * (at your option) any later version.                                      *
 *                                                                          *
 * This program is distributed in the hope that it will be useful,          *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of           *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the            *
 * GNU General Public License for more details.                             *
 *                                                                          *
 * You should have received a copy of the GNU General Public License        *
 * along with this program. If not, see <http://www.gnu.org/licenses/>.     *
 ****************************************************************************/

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <cstdlib>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include <getopt.h>
#include <cassert>
#include <pthread.h>
#ifndef __SENDER
# include <pcap.h>
#endif
#include <errno.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <map>
#include <set>
#include <string>
#include <list>
#include <mutex>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <random>

#include <boost/circular_buffer.hpp>

using std::map;
using std::set;
using std::string;
using std::list;
using std::pair;

//#include "VectorList.h"

struct {
    enum {UNDEF, SENDER, RECEIVER} senderReceiver = UNDEF;
    bool ifActive = false;
    uint16_t psvPort = 0;
    string psvIp;
    string actIp;
    int64_t tcp_info_log_interval = 100000; // [us]
} global_info;

struct {
	int fd = -1;
	FILE* logFile = NULL;
	struct tcp_info lastTcpInfo;
} tcp_logger_info;

struct {
    FILE* f_sender_log = NULL;
    bool hang_up = false;
    bool permanent = false;
} sender_info;

struct
{
    /* types */
    enum RequestPatternType {DETERMINISTIC, NORMAL};
    struct RequestPatternDeterministic {
        int64_t on_duration;
        int64_t off_duration;
    };
    struct RequestPatternNormal {
        int64_t mean;
        int64_t std;
        int64_t min;
        int64_t max;
        int64_t tau;  // segment duration, [ms]
    };

    /* request pattern stuff */
    string request_pattern;
    RequestPatternType request_pattern_type;
    union {
        RequestPatternDeterministic request_pattern_deterministic;
        RequestPatternNormal request_pattern_normal;
    };

    string dev_name;
    int64_t dev_wait_max = -1;  // [us]
    string dev_name_mon;
    FILE* file_request_log;
    int64_t request_sent = 0;
    int64_t first_data_received = 0;  // [us]
    int64_t last_data_received = 0;
    int64_t request_size = 0;
    int64_t scheduled_on_duration = 0;
    double max_thrpt = -1;  // [bps]
    int64_t max_thrpt_duration = -1;  // [us]
} rcv_info;

struct rcv_log_info_t
{
    //std::mutex mutex;
    rcv_log_info_t(): pcap_tcp_data(65536), pcap_rdtap_data(65536) {}
#ifndef __SENDER
    static const int pcap_snaplen = 96;
    static const int radiotap_snaplen = 512;
    pcap_t* pcap_tcp = NULL;
    pcap_t* pcap_rdtap = NULL;
    pcap_dumper_t* pcap_dumper_tcp = NULL;
    pcap_dumper_t* pcap_dumper_rdtap = NULL;
#endif
    struct pcap_element {
        pcap_element(const struct pcap_pkthdr* _pkthdr, const u_char* _pktdata) {
            pkthdr = *_pkthdr;
            assert(pkthdr.caplen <= sizeof(pktdata));
            std::memcpy(pktdata, _pktdata, pkthdr.caplen * sizeof(u_char));
        }
        struct pcap_pkthdr pkthdr;
        u_char pktdata[(pcap_snaplen < radiotap_snaplen) ? radiotap_snaplen : pcap_snaplen];
    };
    boost::circular_buffer<pcap_element> pcap_tcp_data;
    boost::circular_buffer<pcap_element> pcap_rdtap_data;
    std::mutex pcap_tcp_data_mutex;
    std::mutex pcap_rdtap_data_mutex;
    //FILE* f = NULL;
    //int64_t dt = 0;  // [us]
    //int64_t ts_first_packet = 0;  // [us]
    //int64_t tcp_ts_first_packet = 0;  // [us]
    //int64_t index = -1;  // [us]

    //int64_t num_bytes = 0;
    //vector<int64_t> delay_vec;  // [us]
    //vector<int> missing_vec;
    //int64_t off1;
    //int64_t off2;

    //void reset() {
    //    num_bytes = 0;
    //    delay_vec.resize(0);
    //    missing_vec.resize(0);
    //    off1 = 0;
    //    off2 = 0;
    //}
} rcv_log_info;

#pragma pack(push, 1)
struct Rcv2Snd_Params {
    uint8_t limitType = 0;  // 0 for time, 1 for volume
    uint32_t limitValue = 0;  // if time: [ms], if volume: [byte]
    uint8_t hang_up = 0;  // 1 for disconnect after request completed, otherwise 0
};
#pragma pack(pop)

void printUsageAndExit(int line);
void parseInputArguments(int argc, char** argv);
void signalHandler(int sig);
void* runSender(void* args);
void* runReceiver(void* args);
void* runTcpStateLogger(void* args);
void* runSniffer(void* _args);
void* runRadiotap(void* _args);
int64_t now();
void recordTcpState(int fd, const char* reason, FILE* f);
void recordTcpState(FILE* f, const struct tcp_info& tcpInfo, const int64_t t, const char* reason);
string tcpState2String(int tcpState);
string tcpCAState2String(int tcpCAState);
//void rcv_log_output();
string getTimeString(int64_t t, bool showDate);
string get_dev_for_ip(string ip);
string get_ip_for_dev(string dev);
bool wait_for_dev(string dev, int64_t max_wait);
void parse_request_pattern(const char* request_pattern);
//void* run_flusher(void* _args);

char buf[1048576];  // for various string manipulations
const int sndbufsize = 1048576; // 8192;
//const int rcvbufsize = 2 * 1048576;
string config;
string traceDir(".");
int64_t Tmax = -1;
int64_t t_start_sender = 0;
int64_t t_start_receiver = 0;
bool terminate_tcp_logger = false;
bool globalTerminationFlag = false;
std::default_random_engine generator(std::chrono::system_clock::now().time_since_epoch().count());

int main(int argc, char** argv)
{
    printf("Up and running...\n");

    sprintf(buf, "main_enter %" PRId64 "\n", now());
    config.append(buf);

	parseInputArguments(argc, argv);

	/* install signal handler */
	struct sigaction sigAction;
	sigAction.sa_handler = signalHandler;
	sigemptyset(&sigAction.sa_mask);
	sigAction.sa_flags = 0;
	assert(0 == sigaction(SIGINT, &sigAction, NULL));
	assert(0 == sigaction(SIGTERM, &sigAction, NULL));
	assert(0 == sigaction(SIGALRM, &sigAction, NULL));

	/* start flusher thread */
	//pthread_t flusher_thread;
	//assert(0 == pthread_create(&flusher_thread, NULL, &run_flusher, NULL));

	if(global_info.senderReceiver == global_info.SENDER)
	{
	    /* open log file */
	    char fn_sender_log[4096];
	    sprintf(fn_sender_log, "%s/sender_log_%016" PRId64 ".txt", traceDir.c_str(), now());
	    sender_info.f_sender_log = fopen(fn_sender_log, "w");
	    assert(sender_info.f_sender_log);
	    setlinebuf(sender_info.f_sender_log);

		pthread_t senderThread;
		while(!globalTerminationFlag) {
		    assert(0 == pthread_create(&senderThread, NULL, &runSender, NULL));
		    assert(0 == pthread_join(senderThread, NULL));
		    if(!sender_info.permanent) {
		        globalTerminationFlag = true;
		        printf("Terminating sender.\n");
		    }
		}

		/* close log file */
		assert(0 == fclose(sender_info.f_sender_log));
	}
	else if(global_info.senderReceiver == global_info.RECEIVER)
	{
		pthread_t receiverThread;
		assert(0 == pthread_create(&receiverThread, NULL, &runReceiver, NULL));
		assert(0 == pthread_join(receiverThread, NULL));
	}
	else
	{
		abort();
	}

	/* wait for the flusher thread */
	//assert(0 == pthread_join(flusher_thread, NULL));

	sprintf(buf, "main_terminate %" PRId64 "\n", now());
	config.append(buf);

	/* write parameters to file */
	if(global_info.senderReceiver == global_info.RECEIVER)
	{
	    sprintf(buf, "%s/rcv_config_%016" PRId64 ".txt", traceDir.c_str(), t_start_receiver);
	    FILE* f = fopen(buf, "w");
	    fprintf(f, "%s", config.c_str());
	    fclose(f);
	}

	return 0;
}

void printUsageAndExit(int line)
{
	printf("Error parsing command line arguments in line %d.\n", line);
    printf("OPTIONS\n");
    printf("\n");
    printf("--role=( sender | receiver )\n");
    printf("    Mandatory.\n");
    printf("\n");
    printf("--active\n");
    printf("    Optional. If set, the peer actively connects to the remote peer.\n");
    printf("\n");
    printf("--permanent\n");
    printf("    Optional. Only valid for the passive peer. If set, does not terminate after the active peer disconnects.\n");
    printf("\n");
    printf("--passive-ip=xxx.xxx.xxx.xxx\n");
    printf("    Mandatory. IP of the passive peer.\n");
    printf("\n");
    printf("--passive-port=<integer>\n");
    printf("    Mandatory. Port of the passive peer.\n");
    printf("\n");
    printf("--active-ip=xxx.xxx.xxx.xxx\n");
    printf("    Optional. If present, specifies the IP of the active peer. Otherwise,\n");
    printf("    the default is used.\n");
    printf("\n");
    printf("--dev-name=<string>\n");
    printf("    Optional, only valid if --active is set and --active-ip is not set. Uses\n");
    printf("    the default IP of the specified network interface as source IP.\n");
    printf("\n");
    printf("--dev-wait-max=<double, [s]>\n");
    printf("    Optional, only valid if --dev-name is set. Waits for device to become\n");
    printf("    available for up to the specified number of seconds.\n");
    printf("\n");
    printf("--dev-name-mon=<string>\n");
    printf("    Device for radiotap recording. If not specified, no readiotap headers are\n");
    printf("    recorded.\n");
    printf("\n");
    printf("--trace-duration=<integer, [s]>\n");
    printf("    Mandatory for active peer, invalid for passive peer. Specifies the\n");
    printf("    duration of the trace.\n");
    printf("\n");
    printf("--max-thrpt=<double, [Mbps]>\n");
    printf("    Optional. Throughput upper bound. If the throughput exceeds upper bound,\n");
    printf("    terminate experiment. If set, --max-thrpt-duration must be set too.\n");
    printf("\n");
    printf("--max-thrpt-duration=<double, [s]>\n");
    printf("    Optional. Specifies duration over which throughput upper bound must not\n");
    printf("    be exceeded. If set, --max-thrpt must be set.\n");
    printf("\n");
    printf("--log-dir=<string>\n");
    printf("    Optional. Directory for file output. If not set, current directory is used.\n");
    printf("\n");
    printf("--tcp-info-log-interval=<integer, [ms]>\n");
    printf("    Optional, between 0 and 1000 ms. Specifies the sampling rate for struct\n");
    printf("    tcp_info. If not set, the default value of 100 ms is used. If set to 0,\n");
    printf("    logging takes place before and after every socket operation.\n");
    printf("\n");
    printf("--request-pattern=<string>\n");
    printf("    Optional, only valid for receiver. If not set, a continuous TCP flow of\n");
    printf("    duration specified in --trace-duration is requested. Possible values are:\n");
    printf("    deterministic:AAA:BBB\n");
    printf("        AAA, BBB: integer, [ms]\n");
    printf("        Generates an ON/OFF pattern with deterministic duration of ON and OFF\n");
    printf("        phases. AAA specifies the duration of the request (ON phase), while BBB\n");
    printf("        specifies the duration of the inter-request gap (OFF phase).\n");
    printf("    normal:AAA:BBB:CCC:DDD:EEE\n");
    printf("        AAA, BBB, CCC, DDD, EEE: integer, [ms]\n");
    printf("        Generates a random ON/OFF pattern with normally distributed duration of\n");
    printf("        of the ON phase, with mean AAA and standard deviation BBB. In order to\n");
    printf("        avoid negative or very long values, only values with the interval\n");
    printf("        [CCC, DDD] are accepted. The duration of the OFF phase is determined\n");
    printf("        EEE and the duration of the ON phase. If ON phase is longer than EEE,\n");
    printf("        there is no OFF phase. Otherwise, the duration of the OFF phase is\n");
    printf("        EEE - duration of the ON phase.\n");
    printf("\n");
#if 0
    printf("EXAMPLES\n");
    printf("sudo ./trafficGen --role=receiver --active --passive-ip=130.149.49.253 --passive-port=54321 --dev-name=wlan0 --trace-duration=60 --log-dir=. --tcp-info-log-interval=1000\n");
    printf("    Generates a continuous TCP flow with duration 60 seconds.\n");
    printf("\n");
    printf("sudo ./trafficGen --role=receiver --active --passive-ip=130.149.49.253 --passive-port=54321 --dev-name=wlan0 --trace-duration=60 --log-dir=. --tcp-info-log-interval=1000 --request-pattern=normal:1600:400:1200:2400:2000\n");
    printf("    Generates a TCP flow with deterministic ON/OFF pattern, with total duration of 60 seconds.\n");
    printf("\n");
    printf("sudo ./trafficGen --role=receiver --active --passive-ip=130.149.49.253 --passive-port=54321 --dev-name=wlan0 --trace-duration=60 --log-dir=. --tcp-info-log-interval=1000 --request-pattern=deterministic:1600:400\n");
    printf("    Generates a TCP flow with normally distributed ON duration, with total duration of 60 seconds.\n");
    printf("\n");
#endif
	exit(1);
}

void parseInputArguments(int argc, char** argv)
{
	enum {HELP='0', ROLE='a', IS_ACTIVE='b', IS_PERMANENT='c', PASSIVE_IP='d', PASSIVE_PORT='e', ACTIVE_IP='f', DEV_NAME='g',
		TRACE_DURATION='h', LOG_DIR='i', TCP_INFO_LOG_INTERVAL='j', REQUEST_PATTERN='k', DEV_NAME_MON='l', MAX_THRPT='m', MAX_THRPT_DURATION='n',
		DEV_WAIT_MAX='o'};

	while(true)
	{
	    static struct option long_options[] =
	    {
	            {"help",                        no_argument,  0, HELP},
	            {"role",                  required_argument,  0, ROLE},
	            {"active",                      no_argument,  0, IS_ACTIVE},
	            {"permanent",                   no_argument,  0, IS_PERMANENT},
	            {"passive-ip",            required_argument,  0, PASSIVE_IP},
	            {"passive-port",          required_argument,  0, PASSIVE_PORT},
	            {"active-ip",             required_argument,  0, ACTIVE_IP},
	            {"dev-name",              required_argument,  0, DEV_NAME},
	            {"dev-wait-max",          required_argument,  0, DEV_WAIT_MAX},
	            {"dev-name-mon",          required_argument,  0, DEV_NAME_MON},
	            {"trace-duration",        required_argument,  0, TRACE_DURATION},
	            {"max-thrpt",             required_argument,  0, MAX_THRPT},
	            {"max-thrpt-duration",    required_argument,  0, MAX_THRPT_DURATION},
	            {"log-dir",               required_argument,  0, LOG_DIR},
	            {"tcp-info-log-interval", required_argument,  0, TCP_INFO_LOG_INTERVAL},
	            {"request-pattern",       required_argument,  0, REQUEST_PATTERN},
	            {0, 0, 0, 0}
	    };

	    int c = getopt_long (argc, argv, "", long_options, NULL);
	    if (c == -1) break;

	    switch(c)
	    {
	    case HELP:
	        printUsageAndExit(__LINE__);
	        break;
	    case ROLE:
	        if(global_info.senderReceiver != global_info.UNDEF) printUsageAndExit(__LINE__);
	        if(strcmp(optarg, "sender") == 0) global_info.senderReceiver = global_info.SENDER;
	        else if(strcmp(optarg, "receiver") == 0) global_info.senderReceiver = global_info.RECEIVER;
	        else printUsageAndExit(__LINE__);
	        sprintf(buf, "role %s\n", optarg);
	        config.append(buf);
	        break;
	    case IS_ACTIVE:
	        global_info.ifActive = true;
	        sprintf(buf, "active 1\n");
	        config.append(buf);
	        break;
	    case IS_PERMANENT:
	        sender_info.permanent = true;
	        sprintf(buf, "permanent 1\n");
	        config.append(buf);
	        break;
	    case PASSIVE_IP:
	        if(!global_info.psvIp.empty()) printUsageAndExit(__LINE__);
	        global_info.psvIp = optarg;
	        sprintf(buf, "passive_ip %s\n", global_info.psvIp.c_str());
	        config.append(buf);
	        break;
	    case PASSIVE_PORT:
	    {
	        if(global_info.psvPort != 0) printUsageAndExit(__LINE__);
	        char* endptr = NULL;
	        global_info.psvPort = strtol(optarg, &endptr, 10);
	        if(*endptr != '\0') printUsageAndExit(__LINE__);
	        sprintf(buf, "passive_port %" PRIu16 "\n", global_info.psvPort);
	        config.append(buf);
	        break;
	    }
	    case ACTIVE_IP:
            if(!global_info.actIp.empty()) printUsageAndExit(__LINE__);
            global_info.actIp = optarg;
            sprintf(buf, "active_ip %s\n", global_info.actIp.c_str());
            config.append(buf);
            break;
	    case DEV_NAME:
	        if(!rcv_info.dev_name.empty()) printUsageAndExit(__LINE__);
	        rcv_info.dev_name = optarg;
	        sprintf(buf, "dev_name %s\n", rcv_info.dev_name.c_str());
	        config.append(buf);
	        break;
	    case DEV_WAIT_MAX:
	    {
	    	if(rcv_info.dev_wait_max != -1) printUsageAndExit(__LINE__);
	    	char* endptr = NULL;
	    	rcv_info.dev_wait_max = 1e6 * strtod(optarg, &endptr);
	    	if(*endptr != '\0') printUsageAndExit(__LINE__);
	    	sprintf(buf, "dev_wait_max %.3f\n", rcv_info.dev_wait_max / 1e6);
	    	config.append(buf);
	    	break;
	    }
	    case DEV_NAME_MON:
	        if(!rcv_info.dev_name_mon.empty()) printUsageAndExit(__LINE__);
	        rcv_info.dev_name_mon = optarg;
	        sprintf(buf, "dev_name_mon %s\n", rcv_info.dev_name_mon.c_str());
	        config.append(buf);
	        break;
	    case TRACE_DURATION:
	    {
	        if(Tmax != -1) printUsageAndExit(__LINE__);
	        char* endptr = NULL;
	        Tmax = (int64_t)1000000 * (int64_t)strtol(optarg, &endptr, 10);
	        if(*endptr != '\0') printUsageAndExit(__LINE__);
	        sprintf(buf, "Tmax %" PRId64 "\n", Tmax);
	        config.append(buf);
	        break;
	    }
	    case MAX_THRPT:
	    {
	        if(rcv_info.max_thrpt != -1) printUsageAndExit(__LINE__);
	        char* endptr = NULL;
	        rcv_info.max_thrpt = 1e6 * strtod(optarg, &endptr);
	        if(*endptr != '\0') printUsageAndExit(__LINE__);
	        sprintf(buf, "max_thrpt %.3f\n", rcv_info.max_thrpt);
	        config.append(buf);
	        break;
	    }
	    case MAX_THRPT_DURATION:
	    {
	        if(rcv_info.max_thrpt_duration != -1) printUsageAndExit(__LINE__);
	        char* endptr = NULL;
	        rcv_info.max_thrpt_duration = 1e6 * strtod(optarg, &endptr);
	        if(*endptr != '\0') printUsageAndExit(__LINE__);
	        sprintf(buf, "max_thrpt_duration %" PRId64 "\n", rcv_info.max_thrpt_duration);
	        config.append(buf);
	        break;
	    }
	    case LOG_DIR:
            traceDir = optarg;
            sprintf(buf, "log_dir %s\n", traceDir.c_str());
            config.append(buf);
            break;
	    case TCP_INFO_LOG_INTERVAL:
	    {
	        char* endptr = NULL;
	        global_info.tcp_info_log_interval = (int64_t)1000 * (int64_t)strtol(optarg, &endptr, 10);
	        if(*endptr != '\0') printUsageAndExit(__LINE__);
	        sprintf(buf, "tcp_info_log_interval %" PRId64 "\n", global_info.tcp_info_log_interval);
	        config.append(buf);
	        break;
	    }
	    case REQUEST_PATTERN:
	        if(!rcv_info.request_pattern.empty()) printUsageAndExit(__LINE__);
	        parse_request_pattern(optarg);
	        sprintf(buf, "request_pattern %s\n", optarg);
	        config.append(buf);
	        break;
	    default:
	        printUsageAndExit(__LINE__);
	    }

	}

	/* Input arguments consistency check */
	// if(global_info.psvIp.empty() || 49152 > global_info.psvPort || global_info.psvPort > 65535) printUsageAndExit(__LINE__);
	if(global_info.psvIp.empty()) printUsageAndExit(__LINE__);
	if(global_info.ifActive && sender_info.permanent) printUsageAndExit(__LINE__);
	if(global_info.psvIp.empty() || global_info.psvPort == 0) printUsageAndExit(__LINE__);
    if(!rcv_info.dev_name.empty() && !(global_info.ifActive && global_info.actIp.empty())) printUsageAndExit(__LINE__);
    if((Tmax == -1 && global_info.ifActive) || (Tmax != -1 && !global_info.ifActive)) printUsageAndExit(__LINE__);
    if(!rcv_info.request_pattern.empty() && global_info.senderReceiver == global_info.SENDER) printUsageAndExit(__LINE__);
    if((rcv_info.max_thrpt != -1 && rcv_info.max_thrpt_duration == -1) || (rcv_info.max_thrpt == -1 && rcv_info.max_thrpt_duration != -1) || (rcv_info.max_thrpt != -1 && global_info.senderReceiver == global_info.SENDER)) printUsageAndExit(__LINE__);
    if(global_info.senderReceiver == global_info.SENDER && rcv_info.dev_wait_max != -1) printUsageAndExit(__LINE__);
}

void* runSender(void* _args)
{
	int _fd = -1;
	int fd = -1;

	if(global_info.ifActive)
	{
	    fd = socket(AF_INET, SOCK_STREAM, 0);
	    assert(-1 != fd);

	    if(!global_info.actIp.empty())
	    {
	        struct sockaddr_in sockaddr_src;
	        memset(&sockaddr_src, 0, sizeof(sockaddr_src));
	        sockaddr_src.sin_family = AF_INET;
	        sockaddr_src.sin_addr.s_addr = inet_addr(global_info.actIp.c_str());
	        assert(0 == bind(fd, (struct sockaddr*)&sockaddr_src, sizeof(struct sockaddr_in)));
	    }

	    struct sockaddr_in sockaddr;
	    sockaddr.sin_family = AF_INET;
	    sockaddr.sin_addr.s_addr = inet_addr(global_info.psvIp.c_str());
	    sockaddr.sin_port = htons(global_info.psvPort);
	    assert(-1 != connect(fd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr_in)));
	}

	/* passive sender */
	else
	{
	    _fd = socket(AF_INET, SOCK_STREAM, 0);
	    assert(-1 != _fd);

	    if(sender_info.permanent) {
	        int optval = 1;
	        setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	    }

	    fprintf(sender_info.f_sender_log, "%s Binding to %s:%u.\n", getTimeString(0, true).c_str(), global_info.psvIp.c_str(), global_info.psvPort);
	    struct sockaddr_in sockaddr;
	    sockaddr.sin_family = AF_INET;
	    sockaddr.sin_addr.s_addr = inet_addr(global_info.psvIp.c_str());
	    sockaddr.sin_port = htons(global_info.psvPort);
	    assert(0 == bind(_fd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr_in)));

	    assert(0 == listen(_fd, 0));

	    /* waiting for incoming connections */
	    while(!globalTerminationFlag && fd == -1)
	    {
	        fd_set readfds;
	        FD_ZERO(&readfds);
	        FD_SET(_fd, &readfds);
	        struct timeval to;
	        to.tv_sec = 1;
	        to.tv_usec = 0;
	        int ret = select(_fd + 1, &readfds, NULL, NULL, &to);
	        if(ret < 0)
	        {
	            perror("select()");
	            abort();
	        }
	        else if(ret == 0)
	        {
	            continue;
	        }
	        else if(ret == 1)
	        {
	            struct sockaddr_in activeSockaddr;
	            unsigned senderSockaddrLength = sizeof(struct sockaddr_in);
	            fd = accept(_fd, (struct sockaddr*)&activeSockaddr, &senderSockaddrLength);
	            assert(fd > 0 && senderSockaddrLength == sizeof(struct sockaddr_in));
	            fprintf(sender_info.f_sender_log, "%s Got incoming connection from %s:%d.\n", getTimeString(0, true).c_str(), inet_ntoa(activeSockaddr.sin_addr), ntohs(activeSockaddr.sin_port));
	        }
	        else
	        {
	            abort();
	        }
	    }

	    if(globalTerminationFlag){
	        assert(0 == close(_fd));
	        if(fd != -1)
	            assert(0 == close(fd));
	        return NULL;
	    }

	    if(_fd != -1) assert(0 == close(_fd));
	}
	assert(fd != -1);

	t_start_sender = now();
	fprintf(sender_info.f_sender_log, "%s Starting sender %" PRId64 ".\n", getTimeString(0, true).c_str(), t_start_sender);

	// adjust sending buffer size
	//assert(0 == setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbufsize, sizeof(sndbufsize)));
    /* disable Nagle */
    //const int disable_nagle = 1;
    //assert(0 == setsockopt(fd, SOL_TCP, TCP_NODELAY, &disable_nagle, sizeof(disable_nagle)));

	// log sending buffer size
	{
	    int dummy_int = 0;
	    unsigned dummy_int_size = sizeof(dummy_int);
	    assert(0 == getsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void*)&dummy_int, &dummy_int_size));
	    sprintf(buf, "%s/snd_config_%016" PRId64 ".txt", traceDir.c_str(), t_start_sender);
	    FILE* f = fopen(buf, "w");
	    sprintf(buf, "SO_SNDBUF %d\n", dummy_int);
	    fprintf(f, "%s", buf);
	    fclose(f);
	}

	/* open file for logging */
	char logFileName[2048];
	sprintf(logFileName, "%s/snd_tcpinfo_log_%016" PRId64 ".txt", traceDir.c_str(), t_start_sender);
    FILE* logFile = fopen(logFileName, "w");
    assert(logFile);

    /* starting logger thread */
	tcp_logger_info.fd = fd;
	tcp_logger_info.logFile = logFile;
	terminate_tcp_logger = false;
	pthread_t loggerThread;
	if(global_info.tcp_info_log_interval > 0)
		assert(0 == pthread_create(&loggerThread, NULL, &runTcpStateLogger, NULL));

	do  // while not hang up
	{
	    /* if passive, read Tmax from the active peer */
	    if(!global_info.ifActive)
	    {
	        fd_set readfds;
	        FD_ZERO(&readfds);
	        FD_SET(fd, &readfds);
	        struct timeval to;
	        to.tv_sec = 1;
	        to.tv_usec = 0;
	        int ret = select(fd + 1, &readfds, NULL, NULL, &to);
	        if(ret < 0) {
	            perror("select()");
	            throw std::runtime_error("Error in select() 1.\n");
	        } else if(ret == 0) {
	            sender_info.hang_up = false;
	            continue;
	        } else if(ret > 1) {
	            throw std::runtime_error("Error in select() 2.\n");
	        }
	        assert(FD_ISSET(fd, &readfds));

	        Rcv2Snd_Params rcv2snd_params;
	        int br = read(fd, &rcv2snd_params, sizeof(rcv2snd_params));
	        assert(br >= 0);
	        if(br == 0) {
	            printf("%s ERROR: Connection %" PRId64 " reset by peer.\n", getTimeString(0, true).c_str(), t_start_sender);
	            fprintf(sender_info.f_sender_log, "%s ERROR: Connection %" PRId64 " reset by peer.\n", getTimeString(0, true).c_str(), t_start_sender);
	            break;
	        } else {
	            assert(br == sizeof(rcv2snd_params));
	        }
	        rcv2snd_params.limitValue = ntohl(rcv2snd_params.limitValue);

	        sender_info.hang_up = rcv2snd_params.hang_up;

	        if(rcv2snd_params.limitType == 0) {
	            Tmax = (int64_t)rcv2snd_params.limitValue * 1000;
	            fprintf(sender_info.f_sender_log, "%s Will send data for AT LEAST %.3f seconds and %shang up.\n", getTimeString(0, true).c_str(), Tmax / 1e6, sender_info.hang_up ? "" : "NOT ");
	        } else {
	            throw std::runtime_error("only supporting time for the moment.");
	        }
	    }

	    int64_t bytesSent = 0;
	    int64_t bufSend[sndbufsize >> 3];
	    memset(bufSend, 0, sizeof(int64_t));
	    int64_t Tstart = now();
	    int64_t chunk_size = sndbufsize;  // [byte]
	    double nextInfoOutput = Tmax >= 100000000 ? 0.01 : (Tmax >= 5000000 ? 0.1 : 2.0);  // never output for short requests
	    //int cnt_write = 0;
	    //boost::circular_buffer<int64_t> chunk_times(10);
	    //boost::circular_buffer<int64_t> chunk_sizes(10);
	    //boost::circular_buffer<double> chunk_thrpts(10);
	    //for(int i = 0; i < chunk_times.size(); ++i) {chunk_times.push_back(100000); chunk_sizes.push_back(65536); chunk_thrpts.push_back((8.0 * chunk_sizes.at(i)) / (chunk_times.at(i) / 1e6));}
	    while(!globalTerminationFlag)
	    {
	        //int value = -1;
	        //assert(0 == ioctl(fd, TIOCOUTQ, &value) && value != -1);
	        //printf("Still have %d bytes to send.\n", value);

	    	/* send next portion of data */
	        //for(int64_t i = 0; i < (chunk_size >> 3); ++i)
	        //    bufSend[i] = bytesSent + 8 * (i + 1);
	        if(global_info.tcp_info_log_interval == 0) recordTcpState(fd, "before write", logFile);
	        int64_t tic_write = now();
	        int ret = write(fd, bufSend, chunk_size);
	        //printf("After write. ret: %d\n", ret);
	        //++cnt_write;
	        int64_t toc_write = now();
	        if(ret == -1 && errno == ECONNRESET) {
	            perror("write()");
	            printf("ERROR: Connection %" PRId64 " reset by peer while sending data.\n", t_start_sender);
	            fprintf(sender_info.f_sender_log, "%s ERROR: Connection %" PRId64 " reset by peer while sending data.\n", getTimeString(0, true).c_str(), t_start_sender);
	            sender_info.hang_up = true;
	            break;
	        } else if(ret == -1){
	            perror("write()");
	            static char buf[2048];
	            sprintf(buf, "Could not write %" PRId64 " bytes to socket.\n", chunk_size);
	            throw std::runtime_error(buf);
	        }

	        assert(ret >= 0);
	        bytesSent += ret;
	        if(global_info.tcp_info_log_interval == 0) recordTcpState(fd, "after write", logFile);
	        if(ret != chunk_size) {
	        	printf("ERROR: Could not complete writing chunk to socket. Potential reason: connection %" PRId64 " reset by peer while sending data.\n", t_start_sender);
	        	fprintf(sender_info.f_sender_log, "%s ERROR: Could not complete writing chunk to socket. Potential reason: connection %" PRId64 " reset by peer while sending data.\n",
	        			getTimeString(0, true).c_str(), t_start_sender);
	        	sender_info.hang_up = true;
	        	break;
	        }
	        assert(ret == chunk_size);

	        const int64_t t = now();
	        if(t - Tstart >= Tmax - tcp_logger_info.lastTcpInfo.tcpi_rtt / 2)
	        {
	            //printf("%d writes, %.0f writes per sec., %.0f ms inter-write time.\n", cnt_write, cnt_write / ((t - Tstart) / 1e6), ((t - Tstart) / 1e3) / cnt_write);
	            //cnt_write = 0;

	            printf("Request completed: %6.3f seconds.\n", (t - Tstart) / 1e6);
	            fprintf(sender_info.f_sender_log, "%s Tmax (%d sec) expired. Sender: %" PRId64 ".\n", getTimeString(0, true).c_str(), (int)(Tmax / 1000000), t_start_sender);
	            if(global_info.tcp_info_log_interval == 0) recordTcpState(fd, "before write", logFile);
	            uint8_t _tmp = 1;
	            int ret = write(fd, (void*)&_tmp, 1);
	            if(ret == -1 && errno == ECONNRESET) {
	                perror("write()");
	                printf("ERROR: Connection %" PRId64 " reset by peer while finalizing request.\n", t_start_sender);
	                fprintf(sender_info.f_sender_log, "%s ERROR: Connection %" PRId64 " reset by peer while finalizing request.\n", getTimeString(0, true).c_str(), t_start_sender);
	                sender_info.hang_up = true;
	                break;
	            } else if(ret == -1){
	                perror("write()");
	                static char buf[2048];
	                sprintf(buf, "Could not write %u bytes to socket.\n", (unsigned)sizeof(_tmp));
	                throw std::runtime_error(buf);
	            } else {
	            	assert(ret == sizeof(_tmp));
	                //printf("Sent %d bytes.\n", ret);
	            }
	            if(global_info.tcp_info_log_interval == 0) recordTcpState(fd, "after write", logFile);
	            break;
	        } else if((double)(t - Tstart) / (double)Tmax >= nextInfoOutput) {
	            nextInfoOutput += Tmax >= 100000000 ? 0.01 : 0.1;
	            printf("Progress: %6.2f%%.\n", 100.0 * (double)(t - Tstart) / (double)Tmax);
	        }

	        // determine chunk size
	        //chunk_times.push_back(toc_write - tic_write);
	        //chunk_sizes.push_back(chunk_size);
	        //chunk_thrpts.push_back((8.0 * chunk_sizes.back()) / (chunk_times.back() / 1e6));
	        //double chunk_thrpt = std::accumulate(chunk_sizes.begin(), chunk_sizes.end(), 0.0) / (std::accumulate(chunk_times.begin(), chunk_times.end(), 0.0) / 1e6);  // [byte/sec]
	        //for(int i = 0; i < chunk_times.size(); ++i) chunk_thrpt += 1.0 / chunk_times.size() * chunk_sizes.at(i) / ((double)chunk_times.at(i) / 1e6);
	        //const int64_t chunk_size_old = chunk_size;
	        //chunk_size = 0.05 / 8.0 * *std::min_element(chunk_thrpts.begin(), chunk_thrpts.end());  // number of byte to be send in approximately 100 ms
	        //chunk_size = std::min<int64_t>(chunk_size, 65536);
	        //chunk_size = std::max<int64_t>(chunk_size, 8192);
	        //chunk_size = sndbufsize;
	        //printf("old chunk_size: %5" PRId64 ", duration: %8.6f, new chunk_size: %5" PRId64 "\n", chunk_size_old, (toc_write - tic_write) / 1e6, chunk_size);
	    }
	} while(!sender_info.hang_up);

	terminate_tcp_logger = true;
	if(global_info.tcp_info_log_interval > 0)
		assert(0 == pthread_join(loggerThread, NULL));

	/* close log file */
    assert(0 == fclose(logFile));

    /* shutdown connection and close sockets */
    shutdown(fd, SHUT_RDWR);  // intentionally don't check return value
	assert(0 == close(fd));
	//if(_fd != -1) assert(0 == close(_fd));

	fprintf(sender_info.f_sender_log, "%s All sockets closed.\n", getTimeString(0, true).c_str());

    /* write parameters to file */
    {
        sprintf(buf, "%s/snd_config_%016" PRId64 ".txt", traceDir.c_str(), t_start_sender);
        FILE* f = fopen(buf, "w");
        fprintf(f, "%s", config.c_str());
        fclose(f);
    }

	return NULL;
}

void* runReceiver(void* _args)
{
#ifndef __SENDER
    int _fd = -1;
    int fd = -1;

    if(global_info.ifActive)
    {
    	/* wait for device to become available */
    	if(!rcv_info.dev_name.empty() && rcv_info.dev_wait_max > 0 && !wait_for_dev(rcv_info.dev_name, rcv_info.dev_wait_max))
    		return NULL;

    	/* create socket */
        fd = socket(AF_INET, SOCK_STREAM, 0);
        assert(-1 != fd);

        /* bind to specified network interface or IP if requested */
        if(!global_info.actIp.empty() || !rcv_info.dev_name.empty())
        {
            if(rcv_info.dev_name.empty())
                rcv_info.dev_name = get_dev_for_ip(global_info.actIp);
            if(global_info.actIp.empty()) {
                global_info.actIp = get_ip_for_dev(rcv_info.dev_name);
                printf("Determined %s as IP address of %s.\n", global_info.actIp.c_str(), rcv_info.dev_name.c_str());
            }

            struct sockaddr_in sockaddr_src;
            memset(&sockaddr_src, 0, sizeof(sockaddr_src));
            sockaddr_src.sin_family = AF_INET;
            sockaddr_src.sin_addr.s_addr = inet_addr(global_info.actIp.c_str());
            assert(0 == bind(fd, (struct sockaddr*)&sockaddr_src, sizeof(struct sockaddr_in)));
            printf("Bound to specified active IP.\n");
        }

        /* connect */
        struct sockaddr_in sockaddr;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = inet_addr(global_info.psvIp.c_str());
        sockaddr.sin_port = htons(global_info.psvPort);
        assert(-1 != connect(fd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr_in)));
        printf("Connected.\n");
    }
    else
    {
        _fd = socket(AF_INET, SOCK_STREAM, 0);
        assert(-1 != _fd);

        printf("Binding to %s:%u.\n", global_info.psvIp.c_str(), global_info.psvPort);
        struct sockaddr_in sockaddr;
        sockaddr.sin_family = AF_INET;
        sockaddr.sin_addr.s_addr = inet_addr(global_info.psvIp.c_str());
        sockaddr.sin_port = htons(global_info.psvPort);
        assert(0 == bind(_fd, (struct sockaddr*)&sockaddr, sizeof(struct sockaddr_in)));

        assert(0 == listen(_fd, 0));
        printf("Ready and listening for incoming connections.\n");

        while(!globalTerminationFlag && fd == -1)
        {
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(_fd, &readfds);
            struct timeval to;
            to.tv_sec = 1;
            to.tv_usec = 0;
            int ret = select(_fd + 1, &readfds, NULL, NULL, &to);
            if(ret < 0)
            {
                perror("select()");
                abort();
            }
            else if(ret == 0)
            {
                continue;
            }
            else if(ret == 1)
            {
                struct sockaddr_in activeSockaddr;
                unsigned senderSockaddrLength = sizeof(struct sockaddr_in);
                fd = accept(_fd, (struct sockaddr*)&activeSockaddr, &senderSockaddrLength);
                assert(fd > 0 && senderSockaddrLength == sizeof(struct sockaddr_in));
                printf("Got incoming connection from %s:%d.\n", inet_ntoa(activeSockaddr.sin_addr), ntohs(activeSockaddr.sin_port));
            }
            else
            {
                abort();
            }
        }

        if(globalTerminationFlag){
            assert(0 == close(_fd));
            if(fd != -1)
                assert(0 == close(fd));
            return NULL;
        }
    }
    assert(fd != -1);

    // adjust receiving buffer size
    //assert(0 == setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbufsize, sizeof(rcvbufsize)));

    // log receiving buffer size
    int dummy_int = 0;
    unsigned dummy_int_size = sizeof(dummy_int);
    assert(0 == getsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void*)&dummy_int, &dummy_int_size));
    sprintf(buf, "SO_RCVBUF %d\n", dummy_int);
    config.append(buf);

    t_start_receiver = now();

    /* initialize pcap sniffer and radiotap monitor */
    pthread_t snifferThread, radiotapThread;
    if(!rcv_info.dev_name.empty())
        assert(0 == pthread_create(&snifferThread, NULL, &runSniffer, NULL));
    if(!rcv_info.dev_name_mon.empty())
        assert(0 == pthread_create(&radiotapThread, NULL, &runRadiotap, NULL));
    sleep(2); // give the sniffers some time to initialize

    /* open file for logging */
    char logFileName[4096];
    sprintf(logFileName, "%s/rcv_tcpinfo_log_%016" PRId64 ".txt", traceDir.c_str(), t_start_receiver);
    tcp_logger_info.logFile = fopen(logFileName, "w");
    assert(tcp_logger_info.logFile);

    /* start logger thread */
    tcp_logger_info.fd = fd;
	pthread_t loggerThread;
	if(global_info.tcp_info_log_interval > 0)
		assert(0 == pthread_create(&loggerThread, NULL, &runTcpStateLogger, NULL));

	/* open file for request logging */
	char fn_request_log[4096];
	sprintf(fn_request_log, "%s/rcv_request_log_%016" PRId64 ".txt", traceDir.c_str(), t_start_receiver);
	rcv_info.file_request_log = fopen(fn_request_log, "w");
	assert(rcv_info.file_request_log);
	fprintf(rcv_info.file_request_log, "|     request_sent | first_data_received | last_data_received | request_size | scheduled_on_duration |\n");

	/* loop over requests */
	bool log_to_console = true;
	while(!globalTerminationFlag)
	{
	    /* if active, send request parameters */
	    if(global_info.ifActive)
	    {
	        const int64_t _now = now();

	        rcv_info.request_sent = _now;
	        rcv_info.first_data_received = 0;

	        assert(Tmax > 0);
	        if(rcv_info.request_pattern.empty())
	        {
	            rcv_info.scheduled_on_duration = Tmax;

	            Rcv2Snd_Params rcv2snd_params;
	            rcv2snd_params.limitType = 0;
	            rcv2snd_params.limitValue = htonl((uint32_t)(rcv_info.scheduled_on_duration / 1000));
	            rcv2snd_params.hang_up = true;
	            assert(sizeof(rcv2snd_params) == write(fd, &rcv2snd_params, sizeof(rcv2snd_params)));
	        }
	        else if(rcv_info.request_pattern_type == rcv_info.DETERMINISTIC)
	        {
	            rcv_info.scheduled_on_duration = rcv_info.request_pattern_deterministic.on_duration;

	            Rcv2Snd_Params rcv2snd_params;
	            rcv2snd_params.limitType = 0;
	            rcv2snd_params.limitValue = htonl((uint32_t)(rcv_info.scheduled_on_duration / 1000));
	            if(_now + rcv_info.request_pattern_deterministic.on_duration + rcv_info.request_pattern_deterministic.off_duration - t_start_receiver >= Tmax)
	                rcv2snd_params.hang_up = true;
	            else
	                rcv2snd_params.hang_up = false;
	            assert(sizeof(rcv2snd_params) == write(fd, &rcv2snd_params, sizeof(rcv2snd_params)));
	        }
	        else if(rcv_info.request_pattern_type == rcv_info.NORMAL)
	        {
	            std::normal_distribution<double> distribution(rcv_info.request_pattern_normal.mean, rcv_info.request_pattern_normal.std);
	            rcv_info.scheduled_on_duration = 0;
	            do {
	                rcv_info.scheduled_on_duration = distribution(generator);
	            } while(rcv_info.request_pattern_normal.min <= rcv_info.scheduled_on_duration && rcv_info.scheduled_on_duration <= rcv_info.request_pattern_normal.max);

	            Rcv2Snd_Params rcv2snd_params;
	            rcv2snd_params.limitType = 0;
	            rcv2snd_params.limitValue = htonl((uint32_t)(rcv_info.scheduled_on_duration / 1000));
	            if(_now + rcv_info.request_pattern_normal.tau - t_start_receiver >= Tmax)
	                rcv2snd_params.hang_up = true;
	            else
	                rcv2snd_params.hang_up = false;
	            assert(sizeof(rcv2snd_params) == write(fd, &rcv2snd_params, sizeof(rcv2snd_params)));
	        }
	        else
	        {
	            throw std::runtime_error("Unknown request pattern: " + rcv_info.request_pattern);
	        }

	        log_to_console = rcv_info.scheduled_on_duration / 1e6 >= 5 ? true : false;
	    }

	    /* loop until all bytes of the request have been received */
	    int64_t bytesReceived = 0;
	    int64_t bytes_received_last_output = 0;
	    uint8_t bufReceive[1048576];
        int64_t t_first_data = 0;
        int64_t t_last_output = 0;
	    while(!globalTerminationFlag)
	    {
	    	/* sleep until there is data in the socket to read */
	        fd_set readfds;
	        FD_ZERO(&readfds);
	        FD_SET(fd, &readfds);
	        struct timeval to;
	        to.tv_sec = 1;
	        to.tv_usec = 0;
	        int ret = select(fd + 1, &readfds, NULL, NULL, &to);
	        if(ret < 0) {
	            perror("select()");
	            abort();
	        } else if(ret == 0) {
	            continue;
	        } else if(ret > 1) {
	            abort();
	        }

	        /* read data from the socket */
	        assert(FD_ISSET(fd, &readfds));
	        int br = 0;
	        if(global_info.tcp_info_log_interval == 0) recordTcpState(fd, "before recv", tcp_logger_info.logFile);
	        br = recv(fd, bufReceive, sizeof(bufReceive), MSG_DONTWAIT);
	        assert(br >= 0);
	        if(global_info.tcp_info_log_interval == 0) recordTcpState(fd, "after recv", tcp_logger_info.logFile);

	        const int64_t _now = now();

	        if(rcv_info.first_data_received == 0) rcv_info.first_data_received = _now;

	        /* If the sender closed the connection -> terminate. */
	        if(br == 0)
	        {
	            printf("Sender closed the connection.\n");
	            globalTerminationFlag = true;
	            continue;
	        }

	        /* throughput logging to console */
	        if(t_first_data == 0) {
	        	t_first_data = t_last_output = _now;
	        }
	        bytesReceived += br;
	        if(log_to_console && (_now - t_last_output) / 1e6 >= 1)
	        {
	        	printf("Received %.6f MB. Average throughput last second: %.3f Mbps, total: %.3f Mbps.\n",
	        			bytesReceived / 1e6,
	        			8.0 * (bytesReceived - bytes_received_last_output) / (double)(_now - t_last_output),
	        			8.0 * bytesReceived / (double)(_now - t_first_data));
	        	bytes_received_last_output = bytesReceived;
	        	t_last_output = _now;
	        }

	        /* Check if throughput exceeds upper bound. If yes, terminate experiment. */
	        if(rcv_info.max_thrpt != -1 && (_now - rcv_info.first_data_received) >= rcv_info.max_thrpt_duration)
	        {
	        	const double thrpt = (8.0 * bytesReceived) / ((_now - rcv_info.first_data_received) / 1e6);  // [bps]
	        	if(thrpt >= rcv_info.max_thrpt) {
	        		printf("Average throughput over first %.3f s was %.3f Mbps. Terminating.\n", (_now - rcv_info.first_data_received) / 1e6, thrpt / 1e6);
	        		globalTerminationFlag = true;
	        		continue;
	        	}
	        }

	        /* Did we just receive last bytes of the request? */
	        if(bufReceive[br-1] == 1)
	        {
	        	rcv_info.last_data_received = _now;
	        	rcv_info.request_size = bytesReceived;
	        	fprintf(rcv_info.file_request_log, "  %" PRId64 "      %16.6f     %16.6f %14.6f %23.6f\n",
	        			rcv_info.request_sent, (rcv_info.first_data_received - rcv_info.request_sent) / 1e6,
	        			(rcv_info.last_data_received - rcv_info.request_sent) / 1e6, rcv_info.request_size / 1e6, rcv_info.scheduled_on_duration / 1e6);

	        	if(rcv_info.request_pattern.empty())
	        	{
	        		printf("End of request. Duration: %6.3f s. Average throughput: %6.3f Mbps. Terminating.\n", (_now - rcv_info.first_data_received) / 1e6, 8.0 * bytesReceived / (double)(_now - t_first_data));
	        		globalTerminationFlag = true;
	        	} else if(rcv_info.request_pattern_type == rcv_info.DETERMINISTIC) {
	        		if(_now + rcv_info.request_pattern_deterministic.off_duration - t_start_receiver >= Tmax) {
	        			printf("End of request. Duration: %6.3f s. Average throughput: %6.3f Mbps.\n", (_now - rcv_info.first_data_received) / 1e6, 8.0 * bytesReceived / (double)(_now - t_first_data));
	        			printf("End of trace. %.3f (>= %.3f - %.3f) sec expired. Terminating\n", (_now - t_start_receiver) / 1e6, Tmax / 1e6, rcv_info.request_pattern_deterministic.off_duration / 1e6);
	        			globalTerminationFlag = true;
	        		} else {
	        			printf("End of request. Duration: %6.3f s. Average throughput: %6.3f Mbps. Will wait for %6.3f s.\n", (_now - rcv_info.first_data_received) / 1e6, 8.0 * bytesReceived / (double)(_now - t_first_data), rcv_info.request_pattern_deterministic.off_duration / 1e6);
	        			usleep(rcv_info.request_pattern_deterministic.off_duration);
	        		}
	        	} else if(rcv_info.request_pattern_type == rcv_info.NORMAL) {
	        		if(rcv_info.first_data_received + rcv_info.request_pattern_normal.tau - t_start_receiver >= Tmax) {
	        			printf("End of request. Duration: %6.3f s. Average throughput: %6.3f Mbps.\n", (_now - rcv_info.first_data_received) / 1e6, 8.0 * bytesReceived / (double)(_now - t_first_data));
	        			printf("End of trace. %.3f sec expired. Terminating\n", (_now - t_start_receiver) / 1e6);
	        			globalTerminationFlag = true;
	        		} else {
	        			int64_t off_duration = std::max<int64_t>(0, rcv_info.request_pattern_normal.tau - (_now - rcv_info.first_data_received));
	        			if(off_duration) {
	        				printf("End of request. Duration: %6.3f s (< %6.3f). Average throughput: %6.3f Mbps. Will wait for %6.3f s.\n", (_now - rcv_info.first_data_received) / 1e6, rcv_info.request_pattern_normal.tau / 1e6, 8.0 * bytesReceived / (double)(_now - t_first_data), off_duration / 1e6);
	        				usleep(rcv_info.request_pattern_deterministic.off_duration);
	        			} else {
	        				printf("End of request. Duration: %6.3f s (> %6.3f). Average throughput: %6.3f Mbps. Will not wait.\n", (_now - rcv_info.first_data_received) / 1e6, rcv_info.request_pattern_normal.tau / 1e6, 8.0 * bytesReceived / (double)(_now - t_first_data));
	        			}
	        		}
	        	} else {
	        		throw std::runtime_error("Unknown request pattern: " + rcv_info.request_pattern);
	        	}
	        	break;
	        }
	    }
	}

	terminate_tcp_logger = true;
	if(global_info.tcp_info_log_interval > 0)
		assert(0 == pthread_join(loggerThread, NULL));
	if(rcv_log_info.pcap_tcp) pcap_breakloop(rcv_log_info.pcap_tcp);
	if(rcv_log_info.pcap_rdtap) pcap_breakloop(rcv_log_info.pcap_rdtap);
	if(!rcv_info.dev_name.empty()) assert(0 == pthread_join(snifferThread, NULL));
	if(!rcv_info.dev_name_mon.empty()) assert(0 == pthread_join(radiotapThread, NULL));

	/* close log files */
	assert(0 == fclose(tcp_logger_info.logFile));
	//assert(0 == fclose(rcv_log_info.f));
	assert(0 == fclose(rcv_info.file_request_log));

	/* shutdown connection and close sockets */
	shutdown(fd, SHUT_RDWR);  // intentionally don't check return value
	assert(0 == close(fd));
	if(_fd != -1) assert(0 == close(_fd));

#if 0
	{
		char buf[1024];
		sprintf(buf, "%s/rcv_throughput_process_psvport%05d.txt", args.traceDir.c_str(), args.psvPort);
		FILE* f = fopen(buf, "w");
		assert(f);
		for(list<vector<pair<int64_t,int64_t> > >::const_iterator it = thrptProcess.begin(); it != thrptProcess.end(); ++it)
		{
			const vector<pair<int64_t,int64_t> >& v = *it;
			for(int i = 0; i < v.size(); ++i)
			{
				const int64_t ts = v.at(i).first;
				const int64_t numBytes = v.at(i).second;
			    fprintf(f, "%" PRId64 " %" PRId64 "\n", ts, numBytes);
			}
		}
		assert(0 == fclose(f));
	}
#endif

	return NULL;
#endif
}

void* runTcpStateLogger(void* _args)
{
	while(!terminate_tcp_logger)
	{
		recordTcpState(tcp_logger_info.fd, "periodic", tcp_logger_info.logFile);
		assert(0 == usleep(global_info.tcp_info_log_interval));
	}

	return NULL;
}

/* merges pair p with pairs in [first, last).
 * Preconditions:
 *     all the pairs in [first, last] are non-overlapping and sorted.
 * If nothing has to be inserted, it returns toBeInserted.second < toBeInserted.first.
 */
template <class InputIterator, class T> void merge(const InputIterator begin, const InputIterator end, const std::pair<T, T>& p,
        list<InputIterator>& toBeErased, std::pair<T, T>& toBeInserted)
{
    if(!toBeErased.empty()) {printf("Bug in %s:%d.\n", __FILE__, __LINE__); abort();}

    /* Can we insert before first? */
    if(begin == end || p.second + 1 < begin->first) {
        toBeInserted = p;
        return;
    } else if(p.second + 1 == begin->first) {
        toBeInserted.first = p.first;
        toBeInserted.second = begin->second;
        toBeErased.push_back(begin);
        return;
    }

    /* Can we insert after last? */
    if(begin != end) {
        InputIterator endMinusOne = end;
        --endMinusOne;
        if(endMinusOne->second + 1 < p.first) {
            toBeInserted = p;
            return;
        } else if(endMinusOne->second + 1 == p.first) {
            toBeInserted.first = endMinusOne->first;
            toBeInserted.second = p.second;
            toBeErased.push_back(endMinusOne);
            return;
        }
    }

    /* find
     * 1. the pair where, or the one after which, p starts
     * 2. the pair where, or the one before which, p ends
     */
    InputIterator itStart = begin;
    bool startsWithinOrNeighboring = false;
    bool foundStart = false;
    InputIterator itEnd = end;
    bool endsWithinOrNeighboring = false;
    bool foundEnd = false;
    for(InputIterator it = begin; it != end; ++it)
    {
        const pair<T, T>& _p = *it;
        if(_p.second + 1 < p.first) {
            itStart = it;
            startsWithinOrNeighboring = false;
            foundStart = true;
        } else if(_p.first <= p.first) {
            itStart = it;
            startsWithinOrNeighboring = true;
            foundStart = true;
        }
        if(p.second + 1 < _p.first) {
            itEnd = it;
            endsWithinOrNeighboring = false;
            foundEnd = true;
            break;
        } else if(p.second <= _p.second) {
            itEnd = it;
            endsWithinOrNeighboring = true;
            foundEnd = true;
            break;
        }
    }

    if(itStart == itEnd) {
        if(!startsWithinOrNeighboring || !endsWithinOrNeighboring) {printf("Bug in %s:%d.\n", __FILE__, __LINE__); abort();}
        toBeInserted.first = 1;
        toBeInserted.second = 0;
        return;
    }

    if(startsWithinOrNeighboring) {
        toBeInserted.first = itStart->first;
        toBeErased.push_back(itStart);
    } else {
        toBeInserted.first = p.first;
    }

    InputIterator it = itStart;
    ++it;
    for(; it != itEnd; ++it)
        toBeErased.push_back(it);

    if(endsWithinOrNeighboring) {
        toBeInserted.second = itEnd->second;
        toBeErased.push_back(itEnd);
    } else {
        toBeInserted.second = p.second;
    }
}

/* Ethernet header: 14 bytes */
#define ETHER_ADDR_LEN 6
#pragma pack(push, 1)
struct ethernethdr
{
    uint8_t  dst[ETHER_ADDR_LEN];
    uint8_t  src[ETHER_ADDR_LEN];
    uint16_t type ; /* IP? ARP? RARP? etc */
};
#pragma pack(pop)

/* IP header: 20 to 60 bytes */
#pragma pack(push, 1)
struct iphdr
{
    uint8_t  vhl;       /* version << 4 | header length >> 2 */
    uint8_t  tos;       /* type of service */
    uint16_t len;       /* total length */
    uint16_t id;        /* identification */
    uint16_t off;       /* fragment offset field */
    uint8_t  ttl;       /* time to live */
    uint8_t  p;         /* protocol */
    uint16_t sum;       /* checksum */
    uint32_t src;       /* source address */
    uint32_t dst;       /* destination address */
};
#pragma pack(pop)
int ip_hl(const struct iphdr* ip) {return 4 * (ip->vhl & 0x0f);}

/* TCP header: 20 to 60 bytes */
#pragma pack(push, 1)
struct my_tcphdr {
    uint16_t th_sport;               /* source port */
    uint16_t th_dport;               /* destination port */
    uint32_t th_seq;                 /* sequence number */
    uint32_t th_ack;                 /* acknowledgement number */
    uint8_t  th_offx2;
    uint8_t  th_flags;
    uint16_t th_win;                 /* window */
    uint16_t th_sum;                 /* checksum */
    uint16_t th_urp;                 /* urgent pointer */
};
struct tcp_option {
    uint8_t kind;
    uint8_t size;
};
#pragma pack(pop)
struct my_tcphdr_tools {
    static int tcp_off(const struct my_tcphdr& tcpHdr) {return 4 * ((tcpHdr.th_offx2 >> 4) & 0x0f);}
    static bool tcp_syn(const struct my_tcphdr& tcpHdr) {return tcpHdr.th_flags & 0x02;}
    static bool tcp_fin(const struct my_tcphdr& tcpHdr) {return tcpHdr.th_flags & 0x01;}
    static bool tcp_ack(const struct my_tcphdr& tcpHdr) {return tcpHdr.th_flags & 0x10;}
    static uint32_t tcp_seq(const struct my_tcphdr& tcpHdr) {return ntohl(tcpHdr.th_seq);}
    //static string tcp2str(const struct my_tcphdr& tcpHdr);
};

struct LessThenNonOverlapping {
    //bool operator() (const pair<int64_t, int64_t>& a, const pair<int64_t, int64_t>& b) const;
    bool operator() (const pair<int64_t, int64_t>& a, const pair<int64_t, int64_t>& b) const {
        if(a.first <= a.second && b.first <= b.second && a.second < b.first)
            return true;
        else if(a.first <= a.second && b.first <= b.second && b.second < a.first)
            return false;
        else {
            static char buf[2048];
            sprintf(buf, "Overlapping pairs detected: [%lld, %lld] and [%lld, %lld].", (long long)a.first, (long long)a.second, (long long)b.first, (long long)b.second);
            throw std::logic_error(buf);
        }
    }
};

void sniffer_callback(u_char *_args, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
#ifndef __SENDER
    // save the packet into circular buffer
    rcv_log_info.pcap_tcp_data_mutex.lock();
    assert(rcv_log_info.pcap_tcp_data.size() < rcv_log_info.pcap_tcp_data.capacity());
    rcv_log_info.pcap_tcp_data.push_back(rcv_log_info_t::pcap_element(header, pkt_data));
    rcv_log_info.pcap_tcp_data_mutex.unlock();

#if 0

    static bool first_packet = true;
    const int64_t _now = now();

    //
    // parse packet
    //

    const struct ethernethdr* ethernetHdr = (struct ethernethdr*)(pkt_data);

    assert(ntohs(ethernetHdr->type) == 0x0800);  // IP packet

    const struct iphdr* ipHdr = (struct iphdr*)((int8_t*)ethernetHdr + sizeof(*ethernetHdr));

    if(ipHdr->p != 0x06)  // TCP packet
        return;

    const struct my_tcphdr* tcpHdr = (struct my_tcphdr*)((int8_t*)ipHdr + ip_hl(ipHdr));
    const uint32_t tcpPldSize = ntohs(ipHdr->len) - ip_hl(ipHdr) - my_tcphdr_tools::tcp_off(*tcpHdr);

    assert(14 + ip_hl(ipHdr) + my_tcphdr_tools::tcp_off(*tcpHdr) <= rcv_log_info.pcap_snaplen);

    const uint32_t seqNr1 = my_tcphdr_tools::tcp_seq(*tcpHdr);

    /* check for timestamp */
    uint32_t tcp_ts = 0;
    if(my_tcphdr_tools::tcp_off(*tcpHdr) > 5)
    {
        uint8_t* opt = (uint8_t*)tcpHdr + sizeof(struct my_tcphdr);
        while( *opt != 0 )
        {
            tcp_option* _opt = (tcp_option*)opt;
            if( _opt->kind == 1 /* NOP */ ) {
                ++opt;  // NOP is one byte;
                continue;
            }
            if( _opt->kind == 8 /* TSopt */ ) {
                assert(_opt->size == 10);
                tcp_ts = ntohl(*(uint32_t*)(opt+2));
                break;
            }
            opt += _opt->size;
        }
    }
    assert(tcp_ts != 0);

    if(first_packet) {
        //assert(tcp_syn(*tcpHdr));
        first_packet = false;
        //assert(rcv_log_info.ts_first_packet == 0 && rcv_log_info.tcp_ts_first_packet == 0);
        //rcv_log_info.ts_first_packet = _now;
        //rcv_log_info.tcp_ts_first_packet = tcp_ts;
    }/* else if(!tcp_fin(*tcpHdr)) {
        assert(tcpPldSize > 0);
    }*/
#endif

#if 0
    //
    // sequence number monitoring
    //

    /* We only process packets with payload */
    if(tcpPldSize > 0)
    {

        /* sequence number of the first segment of the TCP flow (sequence number of the SYN packet plus 1). */
        static uint32_t seqStart = seqNr1 + 1;

        /* since a TCP sequence is only 32-bit and
         * a TCP flow can carry much more (in fact, unlimited) bytes, the sequence number
         * may overflow and start again from 0. seqRound stores the number of times this happened for
         * the last byte of the first contiguous range of data starting with the initial sequence number seqStart. */
        static int seqRound = 0;

        /* received sequence numbers */
        static set<pair<int64_t, int64_t>, LessThenNonOverlapping> seqOffRcvd;

        /* calculate the ABSOLUTE sequence number of the last data byte in the received segment.
         * if segment number space overflows, it can be smaller than the sequence number of the first data byte. */
        const uint32_t seqNr2 = ((int64_t)seqNr1 + (int64_t)tcpPldSize - 1) % ((int64_t)std::numeric_limits<uint32_t>::max() + 1);

        /* if the first byte of the flow was not received yet, seqRound is w.r.t. seqStart.
         * note that the first byte here means not any byte of the flow but the byte with sequence number seqStart. */
        uint32_t seqRef = seqStart;
        if(seqOffRcvd.empty() || seqOffRcvd.begin()->first > 0) {
            seqRef = seqStart;
        } else {
            seqRef = (seqStart + seqOffRcvd.begin()->second) % ((int64_t)std::numeric_limits<uint32_t>::max() + 1);
        }
        uint32_t seqMax = ((uint64_t)seqRef + (uint64_t)1073725440 - 1) %  ((uint64_t)std::numeric_limits<uint32_t>::max() + 1);
        //fprintf(fd, "seqRef: %" PRIu32 ", seqMax: %" PRIu32 ". Got: [%" PRIu32 ", %" PRIu32 "].\n", seqRef, seqMax, seqNr1, seqNr2);

        /* since sequence numbers are not unique within a TCP flow (they might overflow and start again from 0),
         * we re-calculate the sequence numbers in offsets relative to the first byte of the flow */
        int64_t off1 = (int64_t)seqNr1 - (int64_t)seqStart;
        int64_t off2 = (int64_t)seqNr2 - (int64_t)seqStart;
        if(        (seqNr1 >= seqRef)
                || (seqNr1 < seqRef && (seqMax > seqRef || seqMax < seqNr1)))
            off1 += (int64_t)seqRound * ((int64_t)std::numeric_limits<uint32_t>::max() + (int64_t)1);
        else
            off1 += (int64_t)(seqRound + 1) * ((int64_t)std::numeric_limits<uint32_t>::max() + (int64_t)1);
        if(        (seqNr2 >= seqRef)
                || (seqNr2 < seqRef && (seqMax > seqRef || seqMax < seqNr2)))
            off2 += (int64_t)seqRound * ((int64_t)std::numeric_limits<uint32_t>::max() + (int64_t)1);
        else
            off2 += (int64_t)(seqRound + 1) * ((int64_t)std::numeric_limits<uint32_t>::max() + (int64_t)1);
        //printf("Translated into offset range [%" PRId64 ", %" PRId64 "]\n", off1, off2);
        //fprintf(fd, "%10u %10u %10u %12lld %12lld %10u %d\n", (unsigned)seqRef, (unsigned)seqNr1, (unsigned)seqNr2, (long long)off1, (long long)off2, (unsigned)seqMax, seqRound);

        /* log the received range in the variable seqOffRcvd */

        //printf("Segments before insertion:\n");
        //for(set<pair<int64_t, int64_t> >::const_iterator it = seqOffRcvd.begin(); it != seqOffRcvd.end(); ++it)
        //    printf("[%lld, %lld]\n", (long long)it->first, (long long)it->second);

        const pair<int64_t, int64_t> firstRangeBefore = (seqOffRcvd.empty()) ? (pair<int64_t, int64_t>(-1, -1)) : (*(seqOffRcvd.begin()));

        typedef set<pair<int64_t, int64_t> >::iterator IteratorType;
        list<IteratorType> toBeErased;
        pair<int64_t, int64_t> toBeInserted;
        merge(seqOffRcvd.begin(), seqOffRcvd.end(), pair<int64_t, int64_t>(off1, off2), toBeErased, toBeInserted);
        for(list<IteratorType>::const_iterator it = toBeErased.begin(); it != toBeErased.end(); ++it) {
            //printf("Erasing [%" PRId64 ", %" PRId64 "].\n", (*it)->first, (*it)->second);
            seqOffRcvd.erase(*it);
        }

        if(toBeInserted.first <= toBeInserted.second) {
            //printf("Inserting [%" PRId64 ", %" PRId64 "].\n", toBeInserted.first, toBeInserted.second);
            if(!seqOffRcvd.insert(toBeInserted).second) {printf("Bug in %s:%d.\n", __FILE__, __LINE__); abort();}
        }

        /* Did we update the first range? */
        //if(*(seqOffRcvd.begin()) != firstRangeBefore)
        //    firstRangeUpdated = true;

        /* update sequence round if necessary */
        if(seqOffRcvd.begin()->first == 0
                && (seqStart + seqOffRcvd.begin()->second) % ((int64_t)std::numeric_limits<uint32_t>::max() + 1) < seqRef) {
            ++seqRound;
            //fprintf(fd, "seqRound incremented\n");
        }

        //printf("Segments after insertion:\n");
        //for(set<pair<int64_t, int64_t> >::const_iterator it = seqOffRcvd.begin(); it != seqOffRcvd.end(); ++it)
        //    fprintf(fd, "[%lld, %lld]\n", (long long)it->first, (long long)it->second);

        /* search for missing packets */
        int64_t seq_missing = 0;
        if(seqOffRcvd.size() > 1) {
            set<pair<int64_t, int64_t> >::const_iterator it = seqOffRcvd.begin();
            ++it;
            for(; it != seqOffRcvd.end(); ++it) {
                set<pair<int64_t, int64_t> >::const_iterator it_prev = it;
                --it_prev;
                seq_missing += it->first - it_prev->second - 1;
            }
        }
    }
#endif

    //
    // logging BEGIN
    //

#if 0
    rcv_log_info.mutex.lock();

    // initialization
    if(rcv_log_info.index == -1)                 rcv_log_info.index = (_now - rcv_log_info.ts_first_packet) / rcv_log_info.dt;  // integer division
    if(rcv_log_info.delay_vec.capacity() == 0)   rcv_log_info.delay_vec.reserve(1048576);
    if(rcv_log_info.missing_vec.capacity() == 0) rcv_log_info.missing_vec.reserve(1048576);

    if(rcv_log_info.dt > 0 && _now >= rcv_log_info.ts_first_packet + (1 + rcv_log_info.index) * rcv_log_info.dt) {
        rcv_log_output();
        rcv_log_info.index = (_now - rcv_log_info.ts_first_packet) / rcv_log_info.dt;  // integer division
    }

    assert(rcv_log_info.delay_vec.size() < rcv_log_info.delay_vec.capacity() && rcv_log_info.missing_vec.size() < rcv_log_info.missing_vec.capacity());
    rcv_log_info.delay_vec.push_back((_now - rcv_log_info.ts_first_packet) - 4000 * (tcp_ts - rcv_log_info.tcp_ts_first_packet));
    rcv_log_info.missing_vec.push_back(seq_missing);
    if(rcv_log_info.off1 == 0) rcv_log_info.off1 = off1;
    rcv_log_info.off2 = off2;

    if(rcv_log_info.dt == 0) {
        rcv_log_info.index = _now;
        rcv_log_output();
    }

    rcv_log_info.mutex.unlock();
#endif

    //
    // logging END
    //
#endif
}

void radiotap_callback(u_char *_args, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
#ifndef __SENDER
    // save the packet into circular buffer
    rcv_log_info.pcap_rdtap_data_mutex.lock();
    assert(rcv_log_info.pcap_rdtap_data.size() < rcv_log_info.pcap_rdtap_data.capacity());
    rcv_log_info.pcap_rdtap_data.push_back(rcv_log_info_t::pcap_element(header, pkt_data));
    rcv_log_info.pcap_rdtap_data_mutex.unlock();
#endif
}

bool stop_pcap_tcp_dumper = false;
void* run_pcap_tcp_dumper(void* args)
{
    /* prepare pcap output file */
    char fn_pcap[4096];
    sprintf(fn_pcap, "%s/rcv_tcp_pcap_%016" PRId64 ".pcap", traceDir.c_str(), t_start_receiver);
    rcv_log_info.pcap_dumper_tcp = pcap_dump_open(rcv_log_info.pcap_tcp, fn_pcap);
    assert(rcv_log_info.pcap_dumper_tcp != NULL);

    while(true)
    {
        rcv_log_info.pcap_tcp_data_mutex.lock();
        const bool has_data = !rcv_log_info.pcap_tcp_data.empty();
        rcv_log_info.pcap_tcp_data_mutex.unlock();

        if(has_data)
        {
            //save the packet on the dump file
            pcap_dump((u_char*)rcv_log_info.pcap_dumper_tcp, &rcv_log_info.pcap_tcp_data.front().pkthdr, rcv_log_info.pcap_tcp_data.front().pktdata);

            rcv_log_info.pcap_tcp_data_mutex.lock();
            rcv_log_info.pcap_tcp_data.pop_front();
            rcv_log_info.pcap_tcp_data_mutex.unlock();
        }
        else if(stop_pcap_tcp_dumper)
        {
            break;
        }
        else
        {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 10000;
            nanosleep(&ts, NULL);
        }
    }

    /* close pcap output file */
    pcap_dump_close(rcv_log_info.pcap_dumper_tcp);

    return NULL;
}

void* runSniffer(void* _args)
{
#ifndef __SENDER

    char errbuf[PCAP_ERRBUF_SIZE];

    printf("Sniffing on device: %s\n", rcv_info.dev_name.c_str());

    rcv_log_info.pcap_tcp = pcap_open_live(rcv_info.dev_name.c_str(), rcv_log_info.pcap_snaplen, 0, 100, errbuf);
    if(!rcv_log_info.pcap_tcp) {
        printf("Error: %s.\n", errbuf);
        return NULL;
    } else if(errbuf[0]) {
        printf("Warning: %s.\n", errbuf);
    }

    /* create and apply a filter expression */
    {
        std::ostringstream oss;
        if(global_info.ifActive) {
            oss << "tcp and src host " << global_info.psvIp << " and src port " << global_info.psvPort;
        } else {
            oss << "tcp and dst host " << global_info.psvIp << " and dst port " << global_info.psvPort;
        }

        struct bpf_program filter;
        int ret = pcap_compile(rcv_log_info.pcap_tcp, &filter, oss.str().c_str(), 0, PCAP_NETMASK_UNKNOWN);
        if(ret != 0) {
            printf("Failed to compile the filter expression: %s.\n", oss.str().c_str());
            return NULL;
        }

        ret = pcap_setfilter(rcv_log_info.pcap_tcp, &filter);
        if(ret != 0) {
            printf("Failed to apply the filter expression: %s.\n", oss.str().c_str());
            return NULL;
        }

        pcap_freecode(&filter);
    }

    /* start dumper */
    pthread_t pcap_tcp_dumper_thread;
    stop_pcap_tcp_dumper = false;
    assert(0 == pthread_create(&pcap_tcp_dumper_thread, NULL, &run_pcap_tcp_dumper, NULL));

    int ret = pcap_loop(rcv_log_info.pcap_tcp, -1, sniffer_callback, NULL);

    /* stop dumper */
    stop_pcap_tcp_dumper = true;
    assert(0 == pthread_join(pcap_tcp_dumper_thread, NULL));

    /* close pcap */
    pcap_close(rcv_log_info.pcap_tcp);
#endif
    return NULL;
}

bool stop_pcap_rdtap_dumper = false;
void* run_pcap_rdtap_dumper(void* args)
{
    /* prepare pcap output file */
    char fn_pcap[4096];
    sprintf(fn_pcap, "%s/rcv_rdtap_pcap_%016" PRId64 ".pcap", traceDir.c_str(), t_start_receiver);
    rcv_log_info.pcap_dumper_rdtap = pcap_dump_open(rcv_log_info.pcap_rdtap, fn_pcap);
    assert(rcv_log_info.pcap_dumper_rdtap != NULL);

    while(true)
    {
        rcv_log_info.pcap_rdtap_data_mutex.lock();
        const bool has_data = !rcv_log_info.pcap_rdtap_data.empty();
        rcv_log_info.pcap_rdtap_data_mutex.unlock();

        if(has_data)
        {
            //save the packet on the dump file
            pcap_dump((u_char*)rcv_log_info.pcap_dumper_rdtap, &rcv_log_info.pcap_rdtap_data.front().pkthdr, rcv_log_info.pcap_rdtap_data.front().pktdata);

            rcv_log_info.pcap_rdtap_data_mutex.lock();
            rcv_log_info.pcap_rdtap_data.pop_front();
            rcv_log_info.pcap_rdtap_data_mutex.unlock();
        }
        else if(stop_pcap_rdtap_dumper)
        {
            break;
        }
        else
        {
            struct timespec ts;
            ts.tv_sec = 0;
            ts.tv_nsec = 10000;
            nanosleep(&ts, NULL);
        }
    }

    /* close pcap output file */
    pcap_dump_close(rcv_log_info.pcap_dumper_rdtap);

    return NULL;
}

void* runRadiotap(void* _args)
{
#ifndef __SENDER

    char errbuf[PCAP_ERRBUF_SIZE];

    printf("Sniffing on device: %s\n", rcv_info.dev_name_mon.c_str());

    rcv_log_info.pcap_rdtap = pcap_open_live(rcv_info.dev_name_mon.c_str(), rcv_log_info.radiotap_snaplen, 1, 100, errbuf);
    if(!rcv_log_info.pcap_rdtap) {
        printf("Error: %s.\n", errbuf);
        return NULL;
    } else if(errbuf[0]) {
        printf("Warning: %s.\n", errbuf);
    }

    /* start dumper */
    pthread_t pcap_rdtap_dumper_thread;
    stop_pcap_rdtap_dumper = false;
    assert(0 == pthread_create(&pcap_rdtap_dumper_thread, NULL, &run_pcap_rdtap_dumper, NULL));

    int ret = pcap_loop(rcv_log_info.pcap_rdtap, -1, radiotap_callback, NULL);

    /* stop dumper */
    stop_pcap_rdtap_dumper = true;
    assert(0 == pthread_join(pcap_rdtap_dumper_thread, NULL));

    /* close pcap */
    pcap_close(rcv_log_info.pcap_rdtap);
#endif
    return NULL;
}

void signalHandler(int sig)
{
    assert((sig == SIGINT || sig == SIGTERM || sig == SIGALRM) && !globalTerminationFlag);
    printf("Got signal %d. Terminating.\n", sig);
    globalTerminationFlag = true;
}

int64_t now()
{
	struct timeval tv;
	assert(0 == gettimeofday(&tv, NULL));
	return (int64_t)tv.tv_sec * (int64_t)1000000 + (int64_t)tv.tv_usec;
}

void recordTcpState(int fd, const char* reason, FILE* f)
{
    static std::mutex logMutex;
    static struct tcp_info tcpInfo;

    logMutex.lock();

    memset(&tcpInfo, 0, sizeof(tcpInfo));
    socklen_t len = sizeof(tcpInfo);
    assert(0 == getsockopt(fd, SOL_TCP, TCP_INFO, &tcpInfo, &len) && len == sizeof(tcpInfo));
    //if(0 != memcmp(&tcpInfo, &lastTcpInfo, sizeof(struct tcp_info))) {
        recordTcpState(f, tcpInfo, now(), reason);
        tcp_logger_info.lastTcpInfo = tcpInfo;
    //}

    logMutex.unlock();
}

void recordTcpState(FILE* f, const struct tcp_info& tcpInfo, const int64_t t, const char* reason)
{
	fprintf(f,
			"%17" PRId64 " %17s %19s %19s %13u %8u %9u %9u %12u %12u % 11.6f %9u %9u %9u %9u %8u %8u %9u %9u %16u %15u %16u %15u %8u %14u % 11.6f % 10.6f %14u %10u %8u %12u %9u %11u %15u\n",
			t,
			reason,
			tcpState2String(tcpInfo.tcpi_state).c_str(),
			tcpCAState2String(tcpInfo.tcpi_ca_state).c_str(),
			tcpInfo.tcpi_retransmits,
			tcpInfo.tcpi_probes,
			tcpInfo.tcpi_backoff,
			tcpInfo.tcpi_options,
			tcpInfo.tcpi_snd_wscale,
			tcpInfo.tcpi_rcv_wscale,
			tcpInfo.tcpi_rto / 1e6,
			tcpInfo.tcpi_ato,
			tcpInfo.tcpi_snd_mss,
			tcpInfo.tcpi_rcv_mss,
			tcpInfo.tcpi_unacked,
			tcpInfo.tcpi_sacked,
			tcpInfo.tcpi_lost,
			tcpInfo.tcpi_retrans,
			tcpInfo.tcpi_fackets,
			tcpInfo.tcpi_last_data_sent,
			tcpInfo.tcpi_last_ack_sent,
			tcpInfo.tcpi_last_data_recv,
			tcpInfo.tcpi_last_ack_recv,
			tcpInfo.tcpi_pmtu,
			tcpInfo.tcpi_rcv_ssthresh,
			tcpInfo.tcpi_rtt / 1e6,
			tcpInfo.tcpi_rttvar / 1e6,
			tcpInfo.tcpi_snd_ssthresh,
			tcpInfo.tcpi_snd_cwnd,
			tcpInfo.tcpi_advmss,
			tcpInfo.tcpi_reordering,
			tcpInfo.tcpi_rcv_rtt,
			tcpInfo.tcpi_rcv_space,
			tcpInfo.tcpi_total_retrans);
}

string tcpState2String(int tcpState)
{
    switch(tcpState)
    {
    case TCP_ESTABLISHED: return "TCP_ESTABLISHED";
    case TCP_SYN_SENT:    return "TCP_SYN_SENT";
    case TCP_SYN_RECV:    return "TCP_SYN_RECV";
    case TCP_FIN_WAIT1:   return "TCP_FIN_WAIT1";
    case TCP_FIN_WAIT2:   return "TCP_FIN_WAIT2";
    case TCP_TIME_WAIT:   return "TCP_TIME_WAIT";
    case TCP_CLOSE:       return "TCP_CLOSE";
    case TCP_CLOSE_WAIT:  return "TCP_CLOSE_WAIT";
    case TCP_LAST_ACK:    return "TCP_LAST_ACK";
    case TCP_LISTEN:      return "TCP_LISTEN";
    case TCP_CLOSING:     return "TCP_CLOSING";
    default:              throw "Unrecognized TCP state.";
    }
}

string tcpCAState2String(int tcpCAState)
{
    switch(tcpCAState)
    {
    case TCP_CA_Open:     return "TCP_CA_Open";
    case TCP_CA_Disorder: return "TCP_CA_Disorder";
    case TCP_CA_CWR:      return "TCP_CA_CWR";
    case TCP_CA_Recovery: return "TCP_CA_Recovery";
    case TCP_CA_Loss:     return "TCP_CA_Loss";
    default:              throw "Unrecognized TCP CA state.";
    }
}

#if 0
void rcv_log_output()
{
    assert(rcv_log_info.ts_first_packet > 0);

    if(rcv_log_info.dt == 0)
    {
        assert(rcv_log_info.delay_vec.size() <= 1 && rcv_log_info.missing_vec.size() <= 1);

        //'time [us] | bytes [byte] | delay [s] | missing bytes [byte] |'
        fprintf(rcv_log_info.f, "%" PRId64 " %" PRId64 " %.6f %10d\n",
                rcv_log_info.index, rcv_log_info.num_bytes, rcv_log_info.delay_vec.empty() ? std::numeric_limits<double>::quiet_NaN() : rcv_log_info.delay_vec.at(0),
                rcv_log_info.missing_vec.empty() ? std::numeric_limits<int>::quiet_NaN() : rcv_log_info.missing_vec.at(0));
    }
    else
    {
        std::sort(rcv_log_info.delay_vec.begin(), rcv_log_info.delay_vec.end());

        //const int64_t index = rcv_log_info.tic / rcv_log_info.dt;
        const double thrpt_mbps = 8.0 * rcv_log_info.num_bytes / double(rcv_log_info.dt);
        double delay_min_s, delay_max_s, delay_mean_s, delay_median_s, delay_var;
        delay_min_s = delay_max_s = delay_mean_s = delay_median_s = delay_var = std::numeric_limits<double>::quiet_NaN();
        if(!rcv_log_info.delay_vec.empty())
        {
            delay_min_s = rcv_log_info.delay_vec.front() / 1e6;
            delay_max_s = rcv_log_info.delay_vec.back() / 1e6;
            delay_mean_s = std::accumulate(rcv_log_info.delay_vec.begin(), rcv_log_info.delay_vec.end(), 0.0) / rcv_log_info.delay_vec.size() / 1e6;
            delay_median_s = (rcv_log_info.delay_vec.size() % 2 == 0) ?
                    0.5 * (rcv_log_info.delay_vec.at(rcv_log_info.delay_vec.size() / 2 - 1) + rcv_log_info.delay_vec.at(rcv_log_info.delay_vec.size() / 2)) / 1e6 :
                    rcv_log_info.delay_vec.at(rcv_log_info.delay_vec.size() / 2) / 1e6;
            if(rcv_log_info.delay_vec.size() == 1) {
                delay_var = 0;
            } else {
                double _sqr_sum = std::inner_product(rcv_log_info.delay_vec.begin(), rcv_log_info.delay_vec.end(), rcv_log_info.delay_vec.begin(), 0.0);
                delay_var = rcv_log_info.delay_vec.size() / (rcv_log_info.delay_vec.size() - 1.0) * (_sqr_sum / rcv_log_info.delay_vec.size() / 1e12 - delay_mean_s * delay_mean_s);
            }
        }

        //'index | thrpt [Mbps] | delay [s]: min |        max |       mean |     median |        var | missing bytes: max |'
        fprintf(rcv_log_info.f, "%7" PRId64 " %14.6f %16.6f %13.6f %14.6f %16.6f %12.6f %19d\n",
                rcv_log_info.index, thrpt_mbps, delay_min_s, delay_max_s, delay_mean_s, delay_median_s, delay_var,
                *std::max_element(rcv_log_info.missing_vec.begin(), rcv_log_info.missing_vec.end()));
    }

#if 0
    if(tcpPldSize <= 0) // this is only for SYN and FIN packets
        fprintf(file_sniffer, "%" PRId64 " %" PRIu32 " %" PRId64 " %" PRId64 " %" PRId64 "\n",
                _now, tcp_ts, (int64_t)-1, (int64_t)-1, seq_missing);
    else
        fprintf(file_sniffer, "%" PRId64 " %" PRIu32 " %" PRId64 " %" PRId64 " %" PRId64 "\n",
                _now, tcp_ts, off1, off2, seq_missing);
#endif

    rcv_log_info.reset();
}
#endif

string getTimeString(int64_t t, bool showDate)
{
    static char buf[1024];
    time_t _t;
    int64_t usecs = 0;
    if(t == 0) {
        int64_t absTime = now();
        _t = absTime / 1000000;
        usecs = absTime % 1000000;
    } else {
        _t = t / 1000000;
        usecs = t % 1000000;
    }
    struct tm T;
    localtime_r(&_t, &T);
    if(showDate)
        assert(strftime(buf, 1024, "%d.%m.%Y %H:%M:%S", &T) + 2 < 1024); // + 2 in order to ensure that nothing was truncated
    else
        assert(strftime(buf, 1024, "%H:%M:%S", &T) + 2 < 1024); // + 2 in order to ensure that nothing was truncated
    sprintf(buf + strlen(buf), ".%06" PRId64, usecs);
    return string(buf);
}

string get_dev_for_ip(string ip)
{
    struct ifaddrs* if_list = NULL;
    assert(0 == getifaddrs(&if_list) && if_list != NULL);

    struct ifaddrs* it = if_list;
    while(it != NULL)
    {
        if(inet_addr(get_ip_for_dev(it->ifa_name).c_str()) == inet_addr(ip.c_str())) {
            string ret(it->ifa_name);
            freeifaddrs(if_list);
            return ret;
        }
        it = it->ifa_next;
    }

    throw std::runtime_error("Could not find network device for IP: " + ip);
}

bool wait_for_dev(string dev, int64_t max_wait)
{
	printf("Waiting for device %s to become available. Max. waiting time: %.2f s.\n", dev.c_str(), max_wait / 1e6);

	bool first_check = true;
	const int64_t t0 = now();
	do {
		if(!first_check)
			sleep(1);
		else
			first_check = false;

		const int fd = socket(AF_INET, SOCK_DGRAM, 0);

		struct ifreq ifr;
		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ-1);

		const int ret = ioctl(fd, SIOCGIFADDR, &ifr);

		close(fd);

		if(ret == 0)
			return true;

	} while(now() - t0 < max_wait);

	return false;
}

string get_ip_for_dev(string dev)
{
    const int fd = socket(AF_INET, SOCK_DGRAM, 0);

    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, dev.c_str(), IFNAMSIZ-1);

    if(-1 == ioctl(fd, SIOCGIFADDR, &ifr)) {
        perror("ioctl()");
        abort();
    }

    close(fd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}

#if 0
string get_ip_for_dev(string dev)
{
    struct ifaddrs* if_list = NULL;
    assert(0 == getifaddrs(&if_list) && if_list != NULL);

    struct ifaddrs* it = if_list;
    while(it != NULL)
    {
        if(it->ifa_addr->sa_family != AF_INET) {
            it = it->ifa_next;
            continue;
        }
        if(0 == strcmp(dev.c_str(), it->ifa_name))
        {
            struct sockaddr_in* sockaddr_in = (struct sockaddr_in*)it->ifa_addr;
            string ip(inet_ntoa(sockaddr_in->sin_addr));
            freeifaddrs(if_list);
            return ip;
        }
        it = it->ifa_next;
    }

    throw std::runtime_error("Could not find IP address for device: " + dev + ". Please make sure the device is up and running.");
}
#endif

void parse_request_pattern(const char* request_pattern)
{
    rcv_info.request_pattern = request_pattern;

    if(0 == strncmp(request_pattern, "deterministic:", 14))  // deterministic:<ON duration, integer, [ms]>:<OFF duration, integer, [ms]>
    {
        rcv_info.request_pattern_type = rcv_info.DETERMINISTIC;
        char* endptr = NULL;
        rcv_info.request_pattern_deterministic.on_duration = 1000 * strtol(request_pattern + 14, &endptr, 10);
        assert(endptr && endptr[0] == ':');
        rcv_info.request_pattern_deterministic.off_duration = 1000 * strtol(endptr + 1, &endptr, 10);
        assert(endptr[0] == '\0');
    }
    else if(0 == strncmp(request_pattern, "normal:", 7))  // normal:<mean, integer, [ms]>:<std, integer, [ms]>:<min, integer, [ms]>:<max, integer, [ms]>:<segment duration, integer, [ms]>
    {
        rcv_info.request_pattern_type = rcv_info.NORMAL;
        char* endptr = NULL;
        rcv_info.request_pattern_normal.mean = 1000 * strtol(request_pattern + 7, &endptr, 10);
        assert(endptr && endptr[0] == ':');
        rcv_info.request_pattern_normal.std = 1000 * strtol(endptr + 1, &endptr, 10);
        assert(endptr && endptr[0] == ':');
        rcv_info.request_pattern_normal.min = 1000 * strtol(endptr + 1, &endptr, 10);
        assert(endptr && endptr[0] == ':');
        rcv_info.request_pattern_normal.max = 1000 * strtol(endptr + 1, &endptr, 10);
        assert(endptr && endptr[0] == ':');
        rcv_info.request_pattern_normal.tau = 1000 * strtol(endptr + 1, &endptr, 10);
        assert(endptr[0] == '\0');

        if(rcv_info.request_pattern_normal.mean <= 0
                || rcv_info.request_pattern_normal.std <= 0
                || rcv_info.request_pattern_normal.min > rcv_info.request_pattern_normal.mean
                || rcv_info.request_pattern_normal.max < rcv_info.request_pattern_normal.mean
                || rcv_info.request_pattern_normal.tau < rcv_info.request_pattern_normal.mean) {
            throw std::runtime_error("Invalid request pattern: " + string(request_pattern));
        }
    }
    else
    {
        throw std::runtime_error("Invalid request pattern: " + string(request_pattern));
    }
}

#if 0
void* run_flusher(void* _args)
{
    while(!globalTerminationFlag) {
        std::fflush(NULL);
        sleep(1);
    }
    return NULL;
}
#endif
