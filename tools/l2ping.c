// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2000-2001  Qualcomm Incorporated
 *  Copyright (C) 2002-2003  Maxim Krasnyansky <maxk@qualcomm.com>
 *  Copyright (C) 2002-2010  Marcel Holtmann <marcel@holtmann.org>
 *
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <poll.h>
#include <sys/socket.h>
#include <time.h>

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/hci_lib.h"
#include "lib/l2cap.h"

/* Defaults */
static bdaddr_t bdaddr;
static int size    = 44;
static int ident   = 200;
static int delay   = 1;
static int count   = -1;
static int timeout = 10;
static int reverse = 0;
static int verify = 0;

/* Stats */
static int sent_pkt = 0;
static int recv_pkt = 0;

static float tv2fl(struct timeval tv)
{
	return (float)(tv.tv_sec*1000.0) + (float)(tv.tv_usec/1000.0);
}

static void stat(int sig)
{
	int loss = sent_pkt ? (float)((sent_pkt-recv_pkt)/(sent_pkt/100.0)) : 0;
	printf("%d sent, %d received, %d%% loss\n", sent_pkt, recv_pkt, loss);
	exit(0);
}

static void init_rand(uint seed) {
	if (seed == 0) {
		seed = time(NULL);
	}

	printf("seed: 0x%x\n", seed);
	srand(seed);
}

int rand_range(int min, int max){
   return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

void hexdump(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        
        if (((unsigned char*)data)[i] >= ' ' && 
           ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            printf(" ");
            if ((i+1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

static void ping(char *svr)
{
	struct sigaction sa;
	struct sockaddr_l2 addr;
	socklen_t optlen;
	unsigned char *send_buf;
	unsigned char *recv_buf;
	char str[18];
	int i, sk, lost;
	uint8_t id;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = stat;
	sigaction(SIGINT, &sa, NULL);


	send_buf = malloc(L2CAP_CMD_HDR_SIZE + 256); // make sure there's enough size for max rand value
	recv_buf = malloc(L2CAP_CMD_HDR_SIZE + size);
	if (!send_buf || !recv_buf) {
		perror("Can't allocate buffer");
		exit(1);
	}

	/* Create socket */
	sk = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_L2CAP);
	if (sk < 0) {
		perror("Can't create socket");
		goto error;
	}

	/* Bind to local address */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	bacpy(&addr.l2_bdaddr, &bdaddr);

	if (bind(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't bind socket");
		goto error;
	}

	/* Connect to remote device */
	memset(&addr, 0, sizeof(addr));
	addr.l2_family = AF_BLUETOOTH;
	str2ba(svr, &addr.l2_bdaddr);

	if (connect(sk, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("Can't connect");
		goto error;
	}

	/* Get local address */
	memset(&addr, 0, sizeof(addr));
	optlen = sizeof(addr);

	if (getsockname(sk, (struct sockaddr *) &addr, &optlen) < 0) {
		perror("Can't get local address");
		goto error;
	}

	ba2str(&addr.l2_bdaddr, str);
	printf("Ping: %s from %s (data size %d) ...\n", svr, str, size);

	/* Initialize send buffer */
	// for (i = 0; i < size; i++)
	// 	send_buf[L2CAP_CMD_HDR_SIZE + i] = (i % 40) + 'A';

	id = ident;

	//while (count == -1 || count-- > 0) {
		while (1) {
		//for (int i=0; i<32; i++) {
			struct timeval tv_send, tv_recv, tv_diff;
			l2cap_cmd_hdr *send_cmd = (l2cap_cmd_hdr *) send_buf;
			l2cap_cmd_hdr *recv_cmd = (l2cap_cmd_hdr *) recv_buf;
		
			int fsize = rand() % 256;

			for (i = 0; i < fsize; i++)
				send_buf[L2CAP_CMD_HDR_SIZE + i] = (uint8_t) rand();

			/* Build command header */
			send_cmd->ident = id;
			send_cmd->len   = htobs(size);

			// if (reverse)
			// 	send_cmd->code = L2CAP_ECHO_RSP;
			// else
			// 	send_cmd->code = L2CAP_ECHO_REQ;
			if (rand() % 0b11111 == 0b11111) {
				send_cmd->code = (uint8_t) rand() % 256;
			} else {
				send_cmd->code = (uint8_t) rand_range(0x01, 0x11);
			}

			if (rand() % 2 == 0) {
				send_cmd->ident = (uint8_t) rand() % 256;
			}

			send_cmd->len = htobs(fsize);

			gettimeofday(&tv_send, NULL);

// // .fuzzing code: 0xf
// // 0F C8 64 00 CD 41 E4 75  CE DD D7 CB 1F 2E 54 5F  |  ..d..A.u......T_ 
// // 0D A0 A0 0D 68 C6 D6 0F  4D 62 B1 6D 2F B4 96 D4  |  ....h...Mb.m/... 
// // C9 31 38 96 72 1C 0B 40  F9 E3 0C 19 11 60 78 1F  |  .18.r..@.....`x. 
// // 00 18 2C 68 DE 02 78 2B  64 29 98 94 DD 2E 68 A7  |  ..,h..x+d)....h. 
// // 60 A0 3D D2 BD 49 13 B6  2C 1F CF 3D 7F 47 5C 7F  |  `.=..I..,..=.G\. 
// // 5F 88 E8 3D 8A 60 69 EF  89 01 83 66 30 EB 0D 90  |  _..=.`i....f0... 
// // 8B 4B 62 48 94 75 FF C0                           |  .KbH.u.. 
// 			uint8_t crash_pkt[] = {"\x0F\xC8\x64\x00\xCD\x41\xE4\x75\xCE\xDD\xD7\xCB\x1F\x2E\x54\x5F\x0D\xA0\xA0\x0D\x68\xC6\xD6\x0F\x4D\x62\xB1\x6D\x2F\xB4\x96\xD4\xC9\x31\x38\x96\x72\x1C\x0B\x40\xF9\xE3\x0C\x19\x11\x60\x78\x1F\x00\x18\x2C\x68\xDE\x02\x78\x2B\x64\x29\x98\x94\xDD\x2E\x68\xA7\x60\xA0\x3D\xD2\xBD\x49\x13\xB6\x2C\x1F\xCF\x3D\x7F\x47\x5C\x7F\x5F\x88\xE8\x3D\x8A\x60\x69\xEF\x89\x01\x83\x66\x30\xEB\x0D\x90\x8B\x4B\x62\x48\x94\x75\xFF\xC0"};
// 			memcpy(send_buf, crash_pkt, 104);
// 			fsize = 104;

			/* Send Echo Command */
			//if (send(sk, send_buf, L2CAP_CMD_HDR_SIZE + size, 0) <= 0) {
			printf("fuzzing code: 0x%x\n", send_cmd->code);
			hexdump(send_buf, L2CAP_CMD_HDR_SIZE + fsize);
			if (send(sk, send_buf, L2CAP_CMD_HDR_SIZE + fsize, 0) <= 0) {
				perror("Send failed");
				goto error;
			} else {
				printf(".");
				fflush(stdout);

			}
		}
		/* Wait for Echo Response */
		// lost = 0;
		// while (1) {
		// 	struct pollfd pf[1];
		// 	int err;

		// 	pf[0].fd = sk;
		// 	pf[0].events = POLLIN;

		// 	if ((err = poll(pf, 1, timeout * 1000)) < 0) {
		// 		perror("Poll failed");
		// 		goto error;
		// 	}

		// 	if (!err) {
		// 		lost = 1;
		// 		break;
		// 	}

		// 	if ((err = recv(sk, recv_buf, L2CAP_CMD_HDR_SIZE + size, 0)) < 0) {
		// 		perror("Recv failed");
		// 		goto error;
		// 	}

		// 	if (!err){
		// 		printf("Disconnected\n");
		// 		goto error;
		// 	}

		// 	recv_cmd->len = btohs(recv_cmd->len);

		// 	/* Check for our id */
		// 	if (recv_cmd->ident != id)
		// 		continue;

		// 	/* Check type */
		// 	if (!reverse && recv_cmd->code == L2CAP_ECHO_RSP)
		// 		break;

		// 	if (recv_cmd->code == L2CAP_COMMAND_REJ) {
		// 		printf("Peer doesn't support Echo packets\n");
		// 		goto error;
		// 	}

		// }
		// sent_pkt++;

		// if (!lost) {
		// 	recv_pkt++;

		// 	gettimeofday(&tv_recv, NULL);
		// 	timersub(&tv_recv, &tv_send, &tv_diff);

		// 	if (verify) {
		// 		/* Check payload length */
		// 		if (recv_cmd->len != size) {
		// 			fprintf(stderr, "Received %d bytes, expected %d\n",
		// 				   recv_cmd->len, size);
		// 			goto error;
		// 		}

		// 		/* Check payload */
		// 		if (memcmp(&send_buf[L2CAP_CMD_HDR_SIZE],
		// 				   &recv_buf[L2CAP_CMD_HDR_SIZE], size)) {
		// 			fprintf(stderr, "Response payload different.\n");
		// 			goto error;
		// 		}
		// 	}

		// 	printf("%d bytes from %s id %d time %.2fms\n", recv_cmd->len, svr,
		// 		   id - ident, tv2fl(tv_diff));

		// 	if (delay)
		// 		sleep(delay);
		// } else {
		// 	printf("no response from %s: id %d\n", svr, id - ident);
		// }

		// if (++id > 254)
		// 	id = ident;
	//}
	stat(0);
	free(send_buf);
	free(recv_buf);
	return;

error:
	close(sk);
	free(send_buf);
	free(recv_buf);
	exit(1);
}

static void usage(void)
{
	printf("l2ping - L2CAP ping\n");
	printf("Usage:\n");
	printf("\tl2ping [-i device] [-s size] [-c count] [-t timeout] [-d delay] [-f] [-r] [-v] <bdaddr>\n");
	printf("\t-f  Flood ping (delay = 0)\n");
	printf("\t-r  Reverse ping\n");
	printf("\t-v  Verify request and response payload\n");
}

int main(int argc, char *argv[])
{
	int opt;

	/* Default options */
	bacpy(&bdaddr, BDADDR_ANY);

	while ((opt=getopt(argc,argv,"i:d:s:c:t:frv")) != EOF) {
		switch(opt) {
		case 'i':
			if (!strncasecmp(optarg, "hci", 3))
				hci_devba(atoi(optarg + 3), &bdaddr);
			else
				str2ba(optarg, &bdaddr);
			break;

		case 'd':
			delay = atoi(optarg);
			break;

		case 'f':
			/* Kinda flood ping */
			delay = 0;
			break;

		case 'r':
			/* Use responses instead of requests */
			reverse = 1;
			break;

		case 'v':
			verify = 1;
			break;

		case 'c':
			count = atoi(optarg);
			break;

		case 't':
			timeout = atoi(optarg);
			break;

		case 's':
			size = atoi(optarg);
			break;

		default:
			usage();
			exit(1);
		}
	}

	if (!(argc - optind)) {
		usage();
		exit(1);
	}

	printf("Fuzzer starting!\n");
	init_rand(0);
	ping(argv[optind]);

	return 0;
}
