#include <errno.h>
#include <error.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> /*IP_PROTO*/
#include <linux/if.h> /*for IFF_PROMISC*/
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <linux/wireless.h>
#include <zlib.h>
#include "header.h"
static int config_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct iwreq    wrq;
  memset(&wrq, 0, sizeof(wrq));
  strncpy(wrq.ifr_name, device, IFNAMSIZ);
  wrq.u.mode = IW_MODE_MONITOR;
  if (0 > ioctl(sd, SIOCSIWMODE, &wrq)) {
    perror("ioctl(SIOCSIWMODE) \n");
    return -1;
  }
  return 0;
}

static int open_infd(const char device[])
{
  int skbsz ;
  skbsz = 1U << 23 ;
  int in_fd ;
  in_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (in_fd < 0) {
    perror("socket(PF_PACKET)\n");
    return -1;
  }
  struct ifreq ifr;
  strncpy(ifr.ifr_name, device, sizeof(ifr.ifr_name));

  if (0 > ioctl(in_fd, SIOCGIFINDEX, &ifr)) {
    perror("ioctl(SIOGIFINDEX)\n");
    return -1;
  }
  //printf("the ifindex of device is %d\n",ifr.ifr_ifindex);
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family  = AF_PACKET;
  sll.sll_ifindex = ifr.ifr_ifindex;
  sll.sll_protocol= htons(ETH_P_ALL);
  if (0 > bind(in_fd, (struct sockaddr *) &sll, sizeof(sll))) {
    perror("bind()\n");
    return -1;
  }

  if (0 > setsockopt(in_fd, SOL_SOCKET, SO_RCVBUF, &skbsz, sizeof(skbsz))) {
    perror("setsockopt(in_fd, SO_RCVBUF)\n");
    return -1;
  }
  int skbsz_l = sizeof(skbsz);
  if (0 > getsockopt(in_fd, SOL_SOCKET, SO_RCVBUF, &skbsz,
		     (socklen_t*)&skbsz_l)) {
    perror("getsockopt(in_fd, SO_RCVBUF)\n");
    return -1;
  }
  int rcv_timeo = 600;
  struct timeval rto = { rcv_timeo, 0};
  if (rcv_timeo > 0 &&
      0 > setsockopt(in_fd, SOL_SOCKET, SO_RCVTIMEO, &rto, sizeof(rto))) {
    perror( "setsockopt(in_fd, SO_RCVTIMEO)\n");

    return -1;
  }
  return in_fd ;
}

static int down_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ);
  if (-1 == ioctl(sd, SIOCGIFFLAGS, &ifr)) {
    perror("ioctl(SIOCGIFLAGS)\n");
    return -1;
  }
  if (0 == ifr.ifr_flags)
    return 0;
  ifr.ifr_flags = 0;
  if (-1 == ioctl(sd, SIOCSIFFLAGS, &ifr)) {
    perror("ioctl(SIOCSIWMODE)\n");

    return -1;
  }
  return 0;
}


static int up_radio_interface(const char device[])
{
  int sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  strncpy(ifr.ifr_name, device, IFNAMSIZ);
  if (-1 == ioctl(sd, SIOCGIFFLAGS, &ifr)) {
    perror("ioctl(SIOCGIFFLAGS)\n");
    return -1;
  }
  const int flags = IFF_UP|IFF_RUNNING|IFF_PROMISC;
  if (ifr.ifr_flags  == flags)
    return 0;
  ifr.ifr_flags = flags;
  if (-1 == ioctl(sd, SIOCSIFFLAGS, &ifr)) {
    perror("ioctl(SIOCSIFFLAGS)\n");
    return -1;
  }
  return 0;
}

int checkup(char * device){
  int in_fd ;
  if (down_radio_interface(device)){
    perror("down radio interface \n");
    return -1;
  }
  if (up_radio_interface(device)){
    perror("up radio interface \n");
    return -1;
  }
  if (config_radio_interface(device)){
    perror("config radio intereface ");
    return -1;
  }
  in_fd = open_infd(device);
  if(in_fd == -1){
    perror("Can't set socket option. Abort ");
    return -1;
  }
  return in_fd;
}
