#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "net.h"
#include "buf.h"

// xv6's ethernet and IP addresses
static uint8 local_mac[ETHADDR_LEN] = {0x52, 0x54, 0x00, 0x12, 0x34, 0x56};
static uint32 local_ip = MAKE_IP_ADDR(10, 0, 2, 15);

// qemu host's ethernet address.
static uint8 host_mac[ETHADDR_LEN] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02};

#define MAX_UDP_PORTS 16

static struct spinlock netlock;

struct udp_port
{
  int used;             // is this port in use?
  int port;             // the UDP port number
  struct spinlock lock; // protects this struct
  struct buf *head;     // first packet in the queue
  struct buf *tail;     // last packet in the queue
} udp_ports[MAX_UDP_PORTS];

void netinit(void)
{
  initlock(&netlock, "netlock");
}

//
// bind(int port)
// prepare to receive UDP packets address to the port,
// i.e. allocate any queues &c needed.
//
uint64
sys_bind(void)
{
  int port;
  argint(0, &port);
  if (port < 0 || port > 65535)
    return -1;

  acquire(&netlock);
  // find either an existing binding or a free slot
  for (int i = 0; i < MAX_UDP_PORTS; i++)
  {
    if (udp_ports[i].used && udp_ports[i].port == port)
    {
      // already bound
      release(&netlock);
      return 0;
    }
  }

  for (int i = 0; i < MAX_UDP_PORTS; i++)
  {
    if (!udp_ports[i].used)
    {
      udp_ports[i].used = 1;
      udp_ports[i].port = port;
      udp_ports[i].head = 0;
      udp_ports[i].tail = 0;
      initlock(&udp_ports[i].lock, "udp_port");
      release(&netlock);
      return 0;
    }
  }
  release(&netlock);

  // no free slot
  return -1;
}

//
// unbind(int port)
// release any resources previously created by bind(port);
// from now on UDP packets addressed to port should be dropped.
//
uint64
sys_unbind(void)
{
  int port;
  argint(0, &port);

  if (port < 0 || port > 65535)
    return -1;

  acquire(&netlock);
  for (int i = 0; i < MAX_UDP_PORTS; i++)
  {
    if (udp_ports[i].used && udp_ports[i].port == port)
    {
      // remove binding
      struct udp_port *up = &udp_ports[i];

      acquire(&up->lock);
      // free any queued packets
      while (up->head)
      {
        struct buf *b = up->head;
        up->head = b->next;
        kfree(b); // free packet buffer
      }
      up->tail = 0;
      release(&up->lock);

      up->used = 0;
      up->port = 0;
      release(&netlock);
      return 0;
    }
  }
  release(&netlock);

  // not found
  return -1;
}

//
// recv(int dport, int *src, short *sport, char *buf, int maxlen)
// if there's a received UDP packet already queued that was
// addressed to dport, then return it.
// otherwise wait for such a packet.
//
// sets *src to the IP source address.
// sets *sport to the UDP source port.
// copies up to maxlen bytes of UDP payload to buf.
// returns the number of bytes copied,
// and -1 if there was an error.
//
// dport, *src, and *sport are host byte order.
// bind(dport) must previously have been called.
//
uint64
sys_recv(void)
{
  struct proc *p = myproc();
  int dport;
  uint64 src_userptr;   // user pointer to store source IP (uint32)
  uint64 sport_userptr; // user pointer to store source port (uint16)
  uint64 bufaddr;       // user buffer for payload
  int maxlen;

  argint(0, &dport);
  argaddr(1, &src_userptr);
  argaddr(2, &sport_userptr);
  argaddr(3, &bufaddr);
  argint(4, &maxlen);

  if (dport < 0 || dport > 65535 || maxlen < 0 || maxlen > PGSIZE)
    return -1;

  struct udp_port *up = 0;
  acquire(&netlock);
  for (int i = 0; i < MAX_UDP_PORTS; i++)
  {
    if (udp_ports[i].used && udp_ports[i].port == dport)
    {
      up = &udp_ports[i];
      break;
    }
  }
  release(&netlock);

  if (up == 0)
  {
    // no binding
    return -1;
  }

  // wait for packet on this port
  acquire(&up->lock);
  while (up->head == 0)
  {
    sleep(&up->head, &up->lock);
  }
  struct buf *b = up->head;
  up->head = b->next;
  if (up->head == 0)
    up->tail = 0;
  release(&up->lock);

  // parse IP/UDP from packet stored in b->data
  struct ip *ip = (struct ip *)b->data;
  struct udp *udp = (struct udp *)(ip + 1);

  int udp_payload_len = ntohs(udp->ulen) - sizeof(struct udp);
  if (udp_payload_len > maxlen)
    udp_payload_len = maxlen;

  // copy payload to user buffer
  int err = 0;
  if (copyout(p->pagetable, bufaddr, (char *)(udp + 1), udp_payload_len) < 0)
  {
    err = -1;
  }
  else
  {
    // write src and sport back to user space
    uint32 src_ip_host = ntohl(ip->ip_src);   // host order
    uint16 src_port_host = ntohs(udp->sport); // host order

    if (copyout(p->pagetable, src_userptr, (char *)&src_ip_host, sizeof(src_ip_host)) < 0)
      err = -1;
    if (copyout(p->pagetable, sport_userptr, (char *)&src_port_host, sizeof(src_port_host)) < 0)
      err = -1;
  }

  kfree(b);
  if (err)
    return -1;

  return udp_payload_len;
}

// This code is lifted from FreeBSD's ping.c, and is copyright by the Regents
// of the University of California.
static unsigned short
in_cksum(const unsigned char *addr, int len)
{
  int nleft = len;
  const unsigned short *w = (const unsigned short *)addr;
  unsigned int sum = 0;
  unsigned short answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
  {
    sum += *w++;
    nleft -= 2;
  }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
  {
    *(unsigned char *)(&answer) = *(const unsigned char *)w;
    sum += answer;
  }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum & 0xffff) + (sum >> 16);
  sum += (sum >> 16);
  /* guaranteed now that the lower 16 bits of sum are correct */

  answer = ~sum; /* truncate to 16 bits */
  return answer;
}

//
// send(int sport, int dst, int dport, char *buf, int len)
//
uint64
sys_send(void)
{
  struct proc *p = myproc();
  int sport;
  int dst;
  int dport;
  uint64 bufaddr;
  int len;

  argint(0, &sport);
  argint(1, &dst);
  argint(2, &dport);
  argaddr(3, &bufaddr);
  argint(4, &len);

  int total = len + sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp);
  if (total > PGSIZE)
    return -1;

  char *buf = kalloc();
  if (buf == 0)
  {
    printf("sys_send: kalloc failed\n");
    return -1;
  }
  memset(buf, 0, PGSIZE);

  struct eth *eth = (struct eth *)buf;
  memmove(eth->dhost, host_mac, ETHADDR_LEN);
  memmove(eth->shost, local_mac, ETHADDR_LEN);
  eth->type = htons(ETHTYPE_IP);

  struct ip *ip = (struct ip *)(eth + 1);
  ip->ip_vhl = 0x45; // version 4, header length 4*5
  ip->ip_tos = 0;
  ip->ip_len = htons(sizeof(struct ip) + sizeof(struct udp) + len);
  ip->ip_id = 0;
  ip->ip_off = 0;
  ip->ip_ttl = 100;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = htonl(local_ip);
  ip->ip_dst = htonl(dst);
  ip->ip_sum = in_cksum((unsigned char *)ip, sizeof(*ip));

  struct udp *udp = (struct udp *)(ip + 1);
  udp->sport = htons(sport);
  udp->dport = htons(dport);
  udp->ulen = htons(len + sizeof(struct udp));

  char *payload = (char *)(udp + 1);
  if (copyin(p->pagetable, payload, bufaddr, len) < 0)
  {
    kfree(buf);
    printf("send: copyin failed\n");
    return -1;
  }

  e1000_transmit(buf, total);

  return 0;
}

void ip_rx(char *inbuf, int len)
{
  // don't delete this printf; make grade depends on it.
  static int seen_ip = 0;
  if (seen_ip == 0)
    printf("ip_rx: received an IP packet\n");
  seen_ip = 1;

  //
  // Minimal IP/UDP demux and enqueue into bound UDP port queue.
  //
  if (len < sizeof(struct eth) + sizeof(struct ip))
  {
    kfree(inbuf);
    return;
  }

  struct eth *eth = (struct eth *)inbuf;
  struct ip *ip = (struct ip *)(eth + 1);

  // Basic sanity: IPv4?
  if ((ip->ip_vhl >> 4) != 4)
  {
    kfree(inbuf);
    return;
  }

  // only accept packets addressed to our local IP
  if (ntohl(ip->ip_dst) != local_ip)
  {
    kfree(inbuf);
    return;
  }

  // only handle UDP here
  // if (ip->ip_p != IPPROTO_UDP)
  // {
  //   kfree(inbuf);
  //   return;
  // }

  // bounds check for UDP header presence
  if (len < sizeof(struct eth) + sizeof(struct ip) + sizeof(struct udp))
  {
    kfree(inbuf);
    return;
  }

  struct udp *udp = (struct udp *)(ip + 1);
  int dport = ntohs(udp->dport);

  // find a matching bound UDP port
  struct udp_port *up = 0;
  acquire(&netlock);
  for (int i = 0; i < MAX_UDP_PORTS; i++)
  {
    if (udp_ports[i].used && udp_ports[i].port == dport)
    {
      up = &udp_ports[i];
      break;
    }
  }
  release(&netlock);

  if (!up)
  {
    // nobody bound: drop
    kfree(inbuf);
    return;
  }

  // copy the incoming ethernet/IP/udp packet into a kernel packet buffer
  struct buf *b = (struct buf *)kalloc();
  if (!b)
  {
    kfree(inbuf);
    return;
  }
  // We assume struct buf has a data[] area at its start; copy packet bytes there.
  memmove(b->data, inbuf, len);
  b->next = 0;
  // free the original received buffer
  kfree(inbuf);

  // enqueue onto port's queue and wake any sleepers
  acquire(&up->lock);
  if (up->tail)
  {
    up->tail->next = b;
    up->tail = b;
  }
  else
  {
    up->head = up->tail = b;
  }
  wakeup(&up->head);
  release(&up->lock);
}

void arp_rx(char *inbuf)
{
  static int seen_arp = 0;

  if (seen_arp)
  {
    kfree(inbuf);
    return;
  }
  printf("arp_rx: received an ARP packet\n");
  seen_arp = 1;

  struct eth *ineth = (struct eth *)inbuf;
  struct arp *inarp = (struct arp *)(ineth + 1);

  char *buf = kalloc();
  if (buf == 0)
    panic("send_arp_reply");

  struct eth *eth = (struct eth *)buf;
  memmove(eth->dhost, ineth->shost, ETHADDR_LEN); // ethernet destination = query source
  memmove(eth->shost, local_mac, ETHADDR_LEN);    // ethernet source = xv6's ethernet address
  eth->type = htons(ETHTYPE_ARP);

  struct arp *arp = (struct arp *)(eth + 1);
  arp->hrd = htons(ARP_HRD_ETHER);
  arp->pro = htons(ETHTYPE_IP);
  arp->hln = ETHADDR_LEN;
  arp->pln = sizeof(uint32);
  arp->op = htons(ARP_OP_REPLY);

  memmove(arp->sha, local_mac, ETHADDR_LEN);
  arp->sip = htonl(local_ip);
  memmove(arp->tha, ineth->shost, ETHADDR_LEN);
  arp->tip = inarp->sip;

  e1000_transmit(buf, sizeof(*eth) + sizeof(*arp));

  kfree(inbuf);
}

void net_rx(char *buf, int len)
{
  struct eth *eth = (struct eth *)buf;

  if (len >= sizeof(struct eth) + sizeof(struct arp) &&
      ntohs(eth->type) == ETHTYPE_ARP)
  {
    arp_rx(buf);
  }
  else if (len >= sizeof(struct eth) + sizeof(struct ip) &&
           ntohs(eth->type) == ETHTYPE_IP)
  {
    ip_rx(buf, len);
  }
  else
  {
    kfree(buf);
  }
}
