/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */
struct sr_if* this_iface;
/* TODO: Add helper functions here... */

struct sr_rt *longest_mtch_prefix(struct sr_instance* sr, uint32_t target_ip){
  int maxcount = -1;
  struct sr_rt* rt_walker = 0;
  struct sr_rt* longest_mtch_entry = NULL;
  if(sr->routing_table == 0){
      printf(" *warning* Routing table empty \n");
      return NULL;
  }
  rt_walker = sr->routing_table;
  while(rt_walker){
    uint32_t gateway = ntohl(rt_walker->gw.s_addr);
    uint32_t mask = ntohl(rt_walker->mask.s_addr);
    int mask_count = 0;
    int i=31;
    while (i>=0){
      if ((mask>>i) & 1)
        mask_count++;
      else
          break;                                                                
      i--;
    }
    uint32_t mini = gateway & mask;
    int count = 0;
    i=31;
    while (i>=0){
      if (((target_ip>>i) & 1) == ((mini >> i) & 1))
        count++;
      else
          break;                                                                
      i--;
    }
    if (count>=mask_count){
      if (count > maxcount){
        maxcount = count;
        longest_mtch_entry = rt_walker;
      }
    }
    rt_walker = rt_walker->next; 
  }
  return longest_mtch_entry;
}


/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  time_t now;
  time(&now);
  if (difftime(now,req->sent)>1.0){
    /*ARP request sent five times without reply */
    if (req->times_sent>=5){
      printf("************ Came here\n");
      /* Send icmp host unreachable (type 3 code 1) for all the packets waiting on this request*/
      sr_icmp_t3_hdr_t *my_icmp_hdr = (sr_icmp_t3_hdr_t *)malloc(sizeof(sr_icmp_t3_hdr_t));
      my_icmp_hdr->icmp_type = 3;
      my_icmp_hdr->icmp_code = 1;
      struct sr_packet *pkt_walker = req->packets;
      while (pkt_walker!=NULL){
      /* Iterate and send error message to all packets waiting for this ARP reply */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
        memcpy(eth_hdr,pkt_walker->buf,sizeof(sr_ethernet_hdr_t));
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
        memcpy(send_ip_hdr,pkt_walker->buf+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t));
        struct sr_rt *longest_mtch_entry = longest_mtch_prefix(sr, ntohl(send_ip_hdr->ip_src));
        struct sr_if* buf_iface = sr_get_interface(sr, (const char*)longest_mtch_entry->interface);
        struct sr_if* next_iface = sr_get_interface(sr, (const char*)pkt_walker->iface); 
        int pos = 0;
        for (; pos < ETHER_ADDR_LEN; pos++) {
          eth_hdr->ether_dhost[pos] = eth_hdr->ether_shost[pos]; 
          eth_hdr->ether_shost[pos] = buf_iface->addr[pos]; /*As mentioned in pdf, can send through any interface*/
        }
        send_ip_hdr->ip_dst = send_ip_hdr->ip_src;
        send_ip_hdr->ip_src = next_iface->ip;
        send_ip_hdr->ip_p = ip_protocol_icmp;
        memcpy(my_icmp_hdr->data,pkt_walker->buf+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t)+8*sizeof(uint8_t));
        my_icmp_hdr->icmp_sum = 0;
        my_icmp_hdr->icmp_sum = cksum(my_icmp_hdr,sizeof(sr_icmp_t3_hdr_t));
        send_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_sum = cksum(send_ip_hdr,sizeof(sr_ip_hdr_t));
        void *new_packet = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
        memcpy(new_packet,eth_hdr,sizeof(sr_ethernet_hdr_t));
        memcpy(new_packet+sizeof(sr_ethernet_hdr_t),send_ip_hdr,sizeof(sr_ip_hdr_t));
        memcpy(new_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t),my_icmp_hdr,sizeof(sr_icmp_t3_hdr_t));
        sr_send_packet(sr,new_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t),longest_mtch_entry->interface);
        printf(" Sent through iface %s\n",longest_mtch_entry->interface);
        free(eth_hdr);
        free(send_ip_hdr);
        free(new_packet);
        pkt_walker = pkt_walker->next;
      }
      /*Destroy all the requests waiting for this ARP reply and delete from queue*/
      free(my_icmp_hdr);
      sr_arpreq_destroy(&sr->cache, req);
    }
    else{
      /*Send ARP broadcast request*/  
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
      sr_arp_hdr_t *send_arp_hdr = (sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
      /*find the interface through which to send the request*/
      struct sr_rt *match = longest_mtch_prefix(sr, ntohl(req->ip));
      struct sr_if* send_arp_iface = sr_get_interface(sr, (const char*)match->interface);
      /*construct the ARP header and send*/
      int pos = 0;
      for (; pos < ETHER_ADDR_LEN; pos++) {
        eth_hdr->ether_dhost[pos] = 0xff;
        send_arp_hdr->ar_tha[pos] = 0xff;
        eth_hdr->ether_shost[pos] = send_arp_iface->addr[pos]; 
        send_arp_hdr->ar_sha[pos] = send_arp_iface->addr[pos];
      }
      eth_hdr->ether_type = htons(ethertype_arp);
      send_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
      send_arp_hdr->ar_pro = htons(2048);
      send_arp_hdr->ar_op = htons(arp_op_request);
      send_arp_hdr->ar_hln = 6;
      send_arp_hdr->ar_pln = 4;
      send_arp_hdr->ar_tip = req->ip;
      send_arp_hdr->ar_sip = send_arp_iface->ip;
      uint32_t len =  sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
      void *send_buf = malloc(len);
      memcpy(send_buf,eth_hdr,sizeof(sr_ethernet_hdr_t));
      memcpy(send_buf+sizeof(sr_ethernet_hdr_t),send_arp_hdr,sizeof(sr_arp_hdr_t));
      sr_send_packet(sr,send_buf,len,match->interface);
      time(&req->sent);
      free(eth_hdr);
      free(send_arp_hdr);
      free(send_buf);
      req->times_sent++;
    }
  }
  
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* TODO: (opt) Add initialization code here */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);                                                                              /* */

  /* TODO: Add forwarding logic here */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (len < minlength){
    /* packet length invalid */
    fprintf(stderr, "Failed to process Ethernet header, insufficient length\n");
    return;
  }
  uint16_t ethtype = ethertype(packet);
  this_iface = sr_get_interface(sr, (const char*)interface);
  /* if the packet is an IP packet */
  if (ethtype == ethertype_ip) {
    minlength += sizeof(sr_ip_hdr_t);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    /* sanity checks */
    uint16_t checksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    if (len < minlength){
    /* length not sufficient as per ip */
      fprintf(stderr, "Failed to process IP header, insufficient length\n");
      return;
    }
    else if (cksum(ip_hdr,sizeof(sr_ip_hdr_t))!=checksum){
    /* checksum not matching */
      fprintf(stderr, "Failed to process IP header, checksums don't match\n");
      return;
    }
    else{
    /* passed sanity checks */
      ip_hdr->ip_sum = checksum;
      uint32_t target_ip = ntohl(ip_hdr->ip_dst);
      uint32_t my_ip;
      struct sr_if*i_walker = sr->if_list;
      struct sr_if*curr_iface;
      /*Check if the packet is intended to any of this router's interfaces*/
      while (i_walker){
        if (target_ip==ntohl(i_walker->ip)){
          my_ip = ntohl(i_walker->ip);
          curr_iface = i_walker;
          break;
        }
        i_walker = i_walker->next;
      }            
      if (my_ip==target_ip){   
      /* Two cases: echo message, or UDP/TCP message */
        uint8_t * send_buf = (uint8_t *)malloc(len);
        memcpy(send_buf, packet, len);
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)send_buf;
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(send_buf+sizeof(sr_ethernet_hdr_t));
        /*Creating an appropiate IP header to reply to the sender*/ 
        int pos = 0;
        for (; pos < ETHER_ADDR_LEN; pos++) {
          eth_hdr->ether_dhost[pos] = eth_hdr->ether_shost[pos];
          eth_hdr->ether_shost[pos] = this_iface->addr[pos];
        }
        uint32_t temp_ip_src = send_ip_hdr->ip_src;
        send_ip_hdr->ip_src = curr_iface->ip;
        send_ip_hdr->ip_dst = temp_ip_src;
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_sum = cksum(send_ip_hdr,sizeof(sr_ip_hdr_t));
        uint8_t ip_proto = ip_protocol((uint8_t *)ip_hdr);
        if (ip_proto==ip_protocol_icmp){
        /* This is an icmp protocol packet*/
          sr_icmp_hdr_t *my_icmp_hdr = (sr_icmp_hdr_t *)(send_buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
          uint16_t icmp_cksum = my_icmp_hdr->icmp_sum;
          my_icmp_hdr->icmp_sum = 0;
          uint16_t computed_ck = cksum(my_icmp_hdr,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
          /* verify ICMP checksum */
          if (computed_ck!=icmp_cksum){
            fprintf(stderr, "Failed to process ICMP header, checksums don't match\n");
            return;
          }
          if (my_icmp_hdr->icmp_type==8){
          /* It is an Echo request, send an echo reply*/
            my_icmp_hdr->icmp_type=0;
            my_icmp_hdr->icmp_sum = cksum(my_icmp_hdr,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
            sr_send_packet(sr,send_buf,len,this_iface->name);
          }

        }
        else if (ip_proto==ip_protocol_tcp || ip_proto==ip_protocol_udp){
        /*packet contains payload, so send icmp with port unreachable*/
          sr_ethernet_hdr_t *neweth_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
          memcpy(neweth_hdr,eth_hdr,sizeof(sr_ethernet_hdr_t));
          sr_ip_hdr_t *newsend_ip_hdr = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
          memcpy(newsend_ip_hdr,send_ip_hdr,sizeof(sr_ip_hdr_t));
          sr_icmp_t3_hdr_t *my_icmp_hdr = (sr_icmp_t3_hdr_t *)malloc(sizeof(sr_icmp_t3_hdr_t));
          newsend_ip_hdr->ip_p = ip_protocol_icmp;
          my_icmp_hdr->icmp_type = 3;
          my_icmp_hdr->icmp_code = 3;
          my_icmp_hdr->icmp_sum = 0;
          memcpy(my_icmp_hdr->data,packet+ sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t)+8*sizeof(uint8_t));
          my_icmp_hdr->icmp_sum = cksum(my_icmp_hdr,sizeof(sr_icmp_t3_hdr_t)); 
          newsend_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          newsend_ip_hdr->ip_sum = 0;
          newsend_ip_hdr->ip_sum = cksum(newsend_ip_hdr,sizeof(sr_ip_hdr_t));
          void *new_packet = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          memcpy(new_packet,neweth_hdr,sizeof(sr_ethernet_hdr_t));
          memcpy(new_packet+sizeof(sr_ethernet_hdr_t),newsend_ip_hdr,sizeof(sr_ip_hdr_t));
          memcpy(new_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t),my_icmp_hdr,sizeof(sr_icmp_t3_hdr_t));
          sr_send_packet(sr,new_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t),this_iface->name);
          free(neweth_hdr);
          free(new_packet);
          free(newsend_ip_hdr);
        }
        free(send_buf);
      }
      else{
      /* This interface is not end host, so find longest matching prefix and forward */
        /* Logic for finding longest matching prefix*/
                uint8_t * send_buf = (uint8_t *)malloc(len);
        memcpy(send_buf, packet, len);
        sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)(send_buf+sizeof(sr_ethernet_hdr_t));
        /* Decrementing TTL*/
        send_ip_hdr->ip_ttl--;
        if (send_ip_hdr->ip_ttl==0){
          ip_hdr->ip_sum = checksum;
          /* TTL became zero, discard this packet and send icmp type 11 code 0 */
          sr_ip_hdr_t *newsend_ip_hdr = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
          memcpy(newsend_ip_hdr,packet+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t));
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
          memcpy(eth_hdr,packet,sizeof(sr_ethernet_hdr_t));
          int pos = 0;
          for (; pos < ETHER_ADDR_LEN; pos++) {
            eth_hdr->ether_dhost[pos] = eth_hdr->ether_shost[pos];
            eth_hdr->ether_shost[pos] = this_iface->addr[pos];
          }
          newsend_ip_hdr->ip_dst = newsend_ip_hdr->ip_src;
          newsend_ip_hdr->ip_src = this_iface->ip;
          newsend_ip_hdr->ip_p = ip_protocol_icmp;
          newsend_ip_hdr->ip_sum = 0;
          newsend_ip_hdr->ip_ttl = 64;
          sr_icmp_t3_hdr_t *my_icmp_hdr = (sr_icmp_t3_hdr_t *)malloc(sizeof(sr_icmp_t3_hdr_t));
          my_icmp_hdr->icmp_type = 11;
          my_icmp_hdr->icmp_code = 0;
          my_icmp_hdr->icmp_sum = 0;
          memcpy(my_icmp_hdr->data,send_buf + sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t)+8*sizeof(uint8_t));
          my_icmp_hdr->icmp_sum = cksum(my_icmp_hdr,sizeof(sr_icmp_t3_hdr_t)); 
          newsend_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          newsend_ip_hdr->ip_sum = cksum(newsend_ip_hdr,sizeof(sr_ip_hdr_t));
          void *new_packet = malloc(sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          memcpy(new_packet,eth_hdr,sizeof(sr_ethernet_hdr_t));
          memcpy(new_packet+sizeof(sr_ethernet_hdr_t),newsend_ip_hdr,sizeof(sr_ip_hdr_t));
          memcpy(new_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t),my_icmp_hdr,sizeof(sr_icmp_t3_hdr_t));
          sr_send_packet(sr,new_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t),this_iface->name);
          free(eth_hdr);
          free(newsend_ip_hdr);
          free(new_packet);
          free(send_buf);
          return;
        }
        send_ip_hdr->ip_sum = 0;
        send_ip_hdr->ip_sum = cksum(send_ip_hdr,sizeof(sr_ip_hdr_t));
        struct sr_rt *longest_mtch_entry = longest_mtch_prefix(sr,target_ip);
        if (!longest_mtch_entry){
          /*no matching entry , send icmp net unreachable error type 3 code 0*/
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
          memcpy(eth_hdr,packet,sizeof(sr_ethernet_hdr_t));
          sr_ip_hdr_t *send_ip_hdr = (sr_ip_hdr_t *)malloc(sizeof(sr_ip_hdr_t));
          memcpy(send_ip_hdr,packet+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t)); 
          sr_icmp_t3_hdr_t *my_icmp_hdr = (sr_icmp_t3_hdr_t *)malloc(sizeof(sr_icmp_t3_hdr_t));
          int pos = 0;
          for (; pos < ETHER_ADDR_LEN; pos++) {
            eth_hdr->ether_dhost[pos] = eth_hdr->ether_shost[pos]; 
            eth_hdr->ether_shost[pos] = this_iface->addr[pos]; /*As mentioned in pdf, can send through any interface*/
          }
          send_ip_hdr->ip_dst = send_ip_hdr->ip_src;
          send_ip_hdr->ip_src = this_iface->ip;
          send_ip_hdr->ip_p = ip_protocol_icmp;
          send_ip_hdr->ip_sum = 0;
          send_ip_hdr->ip_sum = cksum(send_ip_hdr,sizeof(sr_ip_hdr_t));
          memcpy(my_icmp_hdr->data,packet+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t)+8*sizeof(uint8_t));
          my_icmp_hdr->icmp_type = 3;
          my_icmp_hdr->icmp_code = 0;
          my_icmp_hdr->icmp_sum = 0;
          my_icmp_hdr->icmp_sum = cksum(my_icmp_hdr,sizeof(sr_icmp_t3_hdr_t));
          send_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          send_ip_hdr->ip_sum = 0;
          send_ip_hdr->ip_sum = cksum(send_ip_hdr,sizeof(sr_ip_hdr_t));
          void *new_packet = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          memcpy(new_packet,eth_hdr,sizeof(sr_ethernet_hdr_t));
          memcpy(new_packet+sizeof(sr_ethernet_hdr_t),send_ip_hdr,sizeof(sr_ip_hdr_t));
          memcpy(new_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t),my_icmp_hdr,sizeof(sr_icmp_t3_hdr_t));
          sr_send_packet(sr,new_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t),this_iface->name);
          free(eth_hdr);
          free(send_ip_hdr);
          free(my_icmp_hdr);
          free(new_packet);
          return;
        }
        /* need to find next-hop mac address*/
        struct sr_arpentry *lookup = sr_arpcache_lookup(&sr->cache, longest_mtch_entry->gw.s_addr);
        if (lookup){
        /* Cache hit, use the value*/
          sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)send_buf;
          struct sr_if* buf_iface = sr_get_interface(sr, (const char*)longest_mtch_entry->interface);
          int pos = 0;
          for (; pos < ETHER_ADDR_LEN; pos++) {
            eth_hdr->ether_shost[pos] = buf_iface->addr[pos];
            eth_hdr->ether_dhost[pos] = lookup->mac[pos];
          }
          sr_send_packet(sr,send_buf,len,longest_mtch_entry->interface);
        }
        else{
        /* Cache miss, need to broadcast*/
          struct sr_arpreq * this_req = sr_arpcache_queuereq(&sr->cache, longest_mtch_entry->gw.s_addr,send_buf,len,longest_mtch_entry->interface);
          handle_arpreq(sr,this_req);
        }
        free(send_buf);
      }                                                                                             /**/
    }
  }  
  /* if the packet is an ARP packet */
  else if (ethtype == ethertype_arp){
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    uint32_t target_ip = ntohl(arp_hdr->ar_tip);
    uint32_t my_ip;
    struct sr_if*i_walker = sr->if_list;
    struct sr_if*curr_iface;
    while (i_walker){
      if (target_ip==ntohl(i_walker->ip)){
        my_ip = ntohl(i_walker->ip);
        curr_iface = i_walker;
        break;
      }
      i_walker = i_walker->next;
    }
    /* ARP is intended to this router itself (else do nothing ==>drop packet)*/
    if (my_ip==target_ip){
      if (ntohs(arp_hdr->ar_op)==arp_op_request){
        /* packet is an ARP broadcast request asking for our MAC*/
        uint8_t * send_buf = (uint8_t *)malloc(len);
        memcpy(send_buf, packet, len);
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)send_buf;
        sr_arp_hdr_t *send_arp_hdr = (sr_arp_hdr_t *)(send_buf+sizeof(sr_ethernet_hdr_t)); 
        int pos = 0;
        for (; pos < ETHER_ADDR_LEN; pos++) {
          eth_hdr->ether_dhost[pos] = eth_hdr->ether_shost[pos];
          send_arp_hdr->ar_tha[pos] = send_arp_hdr->ar_sha[pos];
          eth_hdr->ether_shost[pos] = this_iface->addr[pos];
          send_arp_hdr->ar_sha[pos] = curr_iface->addr[pos]; 
        }
        send_arp_hdr->ar_op = htons(arp_op_reply);
        send_arp_hdr->ar_sip = curr_iface->ip;
        send_arp_hdr->ar_tip = arp_hdr->ar_sip;
        sr_send_packet(sr,send_buf,len,this_iface->name);
        free(send_buf);
        /* Cache the pair of sender ip and sender MAC*/
        sr_arpcache_insert(&sr->cache, send_arp_hdr->ar_tha, send_arp_hdr->ar_tip);

      }
      else{
        /* packet is an ARP reply, serve packets waiting for it */
        sr_arp_hdr_t *recvd_arp_hdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
        struct sr_arpreq * req = sr_arpcache_insert(&sr->cache, recvd_arp_hdr->ar_sha, recvd_arp_hdr->ar_sip);
        if (req){
          struct sr_packet *pkt_walker = req->packets;
          while (pkt_walker!=NULL){
          /* Iterate and send all packets waiting for this ARP reply */
            sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)pkt_walker->buf;
            struct sr_if* buf_iface = sr_get_interface(sr, (const char*)pkt_walker->iface);
            int pos = 0;
            for (; pos < ETHER_ADDR_LEN; pos++) {
              eth_hdr->ether_shost[pos] = buf_iface->addr[pos];
              eth_hdr->ether_dhost[pos] = recvd_arp_hdr->ar_sha[pos];
            }
            sr_send_packet(sr,pkt_walker->buf,pkt_walker->len,pkt_walker->iface);
            pkt_walker = pkt_walker->next;
          }
          /*Destroy all the requests waiting for this ARP reply and delete from queue*/
          sr_arpreq_destroy(&sr->cache, req);
        }
      }
    }
  }
  else{
    printf("Error\n");
  }


}/* -- sr_handlepacket -- */

