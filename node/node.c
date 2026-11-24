/*
 * node.c -- honest RPL node + UDP source for the security testbed.
 * Based on the Contiki-NG rpl-udp client example, with instrumentation.
 */
#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "random.h"

#include "../common/rpl-instrument.h"
#include "sys/log.h"

#include <stdio.h>
#include <string.h>

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#ifndef APP_SEND_INTERVAL
#define APP_SEND_INTERVAL (60 * CLOCK_SECOND)
#endif

static struct simple_udp_connection udp_conn;

PROCESS(node_process, "RPL security node");
AUTOSTART_PROCESSES(&node_process);
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr, uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr, uint16_t receiver_port,
                const uint8_t *data, uint16_t datalen)
{
  uint32_t seq = 0;
  uint16_t remaining = datalen;
  const char *p = (const char *)data;
  /* The root echoes back "hello <seq>"; recover seq for the round-trip time. */
  while(remaining > 0 && (*p < '0' || *p > '9')) { p++; remaining--; }
  while(remaining > 0 && *p >= '0' && *p <= '9') { seq = seq * 10 + (*p - '0'); p++; remaining--; }
  instrument_app_ack(seq, sender_addr);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(node_process, ev, data)
{
  static struct etimer periodic_timer;
  static char str[32];
  static uint32_t tx_count;
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);
  instrument_start();

  etimer_set(&periodic_timer, random_rand() % APP_SEND_INTERVAL);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if(NETSTACK_ROUTING.node_is_reachable() &&
       NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      snprintf(str, sizeof(str), "hello %lu", (unsigned long)tx_count);
      instrument_app_tx(tx_count, &dest_ipaddr);
      simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);
      tx_count++;
    }

    etimer_set(&periodic_timer, APP_SEND_INTERVAL
               - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
