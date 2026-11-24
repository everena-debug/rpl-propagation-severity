/*
 * attacker.c -- adversary node for the RPL security testbed.
 *
 * Behaves as an ordinary node (joins the DODAG, sends app traffic) so it is
 * indistinguishable at join time, then arms the configured attack behaviour
 * at RPL_SEC_ATTACK_ONSET and disarms it at RPL_SEC_ATTACK_STOP. The actual
 * effect is produced by the hooks in ../common/rpl-attack.c acting inside the
 * RPL core; this file only controls timing.
 *
 * At boot it prints one ABOOT line reporting whether the attack behaviour was
 * compiled into this image (RPL_SEC_ATTACK) and which type, so a run can be
 * verified at a glance.
 */
#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "random.h"

#include "../common/rpl-instrument.h"
#include "../common/rpl-attack.h"
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

/* Attack timing relative to boot. The default starts the attack early and
 * keeps it on for the rest of the run, which makes the effect easy to observe.
 * For clean -> attack -> recover experiments, override RPL_SEC_ATTACK_ONSET
 * and RPL_SEC_ATTACK_STOP at build time (e.g. ONSET=10 min, STOP=30 min). */
#ifndef RPL_SEC_ATTACK_ONSET
#define RPL_SEC_ATTACK_ONSET (2 * 60 * CLOCK_SECOND)
#endif
/* A stop far beyond any normal simulation length means "stay on". Set a real
 * value at build time to model a recovery phase. */
#ifndef RPL_SEC_ATTACK_STOP
#define RPL_SEC_ATTACK_STOP  ((clock_time_t)0x7fffffff)
#endif

/* DIS-flood tick interval. Each tick multicasts one DIS; a short interval
 * makes the flood aggressive without stalling the simulator. */
#ifndef RPL_SEC_DIS_INTERVAL
#define RPL_SEC_DIS_INTERVAL (2 * CLOCK_SECOND)
#endif

static struct simple_udp_connection udp_conn;

PROCESS(attacker_process, "RPL security attacker");
AUTOSTART_PROCESSES(&attacker_process);
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
PROCESS_THREAD(attacker_process, ev, data)
{
  static struct etimer periodic_timer;
  static struct etimer onset_timer;
  static struct etimer stop_timer;
  static struct etimer dis_timer;
  static char str[32];
  static uint32_t tx_count;
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);
  instrument_start();

  /* Boot marker: confirms this image is an attacker build and which behaviour
   * it carries. sec_attack=1 means the adversary hooks are compiled in. */
  LOG_INFO("ABOOT,node=%u,sec_attack=%d,type=%d,onset_ticks=%lu\n",
           instrument_node_id(), (int)RPL_SEC_ATTACK, (int)RPL_SEC_ATTACK_TYPE,
           (unsigned long)RPL_SEC_ATTACK_ONSET);

  /* Schedule the attack phase boundaries. */
  etimer_set(&onset_timer, RPL_SEC_ATTACK_ONSET);
  etimer_set(&stop_timer, RPL_SEC_ATTACK_STOP);

  etimer_set(&periodic_timer, random_rand() % APP_SEND_INTERVAL);
  etimer_set(&dis_timer, RPL_SEC_DIS_INTERVAL);
  while(1) {
    PROCESS_WAIT_EVENT();

    if(etimer_expired(&onset_timer) && !rpl_attack_is_active()) {
      rpl_attack_set_active(1);
    }
    if(etimer_expired(&stop_timer) && rpl_attack_is_active()) {
      rpl_attack_set_active(0);
    }

    /* Drive the DIS flood (no-op unless that attack is armed). */
    if(etimer_expired(&dis_timer)) {
      rpl_attack_dis_flood_tick();
      etimer_reset(&dis_timer);
    }

    if(etimer_expired(&periodic_timer)) {
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
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
