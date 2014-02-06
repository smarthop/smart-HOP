/**
 * \file
 *         RPL Unreachability Detection
 * \author
 *         Daniel Moreira
 */

#include "dev/leds.h"
#include "net/rpl/rpl-private.h"
#include "net/rpl/rpl.h"
#include "net/uip-nd6.h"
#include "net/uip-ds6.h"
#include "net/uip.h"
#include "sys/ctimer.h"
#include "net/packetbuf.h"
#include "sys/clock.h"
#include "net/tcpip.h"
#include <limits.h>
#include <string.h>
#include "net/uip-debug.h"

#define DEBUG DEBUG_PRINT
#define SEND_TIME (CLOCK_SECOND / 50)
#define WAIT_DIO (CLOCK_SECOND / 15)
/* This timer is started after DIS is sent. If no DIO is received when timer reaches 0,
 * the parent will be considered unreachable
 */
rpl_parent_t *p;
rpl_dag_t *dag;
rpl_instance_t *instance;
rpl_instance_t *end;
uip_ipaddr_t *pref;
rpl_dio_t dio;
uint8_t counter = 1;
int rssi;
char reliable;
static int dis_burst_flag = 0, wait_dio_flag = 0;
static struct etimer dio_check, dis_timer;
uint32_t current_t;

/*---------------------------------------------------------------------------*/
/* Per-parent RPL information */
NBR_TABLE(rpl_parent_t, rpl_parents);

PROCESS(unreach_process, "rpl-unreach process");
process_event_t unreach_event;

/*---------------------------------------------------------------------------*/
/* This function is called from rpl-icmp6.c when a DIO was received from the parent, meaning it is reachable after all.
 * The DIO check process is killed, but the DIO needs to pass a 2nd check. If the RSSI of the received packet
 * is above threshold (-90), the parent is considered unreliable and mobility is performed.
 */
void
rpl_unreach()
{
  process_start(&unreach_process, NULL);
}
/*
 * This function starts the timer to start dis_burst in discovery phase.
 */
void
rpl_dis_burst()
{
  etimer_set(&dis_timer, SEND_TIME);
}
void
eventhandler(process_event_t ev, process_data_t data)
{
  switch(ev) {

  case PARENT_UNREACHABLE:
  {
    instance = &instance_table[0];
    dag = instance->current_dag;
    if(dag->preferred_parent != NULL) {
    	p = dag->preferred_parent;
    	PRINT6ADDR(rpl_get_parent_ipaddr(p));
    } else {
    	PRINTF("NULL");
    }
    PRINTF("\n");

    if(test_unreachable == 1 && hand_off_backoff_flag == 0) {
      PRINTF("Connection unstable\n");
      dis_output(rpl_get_parent_ipaddr(p), 1, 0);   /* Send DIS to assess parent */
      reliable = 0;
      if(wait_dio_flag == 0) {
        /*
         * Wait DIO reply. If parent doesn't reply until timer finishes,
         * he's considered unreachable.
         */
        etimer_set(&dio_check, WAIT_DIO);
        wait_dio_flag++;
      } else {
        etimer_reset(&dio_check);
      }
    }
  }
  break;

  case PARENT_REACHABLE:
  {
    uint8_t *dis_rssi;

    /* We received the DIO reply from parent but we need to check the RSSI value */
    dis_rssi = data;
    rssi = dis_rssi - 45;
    if(dis_rssi > 200) {
      rssi = dis_rssi - 255 - 46;
    }
    PRINTF("RSSI response from parent = %d ->", rssi);
    if(rssi <= -85) {
      PRINTF(" Unreliable\n");
      mobility_flag = 1;
      leds_on(LEDS_ALL);
      current_t = clock_time() * 1000 / CLOCK_SECOND;
      PRINTF("%u\n", current_t);
      dis_output(NULL, 1, counter);
      rpl_dis_burst();
      /*rpl_remove_parent(dag,dag->preferred_parent); */
    } else {
      PRINTF(" Reliable\n");
      reliable = 1;
      process_post(&tcpip_process, RESET_MOBILITY_FLAG, NULL);
    }
  }
  break;

  case DIS_BURST:
  {
    etimer_reset(&dis_timer);
  }
  break;

  /* DIO received when checking current parent, stop the timer */
  case STOP_DIO_CHECK:
  {
    PRINTF("Stopping wait_dio timer\n");
    etimer_stop(&dio_check);
  }
  break;

  case PROCESS_EVENT_TIMER:
  {
/* Current parent Unreachable/Unreliable, print current time and start DIS_BURST */
    if(data == &dio_check && etimer_expired(&dio_check) && !reliable
       && test_unreachable == 1) {
      mobility_flag = 1;
      if(dis_burst_flag == 0) {
    	  rpl_nullify_parent(dag->preferred_parent);
    	  /*rpl_remove_parent(dag->preferred_parent);*/
        dis_burst_flag++;
        current_t = clock_time() * 1000 / CLOCK_SECOND;
        PRINTF("%u\n", current_t); /* Print current time to measure hand-off */
        dis_output(NULL, 1, counter);
        etimer_set(&dis_timer, SEND_TIME);
      } else {
        etimer_reset(&dis_timer);
      }
    }
/* 1st DIS was sent above. Check for the backoff delay and keep sending (Total = 3DIS) */
    if(data == &dis_timer && etimer_expired(&dis_timer)) {
      counter++;
      dis_output(NULL, 1, counter);
      if(counter < 3) {
        etimer_reset(&dis_timer);
      } else {
        counter = 1;
        dis_burst_flag = 0;
      }
    }
  }
  break;
  }
}
PROCESS_THREAD(unreach_process, ev, data)
{
  PROCESS_BEGIN();
  unreach_event = process_alloc_event();
  while(1) {
    PROCESS_YIELD();
    eventhandler(ev, data);
  }
  PROCESS_END();
}
