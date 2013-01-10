#ifndef __HEADER__
#define __HEADER__

#ifndef BISMARK_ID_FILENAME
#define BISMARK_ID_FILENAME "/etc/bismark/ID"
#endif

#define ANONYMIZATION_SEED_LEN 16
#ifndef ANONYMIZATION_SEED_FILE
#define ANONYMIZATION_SEED_FILE "/etc/bismark/passive.key"
#endif
#define UPDATE_PERIOD_SECONDS 60

#define PCAP_TIMEOUT_MILLISECONDS 1000
#define PCAP_PROMISCUOUS 1
#define ALARMS_PER_UPDATE 6
#define NUM_MICROS_PER_SECOND 1e6
#define TRUE 1
#define FALSE 0
#define MAX_MCS_INDEX   76 
#define SNAP_LEN 300 +50

    
extern int64_t start_timestamp_microseconds;
extern int sequence_number ; 
extern int mgmt_beacon_count ; 
extern time_t current_timestamp ;  
extern char bismark_id[256];
int write_update();
extern char ifc ;

#define pletohs(p)  ((u_int16_t)                       \
  ((u_int16_t)*((const u_int8_t *)(p)+1)<<8|  \
   (u_int16_t)*((const u_int8_t *)(p)+0)<<0))

#define pletohl(p)  ((u_int32_t)*((const u_int8_t *)(p)+3)<<24|  \
  (u_int32_t)*((const u_int8_t *)(p)+2)<<16|  \
  (u_int32_t)*((const u_int8_t *)(p)+1)<<8|   \
		     (u_int32_t)*((const u_int8_t *)(p)+0)<<0)



#define pletoh64(p) ((u_int64_t)*((const u_int8_t *)(p)+7)<<56|  \
  (u_int64_t)*((const u_int8_t *)(p)+6)<<48|  \
  (u_int64_t)*((const u_int8_t *)(p)+5)<<40|  \
  (u_int64_t)*((const u_int8_t *)(p)+4)<<32|  \
  (u_int64_t)*((const u_int8_t *)(p)+3)<<24|  \
  (u_int64_t)*((const u_int8_t *)(p)+2)<<16|  \
  (u_int64_t)*((const u_int8_t *)(p)+1)<<8|   \
		     (u_int64_t)*((const u_int8_t *)(p)+0)<<0)

extern unsigned char * snapend;
int checkup(char * device);
int mac_header_parser(unsigned char * p , int pkt_lent, int cap_len,int type,int radiotap_len ) ;
int mac_header_err_parser(unsigned char * p , int pkt_len, int cap_len) ;
int scanning();

#define UPDATE_DROPS_FILENAME    "/tmp/bismark-uploads/mac-analyzer/%s-%" PRIu64 "-drops-%d-%c.gz"
#define PENDING_UPDATE_DROPS_FILENAME "/tmp/mac-analyzer/current-drops-update-%c.gz"

#ifndef HOMESAW_RX_FRAME_HEADER
#define HOMESAW_RX_FRAME_HEADER 58
#endif 

#define PHY_TABLE_ENTRIES 1024 
typedef struct {
 unsigned char phy_content[HOMESAW_RX_FRAME_HEADER];
} phy_address_table_entry_t; 

typedef struct {
	phy_address_table_entry_t entries[PHY_TABLE_ENTRIES];
	u_int16_t length;
	u_int32_t missed ;
} phy_address_table_t;

extern int phy_err_flag ; 
extern phy_address_table_t phy_address_table;
#include <zlib.h>
void address_phy_table_init(phy_address_table_t* table);
int address_phy_table_update(phy_address_table_t *table , unsigned char* pkt);
int  address_phy_table_write_update(phy_address_table_t *phy_address_table,gzFile phy_handle);



#endif
