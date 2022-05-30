#include <netdb.h>
#include <stdio.h>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <iostream>
#include <fstream>
#include <vector> 
#include <sstream>
#include <sys/types.h>
#include <algorithm>
// DNS packet header
/***************************************************************************************
*    Title: DNS packet header
*    Author: pcapplusplus
*    Code version: 20.08+
*    Availability: https://pcapplusplus.github.io/api-docs/structpcpp_1_1dnshdr.html
*
***************************************************************************************/
typedef struct {
	uint16_t id;
# if _BYTE_ORDER_ == __ORDER_BIG_ENDIAN__
	uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;
	uint16_t ra:1;
	uint16_t zero:3;
	uint16_t rcode:4;
# else
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;
	uint16_t rcode:4;
	uint16_t zero:3;
	uint16_t ra:1;
# endif
	uint16_t qcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t adcount;
} dnshdr;