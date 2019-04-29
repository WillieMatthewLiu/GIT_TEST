/* App Layer Parser for Oracle */
#include "app_common.h"
#include "parser_modbus.h"
#include "svrid.h"
#include "oscall.h"
#include "pktfilter.h"
#include "serialize.h"
#include "gapconfig.h"
#include "nlkernel.h"
#include "parser_tcp.h"
#include "db_agent.h"
#include "EMMCJson.h"
#include "lib/memory.h"


typedef struct _modbus_header
{
	/* MBAP Header */
	uint16_t transaction_id;
	uint16_t protocol_id;
	uint16_t length;
	uint8_t  unit_id;

	/* PDU Start */
	uint8_t function_code;
} modbus_header_t;

/* Modbus Application Protocol (MBAP) header. */
struct ModbusHeader_ {
	uint16_t     transactionId;
	uint16_t     protocolId;
	uint16_t     length;
	uint8_t      unitId;
}  __attribute__((__packed__));
typedef struct ModbusHeader_ ModbusHeader;



/* Modbus Application Data Unit (ADU) length range. */
#define MODBUS_MIN_ADU_LEN  2
#define MODBUS_MAX_ADU_LEN  254

/* Modbus Protocol version. */
#define MODBUS_PROTOCOL_VER 0

/* Modbus Unit Identifier range. */
#define MODBUS_MIN_INVALID_UNIT_ID  247
#define MODBUS_MAX_INVALID_UNIT_ID  255

/* Modbus Quantity range. */
#define MODBUS_MIN_QUANTITY                 0
#define MODBUS_MAX_QUANTITY_IN_BIT_ACCESS   2000
#define MODBUS_MAX_QUANTITY_IN_WORD_ACCESS  125

/* Modbus Count range. */
#define MODBUS_MIN_COUNT    1
#define MODBUS_MAX_COUNT    250

/* Modbus Function Code. */
#define MODBUS_FUNC_NONE                0x00
#define MODBUS_FUNC_READCOILS           0x01
#define MODBUS_FUNC_READDISCINPUTS      0x02
#define MODBUS_FUNC_READHOLDREGS        0x03
#define MODBUS_FUNC_READINPUTREGS       0x04
#define MODBUS_FUNC_WRITESINGLECOIL     0x05
#define MODBUS_FUNC_WRITESINGLEREG      0x06
#define MODBUS_FUNC_READEXCSTATUS       0x07
#define MODBUS_FUNC_DIAGNOSTIC          0x08
#define MODBUS_FUNC_GETCOMEVTCOUNTER    0x0b
#define MODBUS_FUNC_GETCOMEVTLOG        0x0c
#define MODBUS_FUNC_WRITEMULTCOILS      0x0f
#define MODBUS_FUNC_WRITEMULTREGS       0x10
#define MODBUS_FUNC_REPORTSERVERID      0x11
#define MODBUS_FUNC_READFILERECORD      0x14
#define MODBUS_FUNC_WRITEFILERECORD     0x15
#define MODBUS_FUNC_MASKWRITEREG        0x16
#define MODBUS_FUNC_READWRITEMULTREGS   0x17
#define MODBUS_FUNC_READFIFOQUEUE       0x18
#define MODBUS_FUNC_ENCAPINTTRANS       0x2b
#define MODBUS_FUNC_MASK                0x7f
#define MODBUS_FUNC_ERRORMASK           0x80

/* Modbus Diagnostic functions: Subfunction Code. */
#define MODBUS_SUBFUNC_QUERY_DATA           0x00
#define MODBUS_SUBFUNC_RESTART_COM          0x01
#define MODBUS_SUBFUNC_DIAG_REGS            0x02
#define MODBUS_SUBFUNC_CHANGE_DELIMITER     0x03
#define MODBUS_SUBFUNC_LISTEN_MODE          0x04
#define MODBUS_SUBFUNC_CLEAR_REGS           0x0a
#define MODBUS_SUBFUNC_BUS_MSG_COUNT        0x0b
#define MODBUS_SUBFUNC_COM_ERR_COUNT        0x0c
#define MODBUS_SUBFUNC_EXCEPT_ERR_COUNT     0x0d
#define MODBUS_SUBFUNC_SERVER_MSG_COUNT     0x0e
#define MODBUS_SUBFUNC_SERVER_NO_RSP_COUNT  0x0f
#define MODBUS_SUBFUNC_SERVER_NAK_COUNT     0x10
#define MODBUS_SUBFUNC_SERVER_BUSY_COUNT    0x11
#define MODBUS_SUBFUNC_SERVER_CHAR_COUNT    0x12
#define MODBUS_SUBFUNC_CLEAR_COUNT          0x14

/* Modbus Encapsulated Interface Transport function: MEI type. */
#define MODBUS_MEI_ENCAPINTTRANS_CAN   0x0d
#define MODBUS_MEI_ENCAPINTTRANS_READ  0x0e

/* Modbus Exception Codes. */
#define MODBUS_ERROR_CODE_ILLEGAL_FUNCTION      0x01
#define MODBUS_ERROR_CODE_ILLEGAL_DATA_ADDRESS  0x02
#define MODBUS_ERROR_CODE_ILLEGAL_DATA_VALUE    0x03
#define MODBUS_ERROR_CODE_SERVER_DEVICE_FAILURE 0x04
#define MODBUS_ERROR_CODE_MEMORY_PARITY_ERROR   0x08



//*****************************************************************

#define MODBUS_MAX_FUNC_NUM     172
#define MODBUS_DEFAULT_PORT     502
#define MODBUS_EXCEPTION_BIT (0x80)

/* Various Modbus lengths */
#define MODBUS_BYTE_COUNT_SIZE 1
#define MODBUS_DOUBLE_BYTE_COUNT_SIZE 2
#define MODBUS_FILE_RECORD_SUB_REQUEST_SIZE 7
#define MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET 5
#define MODBUS_READ_DEVICE_ID_HEADER_LEN 6
#define MODBUS_READ_DEVICE_ID_NUM_OBJ_OFFSET 5

#define MODBUS_EMPTY_DATA_LEN   0
#define MODBUS_FOUR_DATA_BYTES  4
#define MODBUS_BYTE_COUNT_SIZE  1
#define MODBUS_WRITE_MULTIPLE_BYTE_COUNT_OFFSET 4
#define MODBUS_WRITE_MULTIPLE_MIN_SIZE          5
#define MODBUS_MASK_WRITE_REGISTER_SIZE         6
#define MODBUS_READ_WRITE_MULTIPLE_BYTE_COUNT_OFFSET    8
#define MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE             9
#define MODBUS_READ_FIFO_SIZE                           2
#define MODBUS_MEI_MIN_SIZE                             1
#define MODBUS_FUNC_READ_EXCEPTION_RESP_SIZE            1
#define MODBUS_SUB_FUNC_READ_DEVICE_ID_SIZE             3
#define MODBUS_SUB_FUNC_READ_DEVICE_START_LEN           2
#define MODBUS_SUB_FUNC_READ_DEVICE_LENGTH_OFFSET       1

/* Need 8 bytes for MBAP Header + Function Code */
#define MODBUS_MIN_LEN 8


enum {
	MODBUS_PROTOCOL_REQUEST,
	MODBUS_PROTOCOL_RESPONSE
};

enum {
	READ_COILS = 1,
	READ_DISCRETE_INPUTS = 2,
	READ_HOLDING_REGISTERS = 3,
	READ_INPUT_REGISTERS = 4,
	WRITE_SINGLE_COIL = 5,
	WRITE_SINGLE_REGISTER = 6,
	READ_EXCEPTION_STATUS = 7,
	DIAGNOSTICS = 8,
	GET_COMM_EVENT_COUNTER = 11,
	GET_COMM_EVENT_LOG = 12,
	WRITE_MULTIPLE_COILS = 15,
	WRITE_MULTIPLE_REGISTERS = 16,
	REPORT_SLAVE_ID = 17,
	READ_FILE_RECORD = 20,
	WRITE_FILE_RECORD = 21,
	MASK_WRITE_REGISTER = 22,
	RW_MULTIPLE_REGISTERS = 23,
	READ_FIFO_QUEUE = 24,
	ENCAPSULATED_INTERFACE_TRANSPORT = 43,
	MODBUS_SUB_FUNC_CANOPEN = 0x0D,
	MODBUS_SUB_FUNC_READ_DEVICE_ID = 0x0E
};

enum {
	RETURN_QUERY_DATA,
	RESTART_COMMUNICATIONS_OPTION,
	RETURN_DIAGNOSTIC_REGISTER,
	CHANGE_ASCII_INPUT_DELIMITER,
	FORCE_LISTEN_ONLY_MODE,
	CLEAR_COUNTERS_AND_DIAGNOSTIC_REGISTER = 0x0A,
	RETURN_BUS_MESSAGE_COUNT,
	RETURN_BUS_COMMUNICATION_ERROR_COUNT,
	RETURN_BUS_EXCEPTION_ERROR_COUNT,
	RETURN_SLAVE_MESSAGE_COUNT,
	RETURN_SLAVE_NO_RESPONSE_COUNT,
	RETURN_SLAVE_NAK_COUNT,
	RETURN_SLAVE_BUSY_COUNT,
	RETURN_BUS_CHARACTER_OVERRUN_COUNT,
	CLEAR_OVERRUN_COUNTER_AND_FLAG = 0x14
};


enum {
	MODBUS_FUNC_TYPE,
	MODBUS_START_ADDR,
	MODBUS_END_ADDR,
	MODBUS_REF_ADDR,
	MODBUS_FIFO_ADDR,
	MODBUS_MEI_TYPE,
	MODBUS_SUB_FUNCTION,
	MODBUS_RD_START_ADDR,
	MODBUS_RD_END_ADDR,
	MODBUS_WT_START_ADDR,
	MODBUS_WT_END_ADDR,
	MODBUS_DATA_TYPE,
	MODBUS_TYPE_MAX,
};



//*****************************************************

enum
{
	MODBUS_REQUEST = 0x01,
	MODBUD_RESPONSE,

};


/* Packet Types */
#define TNS_TYPE_CONNECT 1
#define TNS_TYPE_ACCEPT 2
#define TNS_TYPE_ACK 3
#define TNS_TYPE_REFUSE 4
#define TNS_TYPE_REDIRECT 5
#define TNS_TYPE_DATA 6
#define TNS_TYPE_NULL 7
#define TNS_TYPE_ABORT 9
#define TNS_TYPE_RESEND 11
#define TNS_TYPE_MARKER 12
#define TNS_TYPE_ATTENTION 13
#define TNS_TYPE_CONTROL 14
#define TNS_TYPE_MAX 19

#define TRUE 1
#define FALSE 0


#define OFFSET_ERROR -1
#define BoundsError	 2
#define OutLengthError 3


uint8_t * modbus_fast_ensure_contiguous(uint8_t * input, const uint32_t input_len, const uint32_t offset, const uint32_t length);





#define pntoh16(p)  ((uint16_t)                       \
	((uint16_t)*((const uint8_t *)(p)+0) << 8 | \
	(uint16_t)*((const uint8_t *)(p)+1) << 0))


enum MODBUS_STATE
{
	MODBUS_NONE,
	MODBUS_WAIT_HEAD,
	MODBUS_WAIT_DATA,
};

struct modbus_session
{
	int connecting;
	struct evbuffer *parser_buf;
	struct evbuffer *send_buf;
	enum MODBUS_STATE state;
};

struct modbus_session *modbus_session_new()
{
	struct modbus_session *session = SCMalloc(sizeof(struct modbus_session));
	if (session == NULL)
		return NULL;
	memset(session, 0, sizeof(*session));
	session->parser_buf = evbuffer_new();
	session->send_buf = evbuffer_new();
	session->connecting = FALSE;
	session->state = MODBUS_NONE;
	return session;
};

void modbus_session_free(struct modbus_session *session)
{
	evbuffer_free(session->send_buf);
	evbuffer_free(session->parser_buf);
	SCFree(session);
}





static void ModbusExtractUint16(uint16_t *res, uint8_t *input, const uint32_t input_len, const uint32_t offset)
{
	uint8_t *ptr;
	uint16_t *pkt_len_ptr;
	ptr = modbus_fast_ensure_contiguous(input, input_len, offset, sizeof(uint16_t));
	pkt_len_ptr = (uint16_t*)ptr;
	*res = *pkt_len_ptr;
	return;
}


static void ModbusExtractUint8(uint16_t *res, uint8_t *input, const uint32_t input_len, const uint32_t offset)
{

	uint8_t *ptr;
	uint16_t *pkt_len_ptr;
	ptr = modbus_fast_ensure_contiguous(input, input_len, offset, sizeof(uint8_t));
	pkt_len_ptr = (uint16_t*)ptr;
	*res = *pkt_len_ptr;
	return;
}



static void ModbusParseHeader(ModbusHeader  *header, struct evbuffer *evbuf, const uint32_t input_len)
{
	char modbus_head[56] = { 0 };
	evbuffer_copyout(evbuf, modbus_head, sizeof(ModbusHeader));
	uint8_t *input = (uint8_t *)modbus_head;
	uint32_t offset = 0;
	/* Transaction Identifier (2 bytes) */
	ModbusExtractUint16(&(header->transactionId), input, input_len, offset);
	offset += 2;
	/* Protocol Identifier (2 bytes) */
	ModbusExtractUint16(&(header->protocolId), input, input_len, offset);
	offset += 2;
	/* Length (2 bytes) */
	ModbusExtractUint16(&(header->length), input, input_len, offset);
	offset += 2;
	/* Unit Identifier (1 byte) */
	ModbusExtractUint8(&(header->unitId), input, input_len, offset);

	header->length = htons(header->length);

	return;
}



static void ModbusCheckHeader(ModbusHeader *header, uint16_t *check_header)
{
	/* MODBUS protocol is identified by the value 0. */
	if (header->protocolId != MODBUS_PROTOCOL_VER)
	{
		*check_header = -1;
		SCLogError("modbus invalid protocol id\n");
		return;
	}

	/* Check Length field that is a byte count of the following fields */
	if ((header->length < MODBUS_MIN_ADU_LEN) || (header->length > MODBUS_MAX_ADU_LEN))
	{
		*check_header = -1;
		SCLogError("modbus invalid length\n");
		return;
	}
	/* Check Unit Identifier field that is not in invalid range */
	if ((header->unitId > MODBUS_MIN_INVALID_UNIT_ID) && (header->unitId < MODBUS_MAX_INVALID_UNIT_ID))
	{
		*check_header = -1;
		SCLogError("modbus invalid unit identifier\n");
		return;
	}

	*check_header = 1;
	return;
}

static int ModbusCheckRequestLengths(modbus_header_t  *header, uint8_t *input, uint32_t input_len)
{
	uint16_t adu_len = (uint16_t) sizeof(ModbusHeader) + ntohs((uint16_t)header->length) - 1;
	uint16_t modbus_payload_len = adu_len - MODBUS_MIN_LEN;
	uint8_t tmp_count;
	int check_passed = -1;

	if (g_rModbusConfig.bRuleWork)
	{
		if (g_rModbusConfig.chCommnad[header->function_code] == 1)
		{
			return 0;
		}
	}

	switch (header->function_code)
	{
	case MODBUS_FUNC_READCOILS:
	case MODBUS_FUNC_READDISCINPUTS:
	case MODBUS_FUNC_READHOLDREGS:
	case MODBUS_FUNC_READINPUTREGS:
	case MODBUS_FUNC_WRITESINGLECOIL:
	case MODBUS_FUNC_WRITESINGLEREG:
	case MODBUS_FUNC_DIAGNOSTIC:
		if (modbus_payload_len == MODBUS_FOUR_DATA_BYTES)
			check_passed = 1;
		break;

	case MODBUS_FUNC_READEXCSTATUS:
	case MODBUS_FUNC_GETCOMEVTCOUNTER:
	case MODBUS_FUNC_GETCOMEVTLOG:
	case MODBUS_FUNC_REPORTSERVERID:
		if (modbus_payload_len == MODBUS_EMPTY_DATA_LEN)
			check_passed = 1;
		break;

	case MODBUS_FUNC_WRITEMULTCOILS:
	case MODBUS_FUNC_WRITEMULTREGS:
		if (modbus_payload_len >= MODBUS_WRITE_MULTIPLE_MIN_SIZE)
		{
			tmp_count = *(input + MODBUS_MIN_LEN + MODBUS_WRITE_MULTIPLE_BYTE_COUNT_OFFSET);
			if (modbus_payload_len == tmp_count + MODBUS_WRITE_MULTIPLE_MIN_SIZE)
				check_passed = 1;
		}
		break;

	case MODBUS_FUNC_MASKWRITEREG:
		if (modbus_payload_len == MODBUS_MASK_WRITE_REGISTER_SIZE)
			check_passed = 1;
		break;

	case MODBUS_FUNC_READWRITEMULTREGS:
		if (modbus_payload_len >= MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE)
		{
			tmp_count = *(input + MODBUS_MIN_LEN +
				MODBUS_READ_WRITE_MULTIPLE_BYTE_COUNT_OFFSET);
			if (modbus_payload_len == MODBUS_READ_WRITE_MULTIPLE_MIN_SIZE + tmp_count)
				check_passed = 1;
		}
		break;


	case MODBUS_FUNC_READFIFOQUEUE:
		if (modbus_payload_len == MODBUS_READ_FIFO_SIZE)
			check_passed = 1;
		break;

	case MODBUS_FUNC_ENCAPINTTRANS:
		if (modbus_payload_len >= MODBUS_MEI_MIN_SIZE)
		{
			uint8_t mei_type = *(input + MODBUS_MIN_LEN);

			/* MEI Type 0x0E is covered under the Modbus spec as
			"Read Device Identification". Type 0x0D is defined in
			the spec as "CANopen General Reference Request and Response PDU"
			and falls outside the scope of the Modbus preprocessor.

			Other values are reserved.
			*/
			if ((mei_type == MODBUS_SUB_FUNC_READ_DEVICE_ID) && (modbus_payload_len == MODBUS_SUB_FUNC_READ_DEVICE_ID_SIZE))
				check_passed = 1;
		}
		break;


	case MODBUS_FUNC_READFILERECORD:
		/* Modbus read file record request contains a byte count, followed
		by a set of 7-byte sub-requests. */
		if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
		{
			tmp_count = *(input + MODBUS_MIN_LEN);
			if ((tmp_count == modbus_payload_len - MODBUS_BYTE_COUNT_SIZE) && (tmp_count % MODBUS_FILE_RECORD_SUB_REQUEST_SIZE == 0))
			{
				check_passed = 1;
			}
		}
		break;

	case MODBUS_FUNC_WRITEFILERECORD:
		/* Modbus write file record request contains a byte count, followed
		by a set of sub-requests that contain a 7-byte header and a
		variable amount of data. */

		if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
		{
			tmp_count = *(input + MODBUS_MIN_LEN);
			if (tmp_count == modbus_payload_len - MODBUS_BYTE_COUNT_SIZE)
			{
				uint16_t bytes_processed = 0;

				while (bytes_processed < (uint16_t)tmp_count)
				{
					uint16_t record_length = 0;

					/* Check space for sub-request header info */
					if ((modbus_payload_len - bytes_processed) <
						MODBUS_FILE_RECORD_SUB_REQUEST_SIZE)
						break;

					/* Extract record length. */
					record_length = *(input + MODBUS_MIN_LEN +
						MODBUS_BYTE_COUNT_SIZE + bytes_processed +
						MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET);

					record_length = record_length << 8;

					record_length |= *(input + MODBUS_MIN_LEN +
						MODBUS_BYTE_COUNT_SIZE + bytes_processed +
						MODBUS_FILE_RECORD_SUB_REQUEST_LEN_OFFSET + 1);

					/* Jump over record data. */
					bytes_processed += MODBUS_FILE_RECORD_SUB_REQUEST_SIZE +
						2 * record_length;

					if (bytes_processed == (uint16_t)tmp_count)
						check_passed = 1;
				}
			}
		}
		break;

	default: /* Don't alert if we couldn't check the length. */
		check_passed = 1;
		break;
	}

	return check_passed;
}

static int ModbusCheckResponseLengths(modbus_header_t  *header, uint8_t *input, uint32_t input_len)
{
	uint16_t adu_len = (uint16_t) sizeof(ModbusHeader) + ntohs((uint16_t)header->length) - 1;
	uint16_t modbus_payload_len = adu_len - MODBUS_MIN_LEN;
	uint8_t tmp_count;
	int check_passed = -1;

	switch (header->function_code)
	{
	case MODBUS_FUNC_READCOILS:
	case MODBUS_FUNC_READDISCINPUTS:

	case MODBUS_FUNC_GETCOMEVTLOG:
	case MODBUS_FUNC_READWRITEMULTREGS:
		if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
		{
			tmp_count = *(input + MODBUS_MIN_LEN); /* byte count */
			if (modbus_payload_len == MODBUS_BYTE_COUNT_SIZE + tmp_count)
				check_passed = 1;
		}
		break;

	case MODBUS_FUNC_READHOLDREGS:
	case MODBUS_FUNC_READINPUTREGS:
		if (modbus_payload_len >= MODBUS_BYTE_COUNT_SIZE)
		{
			/* count of 2-byte registers*/
			tmp_count = *(input + MODBUS_MIN_LEN);
			if (modbus_payload_len == MODBUS_BYTE_COUNT_SIZE + tmp_count)
				check_passed = 1;
		}
		break;

	case MODBUS_FUNC_WRITESINGLECOIL:
	case MODBUS_FUNC_WRITESINGLEREG:
	case MODBUS_FUNC_DIAGNOSTIC:
	case MODBUS_FUNC_GETCOMEVTCOUNTER:
	case MODBUS_FUNC_WRITEMULTCOILS:
	case MODBUS_FUNC_WRITEMULTREGS:
		if (modbus_payload_len == MODBUS_FOUR_DATA_BYTES)
			check_passed = 1;
		break;

	case MODBUS_FUNC_READEXCSTATUS:
		if (modbus_payload_len == MODBUS_FUNC_READ_EXCEPTION_RESP_SIZE)
			check_passed = 1;
		break;

	case MODBUS_FUNC_MASKWRITEREG:
		if (modbus_payload_len == MODBUS_MASK_WRITE_REGISTER_SIZE)
			check_passed = 1;
		break;

	case MODBUS_FUNC_READFIFOQUEUE:
		if (modbus_payload_len >= MODBUS_DOUBLE_BYTE_COUNT_SIZE)
		{
			uint16_t tmp_count_16;

			/* This function uses a 2-byte byte count!! */
			tmp_count_16 = *(uint16_t *)(input + MODBUS_MIN_LEN);
			tmp_count_16 = ntohs(tmp_count_16);
			if (modbus_payload_len == MODBUS_DOUBLE_BYTE_COUNT_SIZE + tmp_count_16)
				check_passed = 1;
		}
		break;

	case MODBUS_FUNC_ENCAPINTTRANS:
		if (modbus_payload_len >= MODBUS_READ_DEVICE_ID_HEADER_LEN)
		{
			uint8_t mei_type = *(input + MODBUS_MIN_LEN);
			uint8_t num_objects = *(input + MODBUS_MIN_LEN +
				MODBUS_READ_DEVICE_ID_NUM_OBJ_OFFSET);
			uint16_t offset;
			uint8_t i;

			/* MEI Type 0x0E is covered under the Modbus spec as
			"Read Device Identification". Type 0x0D is defined in
			the spec as "CANopen General Reference Request and Response PDU"
			and falls outside the scope of the Modbus preprocessor.

			Other values are reserved.
			*/

			if (mei_type == MODBUS_SUB_FUNC_CANOPEN)
				check_passed = 1;

			if (mei_type != MODBUS_SUB_FUNC_READ_DEVICE_ID)
				break;

			/* Loop through sub-requests, make sure that the lengths inside
			don't violate our total Modbus PDU size. */

			offset = MODBUS_READ_DEVICE_ID_HEADER_LEN;
			for (i = 0; i < num_objects; i++)
			{
				uint8_t sub_request_data_len;

				/* Sub request starts with 2 bytes, type + len */
				if (offset + MODBUS_SUB_FUNC_READ_DEVICE_START_LEN > modbus_payload_len)
					break;

				/* Length is second byte in sub-request */
				sub_request_data_len = *(input + MODBUS_MIN_LEN +
					offset + MODBUS_SUB_FUNC_READ_DEVICE_LENGTH_OFFSET);

				/* Set offset to byte after sub-request */
				offset += (MODBUS_SUB_FUNC_READ_DEVICE_START_LEN + sub_request_data_len);
			}

			if ((i == num_objects) && (offset == modbus_payload_len))
				check_passed = 1;
		}
		break;

		/* Cannot check this response, as it is device specific. */
	case MODBUS_FUNC_REPORTSERVERID:

		/* Cannot check these responses, as their sizes depend on the corresponding
		requests. Can re-visit if we bother with request/response tracking. */
	case MODBUS_FUNC_READFILERECORD:
	case MODBUS_FUNC_WRITEFILERECORD:

	default: /* Don't alert if we couldn't check the lengths. */
		check_passed = 1;
		break;
	}
	return check_passed;
}

int MODBUSVerifyData(ModbusHeader  *header, uint8_t resq, uint8_t *input, uint32_t input_len)
{
	int verify_passed = 0;

	if (input == NULL) 
	{
		SCLogError("NULL pointer. %p\n", input);
		return -1;
	}

	/* Transaction ID(2) + Protocol ID(2) + Length(2) + Slave Address(1) + Function code(1) */
	/* Modbus header is 7 bytes long */
	if (input_len < (uint32_t) sizeof(ModbusHeader)) 
	{
		SCLogError("ALP Modbus data length %d < 7", input_len);
		return -1;
	}

	uint16_t trans_id = header->transactionId;
	uint16_t protocolId = header->protocolId;
	uint8_t  uintid = header->unitId;
	uint8_t  pdu_len = header->length;
	uint32_t adu_len = 0;
	//uint16_t modbus_len  = 0;
	/* Compute ADU length. */
	adu_len = (uint32_t) sizeof(ModbusHeader) + (uint32_t)header->length - 1;
	if (adu_len > input_len)
	{
		return -1;
	}
		

	SCLogInfo("Transaction Identifier:%d, pdu length %d, Unit Identifier:%d", trans_id, pdu_len, uintid);
	//printf("Transaction Identifier:%d, pdu length %d, Unit Identifier:%d",
	//           trans_id, pdu_len, uintid);


	if (resq == MODBUS_REQUEST)
	{
		verify_passed = ModbusCheckRequestLengths((modbus_header_t *)input, input, input_len);
	}
	else if (resq == MODBUD_RESPONSE)
	{
		verify_passed = ModbusCheckResponseLengths((modbus_header_t *)input, input, input_len);
	}

	return verify_passed;
}











void modbus_dumpbin(char *name, const uint8_t *buff, size_t len)
{
	printf("%s(%d):\n", name, (int)len);
	for (int i = 0; i < len; i++)
	{
		printf("%02X ", buff[i]);
		if ((i + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");
}

int modbus_check_offset_length_no_exception(uint8_t * input, uint32_t input_len, const uint32_t offset, const uint32_t length_val, uint32_t * offset_ptr, uint32_t * length_ptr)
{
	uint32_t end_offset;
	if (offset <= input_len)
		*offset_ptr = offset;

	*length_ptr = length_val;
	end_offset = *offset_ptr + *length_ptr;

	if (end_offset <= input_len)
		return 0;
	else
		return BoundsError;
}

int modbus_tvb_bytes_exist(uint8_t * input, const uint32_t input_len, const unsigned int offset, const unsigned int length)
{
	unsigned int abs_offset, abs_length;
	int exception;

	exception = modbus_check_offset_length_no_exception(input, input_len, offset, length, &abs_offset, &abs_length);

	if (exception)
		return FALSE;

	return TRUE;
}

uint8_t * modbus_fast_ensure_contiguous(uint8_t * input, const uint32_t input_len, const uint32_t offset, const uint32_t length)
{
	uint32_t end_offset;
	uint32_t u_offset;

	if (!input)
		return NULL;

	u_offset = offset;
	end_offset = u_offset + length;

	if (end_offset <= input_len)
	{
		return input + u_offset;
	}

	if (end_offset > input_len)
		SCLogInfo("MODBUS: [ %s:%d ] out of bounds\n", __FILE__, __LINE__);

	return NULL;
}

uint8_t modbus_tvb_get_uint8(uint8_t * input, const uint32_t input_len, const uint32_t offset)
{
	const uint8_t * ptr;
	ptr = modbus_fast_ensure_contiguous(input, input_len, offset, sizeof(uint8_t));
	return *ptr;
}

uint16_t modbus_tvb_get_ntohs(uint8_t * input, const uint32_t input_len, const uint32_t offset)
{
	uint8_t *ptr;
	uint16_t *pkt_len_ptr;
	uint16_t pkt_len;
	ptr = modbus_fast_ensure_contiguous(input, input_len, offset, sizeof(uint16_t));
	pkt_len_ptr = (uint16_t*)ptr;
	pkt_len = ntohs(*pkt_len_ptr);
	return pkt_len;
}

enum FLT_RET modbus_ondata(struct filter_header *hdr, enum FLT_EVENT ev, const void *buff, size_t len)
{
	/* FLTEV_ONCLIIN */
	if (ev == FLTEV_ONCLIIN)
	{
		SCLogInfo("MODBUS: on cli in, ssid: %d", hdr->sessionid);
		struct modbus_session *session = modbus_session_new();
		if (session == NULL)
			return FLTRET_CLOSE;
		session->connecting = FALSE;
		hdr->user = session;
		return FLTRET_OK;
	}

	/* FLTEV_ONSVROK */
	else if (ev == FLTEV_ONSVROK)
	{
		struct modbus_session *session = hdr->user;
		session->connecting = TRUE;
		int isok = *((int*)buff); assert(len == sizeof(isok));
		SCLogInfo("MODBUS: connect server ret: %d, ssid: %d", isok, hdr->sessionid);
		if (isok == 0)
			return modbus_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		if (evbuffer_get_length(session->parser_buf) > 0)
			return modbus_ondata(hdr, FLTEV_ONSOCKDATA, NULL, 0);
		return FLTRET_OK;
	}

	/* FLTEV_ONSOCKDATA */
	else if (ev == FLTEV_ONSOCKDATA)
	{
		uint8_t mod_req = MODBUS_REQUEST;
		if (hdr->svr == NULL)
		{
			mod_req = MODBUD_RESPONSE;
		}

		struct modbus_session *session = hdr->user;
		ModbusHeader header;
		memset(&header, 0, sizeof(ModbusHeader));
		uint8_t well_parserd = 0;

		char modbus_head[56] = { 0 }; //the length of modbus head is 7 byte 
		char ip_src[20] = { 0 };
		char ip_dst[20] = { 0 };
		addr2str(hdr->ip->daddr, ip_dst);
		addr2str(hdr->ip->saddr, ip_src);

		SCLogInfo("MODBUS: on cli/svr len: %d, ssid: %d", (int)len, hdr->sessionid);
		//modbus_dumpbin("on cli/svr data", buff, len);


		if (evbuffer_add(session->parser_buf, buff, len) != 0)
		{
			return modbus_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		if (session->connecting == FALSE)
		{
			SCLogInfo("MODBUS: svr not ready, delay.... ssid: %d", hdr->sessionid);
			return FLTRET_OK;
		}

		uint32_t evbuf_len = evbuffer_get_length(session->parser_buf);

		/* Modbus header is 7 bytes long */
		if (evbuf_len < (uint32_t) sizeof(ModbusHeader))
		{
			return FLTRET_OK;
		}

		ModbusParseHeader(&header, session->parser_buf, sizeof(ModbusHeader));
		uint16_t header_pass = FALSE;
		ModbusCheckHeader(&header, &header_pass);
		SCLogInfo("modbus header : transactionId : %02X | protocolId : %02X | length : %02X | unitId : %02X ", header.transactionId, \
			header.protocolId, header.length, header.unitId);

		if (header_pass != TRUE)
		{
			return modbus_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
		evbuf_len = evbuffer_get_length(session->parser_buf);
		uint32_t adu_len = (uint32_t) sizeof(ModbusHeader) + (uint32_t)(header.length) - 1;
		SCLogInfo("evbuf_len: %ld adu_len : %ld  and header.length : %d ", evbuf_len, adu_len, header.length);

		if (evbuf_len < adu_len)
		{
			return FLTRET_OK;
		}
		uint16_t data_verify_pass = FALSE;
		char modbus_packet[15000] = { 0 };
		evbuffer_copyout(session->parser_buf, modbus_packet, adu_len);
		data_verify_pass = MODBUSVerifyData(&header, mod_req, (uint8_t *)modbus_packet, adu_len);
		if (data_verify_pass != TRUE)
		{
			return modbus_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		if (evbuffer_sendtofwd(hdr, session->parser_buf, adu_len) != 0)
		{
			char *err = "evbuffer_sendtofwd failed!!!";
			write_secevent_log(ip_src, ip_dst, hdr->username, "MODBUS", SEC_EVT_LEVEL_CRITICAL, SEC_EVT_TYPE, err, "", PRI_HIGH, 0);
			return modbus_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}

		hdr->timeout = 30 * 60;//30min
		return FLTRET_OK;

	}

	/* FLTEV_ONFWDDATA */
	else if (ev == FLTEV_ONFWDDATA)
	{
		const ForwardObject *obj = buff; assert(len == sizeof(obj));
		char ip_src[20] = { 0 };
		char ip_dst[20] = { 0 };
		addr2str(hdr->ip->daddr, ip_dst);
		addr2str(hdr->ip->saddr, ip_src);

		SCLogInfo("MODBUS: on fwd len:%d, ssid=%d", (int)obj->buffdata.len, hdr->sessionid);
		//modbus_dumpbin("on fwd data", obj->buffdata.data, obj->buffdata.len);
		assert(obj->has_buffdata);
		int ret = buffer_sendtoreq(hdr, obj->buffdata.data, obj->buffdata.len);
		if (ret != 0)
		{
			char *err = "buffer_sendtoreq failure";
			write_secevent_log(ip_src, ip_dst, hdr->username, "MODBUS", SEC_EVT_LEVEL_CRITICAL, SEC_EVT_TYPE, err, "", PRI_HIGH, 0);
			return modbus_ondata(hdr, FLTEV_ONSOCKERROR, buff, len);
		}
		return FLTRET_OK;
	}

	/* FTLEV_ONSOCKERROR */
	else if (ev == FLTEV_ONSOCKERROR)
	{
		struct modbus_session *session = hdr->user;
		SCLogInfo("MODBUS: on socket close, ssid: %d", hdr->sessionid);
		modbus_session_free(session);
		hdr->user = NULL;
		return FLTRET_CLOSE;
	}
	else
	{
	}
	return FLTRET_OK;
}

int modbus_oninit()
{
	memset(&g_rModbusConfig, 0, sizeof(g_rModbusConfig));
	strcpy(g_rModbusConfig.chModbusJsonStr, g_pModbusDefaultJsonStr);

	return 0;
}

int modbus_onfree()
{
	return 0;
}

static struct packet_filter g_filter_modbus = { SVR_ID_MODBUS, "modbus parser", modbus_oninit, modbus_ondata, modbus_onfree };

PROTOCOL_FILTER_OP(modbus)

static struct cmd_node modbus_node =
{
	.node = MODBUS_NODE,
	.prompt = "",
	.vtysh = 1
};

char* modbus_getConfig(void)
{
	if (g_rModbusConfig.chModbusJsonStr[0] != 0x00)
	{
		return g_rModbusConfig.chModbusJsonStr;
	}

	return g_pModbusDefaultJsonStr;
}

static int modbus_config_write(struct vty *vty)
{
	vty_out(vty, "modbus set %s%s", modbus_getConfig(), VTY_NEWLINE);
	return CMD_SUCCESS;
}

/************************************************************
*Function    : gap_ctl_show_modbus
*Action      : display modbus config info
*Input       : null
*Output      : null
*Return      : CMD_SUCCESS
*Author      : 
*Date        : 2019.2.18
*Instruction : null
************************************************************/
DEFUN(gap_ctl_show_modbus,
	gap_ctl_show_modbus_cmd,
	"show modbus",
	SHOW_STR
	"modbus\n")
{
	vty_out(vty, "%s%s", modbus_getConfig(), VTY_NEWLINE);
	return CMD_SUCCESS;
}

/************************************************************
*Function    : gap_ctl_set_modbus_json
*Action      : set modbus config
*Input       : null
*Output      : null
*Return      : CMD_SUCCESS
			   CMD_ERR_NOTHING_TODO
*Author      :
*Date        : 2019.2.18
*Instruction : null
************************************************************/
DEFUN(gap_ctl_set_modbus_json,
	gap_ctl_set_modbus_json_cmd,
	"modbus set .JSON",
	"modbus command\n"
	"set modbus rule.\n"
	"Json format string\n")
{
	if (RUN_AS_INNER() && vty->usr_data)
	{
		if (vty_adapter_run(vty, ((struct vty_adapter*)vty->usr_data)) < 0)
		{
			SCLogError("[%s:%d]connect outer fail.", __FILE__, __LINE__);
			return CMD_ERR_NOTHING_TODO;
		}
	}
		
	char* pModbusJsonStr = argv_concat(argv, argc, 0);
	if (pModbusJsonStr == NULL)
	{
		SCLogError("[%s:%d]argv_concat erro", __FILE__, __LINE__);
		vty_out(vty, "argv_concat error%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	cJSON* pRoot = cJSON_Parse(pModbusJsonStr);
	if (pRoot == NULL)
	{
		SCLogError("[%s:%d]cJSON_Parse erro", __FILE__, __LINE__);
		vty_out(vty, "cJSON_Parse error%s", VTY_NEWLINE);
		XFREE(MTYPE_TMP, pModbusJsonStr);
		return CMD_SUCCESS;
	}

	memset(&g_rModbusConfig, 0, sizeof(g_rModbusConfig));
	strcpy(g_rModbusConfig.chModbusJsonStr, pModbusJsonStr);

	cJSON* pJsonRuleWork = cJSON_GetObjectItem(pRoot, "rule_work");
	if (pJsonRuleWork != NULL)
	{
		g_rModbusConfig.bRuleWork = Abs(pJsonRuleWork->valueint);
	}

	cJSON* pJsonReadOnly = cJSON_GetObjectItem(pRoot, "readonly");
	if (pJsonReadOnly != NULL)
	{
		g_rModbusConfig.bReadOnly = Abs(pJsonReadOnly->valueint);
	}

	cJSON* pJsonCommandArry = cJSON_GetObjectItem(pRoot, "black_cmd");
	if (pJsonCommandArry != NULL)
	{
		int i = 0;
		int nCommand = 0;
		int nArraySize = cJSON_GetArraySize(pJsonCommandArry);

		cJSON* pConfigItem = NULL;

		for (i = 0; i < nArraySize; i++)
		{
			pConfigItem = cJSON_GetArrayItem(pJsonCommandArry, i);
			if (NULL == pConfigItem)
			{ 
				continue; 
			}

			nCommand = Abs(pConfigItem->valueint);
			g_rModbusConfig.chCommnad[nCommand] = 1;
		}
	}

	if (g_rModbusConfig.bReadOnly)
	{
		//8	回送诊断校验			把诊断校验报文送从机，以对通信处理进行评鉴
		g_rModbusConfig.chCommnad[8] = 1;

		//9编程（484用）			使主机模拟编程器作用，修改PC从机逻辑
		g_rModbusConfig.chCommnad[9] = 1;

		//13编程（184 / 384 / 484 / 584）	可使主机模拟编程器功能修改PC从机逻辑
		g_rModbusConfig.chCommnad[13] = 1;

		//18（884和MICRO 84）		可使主机模拟编程功能，修改PC状态逻辑
		g_rModbusConfig.chCommnad[18] = 1;

		//19重置通信链路			发生非可修改错误后，是从机复位于已知状态，可重置顺序字节
		g_rModbusConfig.chCommnad[19] = 1;
	}

	cJSON_Delete(pRoot);
	XFREE(MTYPE_TMP, pModbusJsonStr);

	SCLogInfo("[%s:%d]add modbus config success.", __FILE__, __LINE__);

	return CMD_SUCCESS;
}

void modbus_conf_cmd_init(void)
{	
	install_element(VIEW_NODE, &gap_ctl_show_modbus_cmd);
	install_element(ENABLE_NODE, &gap_ctl_show_modbus_cmd);

	install_element(CONFIG_NODE, &gap_ctl_set_modbus_json_cmd);

	install_node(&modbus_node, modbus_config_write);
}
