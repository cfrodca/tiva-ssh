/*
 * transport.h
 *
 *  Created on: 15/07/2015
 *      Author: Cristian
 */

#ifndef SERVERS_SSH_TRANSPORT_H_
#define SERVERS_SSH_TRANSPORT_H_

typedef enum {
	/* Transport layer protocol */
	SSH_MSG_DISCONNECT    				= 1,
	SSH_MSG_IGNORE        				= 2,
	SSH_MSG_UNIMPLEMENTED 				= 3,
	SSH_MSG_DEBUG         				= 4,
	SSH_MSG_SERVICE_REQUEST 			= 5,
	SSH_MSG_SERVICE_ACCEPT  			= 6,
	SSH_MSG_KEXINIT       				= 20,
	SSH_MSG_NEWKEYS       				= 21,
	SSH_MSG_KEXDH_INIT    				= 30,
	SSH_MSG_KEXDH_REPLY   				= 31,

	/* User authentication protocol */
	SSH_MSG_USERAUTH_REQUEST 			= 50,
	SSH_MSG_USERAUTH_FAILURE 			= 51,
	SSH_MSG_USERAUTH_SUCCESS 			= 52,

	/* Connection protocol */
	SSH_MSG_CHANNEL_OPEN				= 90,
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION 	= 91,
	SSH_MSG_CHANNEL_OPEN_FAILURE      	= 92,
	SSH_MSG_CHANNEL_WINDOW_ADJUST     	= 93,
	SSH_MSG_CHANNEL_DATA              	= 94,
	SSH_MSG_CHANNEL_EOF               	= 96,
	SSH_MSG_CHANNEL_CLOSE             	= 97,
	SSH_MSG_CHANNEL_REQUEST           	= 98,
	SSH_MSG_CHANNEL_SUCCESS           	= 99,
	SSH_MSG_CHANNEL_FAILURE           	= 100,
} SSHMsgNumbers;

typedef enum {
	SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
	SSH_OPEN_CONNECT_FAILED              = 2,
	SSH_OPEN_UNKNOWN_CHANNEL_TYPE        = 3,
	SSH_OPEN_RESOURCE_SHORTAGE           = 4,
} SSHReasonCode;

typedef enum {
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT    =  1,
    SSH_DISCONNECT_PROTOCOL_ERROR                 =  2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED            =  3,
    SSH_DISCONNECT_RESERVED                       =  4,
    SSH_DISCONNECT_MAC_ERROR                      =  5,
    SSH_DISCONNECT_COMPRESSION_ERROR              =  6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE          =  7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED =  8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE        =  9,
    SSH_DISCONNECT_CONNECTION_LOST                = 10,
    SSH_DISCONNECT_BY_APPLICATION                 = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS           = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER         = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME              = 15
} DisconnectNumbers;

/* Main functions */
int transportInit(SSH *);
int transportReadPacket(SSH *, word32);
int transportWritePacket(SSH *);
int transportVersion_hd(SSH *);
int transportProcessPacket(SSH *);
int transportGetPacket(SSH *);
int transportExtract(SSH *);

/* Build reply */
void packet_begin(byte **, byte);
void packet_add_byte(byte **, byte);
int packet_add_random(byte **, byte);
void packet_add_uint32(byte **, word32);
void packet_add_bin(byte **, byte *, word32);
void packet_add_name_list(byte **, byte *);
int packet_finalize(SSH *);

/* Read packets */
void read_bin(byte **, byte **, word32 *);
void read_byte(byte **, byte *);
void read_uint32(byte **, word32 *);

#endif /* SERVERS_SSH_TRANSPORT_H_ */
