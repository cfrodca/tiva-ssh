/*
 * sshd.h
 *
 *  Created on: 7/07/2015
 *      Author: Cristian
 */

#ifndef SSHD_H_
#define SSHD_H_

/* CyaSSL */
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/aes.h>
#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/dh.h>
#include <cyassl/ctaocrypt/dsa.h>


#define TCPPACKETSIZE 	2048		/* Length for read/write sockets operations */

/* Constantes varias */
typedef enum {
	MAX_VERSION		= 128,
	MIN_VERSION		= 7,
	MAX_MAC      	= 20,
	COOKIE_SIZE		= 16,
	MAX_PADDING 	= 255,
	MIN_PADDING 	= 8,
	SIGN_SIZE		= 40
} Misc;

typedef enum {
	DH_GROUP_IND 	= 0,
	HOST_KEY_IND,
	ENC_C2S_IND,
	ENC_S2C_IND,
	MAC_C2S_IND,
	MAC_S2C_IND,
	COM_C2S_IND,
	COM_S2C_IND,
	LAN_C2S_IND,
	LAN_S2C_IND,

	TOTAL_NAMELIST
} Namelist;

typedef struct {
    word32 payload_length;
    word32 packet_length;
    byte padding_length;
    byte type;				/* message type */
    byte *payload; 			/* points to start of payload in the blob */
    byte *data; 			/* points to start of data (payload + 1)  */
    byte *padding; 			/* points to start of padding in the blob */
    byte *mac;     			/* points to the start of MAC in the blob */
} ssh_packet;

typedef struct {
	byte actSe;				/* Total active sessions */
	DsaKey peerKey;			/* DSA host keys */
} SSH_CTX;

#define MAX_UN_LEN			16
#define MAX_PW_LEN			16

typedef enum {
	SSH_NONE = 0,
	SSH_AUTH,
	SSH_CHOPEN,
	SSH_PTY,
	SSH_SHELL,
} SSH_req;

typedef struct {
	SSH_CTX* ctx;
	char in_addr[16];		/* Client IP address */
	char authAtt;			/* Auth tries */

	char* namelist[TOTAL_NAMELIST];

	byte *PacketBuffer; 	/* Buffer read/write sockets */
	int Length; 			/* Number of bytes read/write */
	ssh_packet sp;			/* SSH fields */

	DhKey dh;				/* DH selected */
	byte K[257];			/* Shared secret */
	byte f[257];			/* f = g^y mod p */
	word32 KSz;				/* Size KSz */
	word32 fSz;				/* Size f */

	Aes enc;
	Aes dec;
	Hmac hmacV;
	Hmac hmacB;

	byte flEnc;				/* Flag is this session encrypted */
	int in_sequence;  		/* The mac sequence for the incoming stream */	// YA
	int out_sequence;

	Sha	sha;				/* Sha H = V_C || V_S || I_C || I_S || K_S || e || f || K */ //	YA
	byte H[SHA_DIGEST_SIZE];/* Hash exchange */
	byte session[SHA_DIGEST_SIZE]; /* Session id */
	byte sign[SIGN_SIZE];	/* Signature */

	int rfd;				/* read file descriptor */
	int wfd;				/* write descriptor */

	byte user[MAX_UN_LEN + 1];
	byte pass[MAX_UN_LEN + 1];

	SSH_req state;			/* protocol status */
	word32 rec_num;			/* special number for channels */
	word32 in_win_sz;		/* window in size */
	word32 out_win_sz;		/* window out size */
	word32 packet_sz;		/* maximum packet */
	word32 local_num;
	byte wantReply;
} SSH;

#include "transport.h"

SSH* SSH_new(SSH_CTX*);
void SSH_free(SSH*);
SSH_CTX* SSH_CTX_new(void);
void SSH_CTX_free(SSH_CTX*);
int SSH_get_fd(const SSH*);
void SSH_set_fd(SSH*, int);
int SSH_CTX_load_keys(SSH_CTX*);

#endif /* SSHD_H_ */
