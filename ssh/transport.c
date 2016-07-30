/*
 * transport.c
 *
 *  Created on: 8/07/2015
 *      Author: Cristian
 *
 *      RFC4253 - SSH Transport Layer Protocol implementation
 */

#include <stdio.h>
#include <string.h>

/* XDCtools Header files */
#include <xdc/std.h>
#include <xdc/runtime/Memory.h>
#include <xdc/runtime/System.h>
#include <xdc/runtime/Error.h>
#include <xdc/cfg/global.h>

/* NDK BSD support */
#include <sys/socket.h>

#include "sshd.h"
#include "kex.h"
#include "transport.h"
#include "auth.h"
#include "channel.h"
#include "console.h"

#define SSH_PROT_VERSION 		"SSH-2.0-TIVA"
#define AUTH_SERVICE        	"ssh-userauth"

/* Main functions */
static int servicerequest_hd(SSH *);
static int parse_service(SSH *);
static int build_service_response(SSH *);
static int transportVerifyMAC(SSH *);
static int transportBuildMAC(SSH *);
static int build_ver_response(SSH *);
static int parse_ver(SSH *);

/**
 * @brief Init sha and dh keys
 */
int transportInit(SSH *ssh) {

	if (InitSha(&ssh->sha) != 0)
		return -1;

	InitDhKey(&ssh->dh);

	return 0;
}

/**
 * @brief Section 4.2 - Protocol version exchange
 */
int transportVersion_hd(SSH *ssh) {
	int ret = 0;

	ret = build_ver_response(ssh);
	if (ret < 0) {
		return -1;
	}

	ret = transportWritePacket(ssh);
	if (ret < 0) {
		return -1;
	}

	ret = transportReadPacket(ssh, TCPPACKETSIZE);
	if (ret < 0) {
		return -1;
	}

	ret = parse_ver(ssh);

	return ret;
}

/**
 * @brief Service request handler
 */
static int servicerequest_hd(SSH *ssh) {

	/* Parse service */
	if (parse_service(ssh) < 0) {
		return -1;
	}

	/* Build response packet */
	build_service_response(ssh);

	/* Send reply to client */
	if (transportWritePacket(ssh) < 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Read packet from socket
 */
int transportReadPacket(SSH *ssh, word32 len) {

	if (len > TCPPACKETSIZE) {
		return -1;
	}

	ssh->Length = recv(ssh->rfd, ssh->PacketBuffer, len, 0);

	if (ssh->Length <= 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Write packet to socket
 */
int transportWritePacket(SSH *ssh) {
	byte *tmp;
	byte *p;
	Error_Block eb;

	ssh->out_sequence++;

	/* Maximum TCPPACKETSIZE bytes */
	if (ssh->Length > TCPPACKETSIZE) {
		return -1;
	}

	if (ssh->flEnc) {
		/* Allocate memory */
		Error_init(&eb);
		tmp = (byte *) Memory_alloc(NULL, TCPPACKETSIZE, 0, &eb);
		if (!tmp) {
			return -1;
		}

		p = ssh->PacketBuffer;

		/* Encrypt the packet */
		AesCbcEncrypt(&ssh->enc, tmp, p, ssh->Length);

		/* Build mac and update packet length */
		transportBuildMAC(ssh);

		/* Copy encrypted packet to output buffer */
		memcpy(p, tmp, ssh->Length - SHA_DIGEST_SIZE);

		if (tmp)
			Memory_free(NULL, tmp, TCPPACKETSIZE);
	}

	if (send(ssh->wfd, ssh->PacketBuffer, ssh->Length, 0) < 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Read plain/encrypt packet from client
 */
int transportGetPacket(SSH *ssh) {
	byte *p;
	ssh_packet* sp;
	byte *tmp;
	int remain;
	Error_Block eb;

	sp = &ssh->sp;
	p = ssh->PacketBuffer;

	if (ssh->flEnc) {
		/* We encrypt 16 bytes at a time */
		ssh->Length = recv(ssh->rfd, ssh->PacketBuffer, AES_BLOCK_SIZE, 0);
	} else {
		/* Plain text, read packet length and padding field */
		ssh->Length = recv(ssh->rfd, ssh->PacketBuffer, sizeof(word32) + sizeof(byte), 0);
	}

	/* Read valid? */
	if (ssh->Length <= 0) {
		return -1;
	}

	/* Decrypt */
	if (ssh->flEnc) {
		/* Allocate memory */
		Error_init(&eb);
		tmp = (byte *) Memory_alloc(NULL, TCPPACKETSIZE, 0, &eb);
		if (!tmp) {
			return -1;
		}

		/* Decrypt packet length */
		AesCbcDecrypt(&ssh->dec, tmp, p, AES_BLOCK_SIZE);

		/* Extract ssh fields */
		sp->packet_length = (word32) ntohl(*(word32* )tmp);
		sp->padding_length = *(word32*) (tmp + sizeof(word32));

		/* Bad packet */
		if (sp->packet_length
				> TCPPACKETSIZE - sizeof(word32) - SHA_DIGEST_SIZE) {
			Memory_free(NULL, tmp, TCPPACKETSIZE);
			return -1;
		}

		/* How much remain to read, including mac */
		remain = sp->packet_length + sizeof(word32) + SHA_DIGEST_SIZE
				- AES_BLOCK_SIZE;
		//System_printf("RxE:%d\n", ssh->Length);

		while(remain > 0) {
			ssh->Length += recv(ssh->rfd, p + ssh->Length, remain, 0);
			remain = sp->packet_length + sizeof(word32) + SHA_DIGEST_SIZE - ssh->Length;
			//System_printf("RxE:%d\n", ssh->Length);
		}

		/* Decrypt the data without the mac and the firts block */
		AesCbcDecrypt(&ssh->dec, tmp + AES_BLOCK_SIZE, p + AES_BLOCK_SIZE,
				ssh->Length - SHA_DIGEST_SIZE - AES_BLOCK_SIZE);

		/* Mac is not encrypted. we copy it to packet */
		memcpy(tmp + sp->packet_length + sizeof(word32),
				p + sp->packet_length + sizeof(word32), SHA_DIGEST_SIZE);
		memcpy(p, tmp, sp->packet_length + sizeof(word32) + SHA_DIGEST_SIZE);

		Memory_free(NULL, tmp, TCPPACKETSIZE);
	} else {
		/* Plain packet */
		sp->packet_length = (word32) ntohl(*(word32* )p);
		sp->padding_length = *(word32*) (p + sizeof(word32));

		/* Bad packet */
		if (sp->packet_length
				> TCPPACKETSIZE - sizeof(word32)) {
			return -1;
		}

		/* How much remain to read */
		remain = sp->packet_length + sizeof(word32) - ssh->Length;
		//System_printf("RxP:%d\n", ssh->Length);

		while(remain) {
			ssh->Length += recv(ssh->rfd, p + ssh->Length, remain, 0);
			remain = sp->packet_length + sizeof(word32) - ssh->Length;
			//System_printf("RxP:%d\n", ssh->Length);
		}
	}

	return 0;
}

/**
 * @brief Extract SSH fields from plain packet
 */
int transportExtract(SSH *ssh) {
	byte *p;
	ssh_packet* sp;

	sp = &ssh->sp;
	p = ssh->PacketBuffer;

	memset(sp, 0, sizeof(ssh_packet));

	/* Section 6.0 SSH packet */
	sp->packet_length = (word32) ntohl(*(word32* )p);
	sp->padding_length = *(word32*) (p + sizeof(word32));
	sp->payload = (byte*) p + sizeof(byte) + sizeof(word32);
	sp->payload_length = sp->packet_length - sp->padding_length - 1;
	sp->data = sp->payload + sizeof(byte); // random padding
	sp->padding = sp->payload + sp->packet_length - sp->padding_length
			- sizeof(byte);
	sp->mac = sp->padding + sp->padding_length;
	sp->type = ((char*) sp->payload)[0];

	return 0;
}

/**
 * @brief Identifies the service and dispatches data to their
 * handler
 */
int transportProcessPacket(SSH *ssh) {

	ssh->in_sequence++;

	if (ssh->flEnc) {
		/* Verify data integrity */
		if (transportVerifyMAC(ssh) < 0) {
			return -1;
		}
	}

	switch (ssh->sp.type) {

		case SSH_MSG_CHANNEL_CLOSE:
		/* Transport layer protocol */
		case SSH_MSG_DISCONNECT:
		case SSH_MSG_UNIMPLEMENTED:
			return 1;

		case SSH_MSG_IGNORE:
		case SSH_MSG_DEBUG:
		case SSH_MSG_CHANNEL_EOF:
		case SSH_MSG_CHANNEL_WINDOW_ADJUST:
			return 0;

		case SSH_MSG_SERVICE_REQUEST:
			if (servicerequest_hd(ssh) < 0)
				return -1;
			break;

		case SSH_MSG_KEXINIT:
			if (kexinit_hd(ssh) < 0)
				return -1;
			break;

		case SSH_MSG_NEWKEYS:
			if (kexnewk_hd(ssh) < 0)
				return -1;
			break;

		case SSH_MSG_KEXDH_INIT:
			if (kexdh_hd(ssh) < 0)
				return -1;
			break;

			/* User authentication protocol */
		case SSH_MSG_USERAUTH_REQUEST:
			if (auth_hd(ssh) < 0)
				return -1;
			break;

			/* Connection protocol */
		case SSH_MSG_CHANNEL_OPEN:
			if (chopen_hd(ssh) < 0)
				return -1;
			break;

		case SSH_MSG_CHANNEL_DATA:
			if (console_hd(ssh) < 0)
				return -1;
			break;

		case SSH_MSG_CHANNEL_REQUEST:
			if (chrequest_hd(ssh) < 0)
				return -1;
			break;

		default:
			return -1;
	}
	return 0;
}

/**
 * @brief Build version exchange reply
 */
static int build_ver_response(SSH *ssh) {
	byte *p;

	p = ssh->PacketBuffer;

	/* Escribimos nuestra versión */
	memset(p, 0, TCPPACKETSIZE);
	ssh->Length = (int) sprintf((char *) p, "%s\r\n", SSH_PROT_VERSION);

	return 0;
}

/**
 * @brief Parse SSH client version
 */
static int parse_ver(SSH *ssh) {
	byte *p;
	word32 pSz;
	word32 verSz = 0;
	Sha* sha;

	p = ssh->PacketBuffer;
	sha = &ssh->sha;

	/* Extract client version */
	pSz = MAX_VERSION;
	while (pSz--) {
		if (*p == '\n' || (*p == '\r' && *(p + 1) == '\n')) {
			break;
		}
		p++;
	}

	verSz = p - ssh->PacketBuffer;
	if (verSz < MIN_VERSION || verSz >= MAX_VERSION) {
		return -1;
	}
	p = ssh->PacketBuffer;

	/* Verify protocol version */
	if (memcmp("SSH-2.0", p, sizeof("SSH-2.0") != 0)) {
		return -1;
	}

	memcpy(ssh->V_C, p, verSz);
	ssh->V_C[verSz] = 0;
	
	ssh->in_sequence = -1;
	ssh->out_sequence = -1;

	/* Additional data? we notified */
	if (ssh->Length > MAX_VERSION) {
		if (*(p + verSz) == '\r') {
			verSz++;
		}
		verSz++;
		ssh->Length -= verSz;
		memmove(p, p + verSz, ssh->Length);
		return 1;
	}
	return 0;
}

/**
 * @brief Parse auth service
 */
static int parse_service(SSH *ssh) {
	word32 netSz;

	netSz = (word32) ntohl(*(word32* ) ssh->sp.data);
	if (memcmp(ssh->sp.data + sizeof(word32), AUTH_SERVICE, netSz) != 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Build auth service reply
 */
static int build_service_response(SSH *ssh) {
	byte *p;

	/* Preparamos el buffer de salida */
	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	/* Construimos el paquete */
	packet_begin(&p, SSH_MSG_SERVICE_ACCEPT); /* Tipo de mensaje */
	packet_add_uint32(&p, strlen(AUTH_SERVICE)); /* Longitud respuesta */
	packet_add_bin(&p, AUTH_SERVICE, strlen(AUTH_SERVICE));

	ssh->Length = (p - ssh->PacketBuffer); /* longitud de la trama sin el padding aún */

	packet_finalize(ssh); /* agregamos el padding */

	return 0;
}

/**
 * @brief Verify packet integrity
 */
static int transportVerifyMAC(SSH *ssh) {
	//Hmac hmac;
	word32 netSz;
	byte tmp[4];   // for network k size
	byte hmacDigest[SHA_DIGEST_SIZE];

	netSz = htonl(ssh->in_sequence);
	memcpy(tmp, &netSz, sizeof(tmp));

	//HmacSetKey(&hmac, SHA, ssh->keyE, sizeof(ssh->keyE));
	HmacUpdate(&ssh->hmacV, tmp, sizeof(tmp));
	HmacUpdate(&ssh->hmacV, ssh->PacketBuffer,
			ssh->sp.packet_length + sizeof(word32));
	HmacFinal(&ssh->hmacV, hmacDigest);

	if (memcmp(ssh->sp.mac, hmacDigest, SHA_DIGEST_SIZE) != 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Build mac
 */
static int transportBuildMAC(SSH *ssh) {
	//Hmac hmac;
	word32 netSz;
	byte tmp[4];   // for network k size
	byte hmacDigest[SHA_DIGEST_SIZE];

	netSz = htonl(ssh->out_sequence);
	memcpy(tmp, &netSz, sizeof(tmp));

	//HmacSetKey(&hmac, SHA, ssh->keyF, sizeof(ssh->keyF));
	HmacUpdate(&ssh->hmacB, tmp, sizeof(tmp));
	HmacUpdate(&ssh->hmacB, ssh->PacketBuffer, ssh->Length);
	HmacFinal(&ssh->hmacB, hmacDigest);

	memcpy(ssh->PacketBuffer + ssh->Length, hmacDigest, SHA_DIGEST_SIZE);
	ssh->Length += SHA_DIGEST_SIZE;

	return 0;
}

/**
 * @brief Read binary field from ssh packet
 */
void read_bin(byte **p, byte **out, word32 *size) {

	*size = htonl(*(word32 * )*p);
	*p += sizeof(word32);
	*out = *p;
	*p += *size;
}

/**
 * @brief Read byte field from ssh packet
 */
void read_byte(byte **p, byte *b) {

	*b = *(*p);
	*p += 1;
}

/**
 * @brief Read word32 field from ssh packet
 */
void read_uint32(byte **p, word32 *w) {

	*w = htonl(*(word32 * )*p);
	*p += 4;
}

/**
 * @brief Reserve space for packet length and padding fields.
 * Adds the type message being build.
 */
void packet_begin(byte **p, byte i) {

	*p = *p + sizeof(word32) + sizeof(byte);
	packet_add_byte(p, i); /* type message */
}

/**
 * @brief Add byte to frame
 */
void packet_add_byte(byte **p, byte i) {
	*(*p)++ = i;
}

/**
 * @brief Add word32 to frame
 */
void packet_add_uint32(byte **p, word32 i) {
	word32 *up;

	up = (word32 *) (*p);
	*up = htonl(i);
	*p += 4;
}

/**
 * @brief Add binary to frame
 */
void packet_add_bin(byte **d, byte*s, word32 i) {
	memcpy(*d, s, i);
	*d += i;
}

/**
 * @brief Add name-list field to frame
 */
void packet_add_name_list(byte **p, byte *nl) {

	packet_add_uint32(p, strlen((char *) nl));
	memcpy(*p, nl, strlen((char *) nl));
	*p += strlen((char *) nl);
}

/**
 * @brief Add packet length and padding fields.
 * Encrypt if necessary
 */
int packet_finalize(SSH *ssh) {
	byte *p;
	int *pSz;
	word32 packet_length;
	byte padding_length;
	RNG rng;
	byte block[MAX_PADDING];
	int blockSz;

	p = ssh->PacketBuffer;
	pSz = &ssh->Length;

	/* All packets should be multiple of 8 or cipher block size */
	if (ssh->flEnc) {
		blockSz = getCipherBlockSize(ssh);
		if (blockSz < 0) {
			return -1;
		}
	} else {
		blockSz = 8;
	}
	padding_length = blockSz - *pSz % blockSz;
	if (padding_length < 4) {
		padding_length += blockSz;
	}

	packet_length = *pSz - sizeof(word32) + padding_length;
	packet_add_uint32(&p, packet_length); /* Add packet length */
	*p = padding_length; /* Add padding length */
	p = ssh->PacketBuffer; /* Restore ptr */

	if (InitRng(&rng) != 0) {
		return -1;
	}
	if (RNG_GenerateBlock(&rng, block, padding_length) != 0) {
		return -1;
	}
	memcpy(p + *pSz, block, padding_length); /* Add padding */
	*pSz += padding_length; /* Update length */
	return 0;
}
