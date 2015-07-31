/*
 * auth.c
 *
 *  Created on: 24/07/2015
 *      Author: Cristian
 */

#include <stdio.h>
#include <string.h>

/* XDCtools Header files */
#include <xdc/std.h>
#include <xdc/runtime/Memory.h>
#include <xdc/runtime/System.h>
#include <xdc/runtime/Error.h>
#include <xdc/cfg/global.h>

#include <ti/ndk/inc/netmain.h>
#include <ti/ndk/inc/_stack.h>

#include "sshd.h"
#include "auth.h"
#include "console.h"

#define PASSWORD_STR		"password"

static int parse_auth(SSH *);
static int build_authsucc_response(SSH *);
static int build_authfail_response(SSH *);

/**
 * @brief Auth handler
 */
int auth_hd(SSH *ssh) {
	int ret;

	/* Parse auth */
	ret = parse_auth(ssh);
	if(ret < 0) {
		return -1;
	}

	/* Build success or fail reply */
	if (ret == 1) {
		build_authfail_response(ssh);
	} else {
		build_authsucc_response(ssh);
	}

	/* Send reply to client */
	if (transportWritePacket(ssh) < 0) {
		return -1;
	}

	return 0;
}

/**
 * Parse username and password
 */
static int parse_auth(SSH *ssh) {
	byte *p;
	byte *out;
	byte aux;
	word32 outSz;

	p = ssh->sp.data;

	/* Get username */
	read_bin(&p, &out, &outSz);

	/* Size valid? */
	if (outSz > MAX_UN_LEN)
		return -1;

	memcpy(ssh->user, out, outSz);
	ssh->user[outSz] = 0;

	/* Get service */
	read_bin(&p, &out, &outSz);

	/* Get method */
	read_bin(&p, &out, &outSz);

	/* Only support password based autentication */
	if (memcmp(out, PASSWORD_STR, strlen(PASSWORD_STR)) != 0) {
		return 1;
	}

	/* Read byte */
	read_byte(&p, &aux);

	/* Get password */
	read_bin(&p, &out, &outSz);

	/* Size valid? */
	if (outSz > MAX_PW_LEN)
		return -1;

	memcpy(ssh->pass, out, outSz);
	ssh->pass[outSz] = 0;

	/* Check username and password */
	if (check_password(ssh->user, ssh->pass) < 0) {
		/* Limit auth attempts */
		if (ssh->authAtt++ > 1) {
			return -1;
		}
		return 1;
	}

	ssh->state = SSH_AUTH;

	return 0;
}

/**
 * @brief Build auth success reply
 */
static int build_authsucc_response(SSH *ssh) {
	byte *p;

	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_USERAUTH_SUCCESS);

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	return 0;
}


/**
 * @brief Build auth fail reply
 */
static int build_authfail_response(SSH *ssh) {
	byte *p;

	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_USERAUTH_FAILURE);			/* Type message */
	packet_add_name_list(&p, PASSWORD_STR);				/* String password */
	packet_add_byte(&p, 0);								/* False */

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	return 0;
}
