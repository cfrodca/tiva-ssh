/*
 * console.c
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

/* NDK BSD support */
#include <sys/socket.h>

#include "sshd.h"
#include "console.h"

#define LASTLOGIN_STR		"Last login: "	// Tue Mar 20 23:00:01 2007 from XXX.XXX.XXX.XXX
#define WELCOME_STR			"Welcome to TirtosSSH!!!\r\n\r\n\t* To display a list of commands type ?\r\n"
#define PROMPT_STR			"@tirtos$ "		// Antes del @ se adiciona el usuario que está conectado

#define USERNAME			"admin"
#define PASSWORD			"admin"

static int parse_echo(SSH *);

static int execute_echo(SSH *);

static byte buf[200];
static byte idx = 0;

/**
 * @brief Build welcome message
 */
int build_welcome_msg_response(SSH *ssh) {
	byte *p;

	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_CHANNEL_DATA);
	packet_add_uint32(&p, ssh->rec_num);

	sprintf((char *)(p + 4), "%s from %s\r\n\r\n\t%s\r\n%s%s", /* Build and add message */
			LASTLOGIN_STR,
			ssh->in_addr,
			WELCOME_STR,
			USERNAME,
			PROMPT_STR);

	packet_add_uint32(&p, strlen((char *)(p + 4)));
	p += strlen((char *)p);

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	return 0;
}

/**
 * @brief Verify username and password
 */
int check_password(byte *user, byte *pass) {

	if (strcmp((char *)user, USERNAME) != 0) {
		return -2;
	}
	if (strcmp((char *)pass, PASSWORD) != 0) {
		return -1;
	}
	return 0;
}

/**
 * @brief Console main task
 */
int console_hd(SSH *ssh) {
	int ret;

	/* Parse input string */
	ret = parse_echo(ssh);
	if (ret < 0) {
		return -1;
	}

	/* Any command to execute? */
	if (ret == 1) {
		execute_echo(ssh);
		/* Send reply to client */
		if (transportWritePacket(ssh) < 0) {
			return -1;
		}
	}

    return 0;
}

/**
 * @brief Parse input string
 */
static int parse_echo(SSH *ssh) {
	byte *p;
	byte *out;
	word32 tmpSz;

	p = ssh->sp.data;
	//out = tmp;

	/* Read recipient channel */
	read_uint32(&p, &tmpSz);

	/* Read input */
	read_bin(&p, &out, &tmpSz);

	if ((idx + tmpSz) < sizeof(buf) - 1) {
		/* Copy input data */
		memcpy(buf + idx, out, tmpSz);
		idx += tmpSz;
	} else {
		/* too much data*/
		buf[0] = '\r';
		buf[1] = 0;
		return 1;
	}

	/* Return on CR */
	if (out[tmpSz - 1] == '\n' || out[tmpSz - 1] == '\r') {
		return 1;
	}

	/* Echo inputdata */
	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_CHANNEL_DATA);
	packet_add_uint32(&p, ssh->rec_num);
	packet_add_name_list(&p, buf + idx - tmpSz);

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	/* Send reply to client */
	if (transportWritePacket(ssh) < 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Application
 */
static int execute_echo(SSH *ssh) {
	byte *p;

	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	/* Input data and his size is in buf and idx.
	 * At this point you can process the received commands */

	packet_begin(&p, SSH_MSG_CHANNEL_DATA);
	packet_add_uint32(&p, ssh->rec_num);

	/* We not support any command */
	sprintf((char *)(p + 4), "\r\n command not found\r\n%s%s", /* Build and add message */
				USERNAME,
				PROMPT_STR);

	packet_add_uint32(&p, strlen((char *)(p + 4)));
	p += strlen((char *)p);

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	memset(buf, 0, sizeof(buf));
	idx = 0;

	return 0;
}
