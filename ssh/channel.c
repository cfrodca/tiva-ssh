/*
 * channel.c
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
#include "channel.h"
#include "console.h"

#define SESSION_STR		"session"
#define PTY_STR			"pty-req"
#define ENV_STR			"env"
#define X11_STR			"x11-req"
#define SHELL_STR		"shell"
#define EXEC_STR		"exec"
#define SUBSYSTEM_STR	"subsystem"
#define WINDOWCH_STR	"window-change"
#define XONXOFF_STR		"xon-xoff"
#define SIGNAL_STR		"signal"
#define EXITSTATUS_STR	"exit-status"
#define EXITSIGNAL_STR	"exit-signal"
#define NONE_STR		""

static int parse_chopen(SSH *);
static int build_chopensucc_response(SSH *);
static int build_chopenfail_response(SSH *);
static int parse_chrequest(SSH *);
static int build_chreq_response(SSH *, byte);

/**
 * @brief Open channel
 */
int chopen_hd(SSH *ssh) {
	int ret;

	/* Parse channel open request */
	ret = parse_chopen(ssh);
	if (ret < 0) {
		return -1;
	}

	/* Build success or fail reply */
	if (ret == 1) {
		build_chopenfail_response(ssh);
	} else {
		build_chopensucc_response(ssh);
	}

	/* Send reply to client */
	if (transportWritePacket(ssh) < 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Request channel
 */
int chrequest_hd(SSH *ssh) {
	int ret;

	/* Verify request */
	ret = parse_chrequest(ssh);
	if (ret < 0) {
		return -1;
	}

	/* Build success or fail reply */
	if (ret == 1) {
		build_chreq_response(ssh, SSH_MSG_CHANNEL_FAILURE);
	} else {
		build_chreq_response(ssh, SSH_MSG_CHANNEL_SUCCESS);
	}

	/* Send reply to client */
	if (ssh->wantReply) {
		if(transportWritePacket(ssh) < 0) {
			return -1;
		}
	}

	/* Build welcome reply */
	if (ret == 2) {
		build_welcome_msg_response(ssh);
		/* Send reply to client */
		if (transportWritePacket(ssh) < 0) {
			return -1;
		}
	}

	return 0;
}

/**
 * @brief Parse channel request
 */
static int parse_chrequest(SSH *ssh) {
	byte *p;
	byte *out;
	word32 outSz;
	word32 num;

	/* Verify if the channel is open or the session is pty */
	if (ssh->state != SSH_CHOPEN && ssh->state != SSH_PTY) {
		return -1;
	}

	p = ssh->sp.data;

	/* Read recipient channel */
	read_uint32(&p, &num);

	/* Read string */
	read_bin(&p, &out, &outSz);

	/* Read want_reply byte */
	read_byte(&p, &ssh->wantReply);

	/* Handle channel request */
	if (memcmp(out, PTY_STR, strlen(PTY_STR)) == 0) {
		/* Only support pty mode */
		ssh->state = SSH_PTY;
		return 0;
	} else if (memcmp(out, ENV_STR, strlen(ENV_STR)) == 0) {
		return 0;
	} else if (memcmp(out, X11_STR, strlen(X11_STR)) == 0) {
		return 1;
	} else if (memcmp(out, SHELL_STR, strlen(SHELL_STR)) == 0) {
		/* Signal build welcome reply */
		ssh->state = SSH_SHELL;
		return 2;
	} else if (memcmp(out, EXEC_STR, strlen(EXEC_STR)) == 0) {
		return 1;
	} else if (memcmp(out, SUBSYSTEM_STR, strlen(SUBSYSTEM_STR)) == 0) {
		return 1;
	} else if (memcmp(out, WINDOWCH_STR, strlen(WINDOWCH_STR)) == 0) {
		return 1;
	} else if (memcmp(out, XONXOFF_STR, strlen(XONXOFF_STR)) == 0) {
		return 1;
	} else if (memcmp(out, SIGNAL_STR, strlen(SIGNAL_STR)) == 0) {
		return 1;
	} else if (memcmp(out, EXITSTATUS_STR, strlen(EXITSTATUS_STR)) == 0) {
		return 1;
	} else if (memcmp(out, EXITSIGNAL_STR, strlen(EXITSIGNAL_STR)) == 0) {
		return 1;
	} else {
		return -1;
	}
}

/**
 * @brief Build channel request reply
 */
static int build_chreq_response(SSH *ssh, byte state) {
	byte *p;

	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	packet_begin(&p, state);							/* Type message */
	packet_add_uint32(&p, ssh->rec_num);				/* Recipient channel */

	ssh->Length = (p - ssh->PacketBuffer);				/* Frame length without padding  */

	packet_finalize(ssh);								/* Add padding and encrypt */

	return 0;
}

/**
 * @brief Parse channel open request
 */
static int parse_chopen(SSH *ssh) {
	byte *p;
	byte *out;
	word32 outSz;

	/* Requires auth  */
	if (ssh->state != SSH_AUTH) {
		return -1;
	}

	p = ssh->sp.data;

	/* Read sesion */
	read_bin(&p, &out, &outSz);

	/* Read sender channel */
	read_uint32(&p, &ssh->rec_num);

	/* Only supports sessions */
	if (memcmp(out, SESSION_STR, strlen(SESSION_STR)) != 0) {
		return 1;
	}

	/* Read initial windows size */
	read_uint32(&p, &ssh->out_win_sz);

	ssh->in_win_sz = 4294967295;

	/* Read maximum packet size */
	read_uint32(&p, &ssh->packet_sz);

	ssh->local_num = ssh->in_sequence;

	/* Channel open */
	ssh->state = SSH_CHOPEN;

	return 0;
}

/**
 * @brief Build channel open success reply
 */
static int build_chopensucc_response(SSH *ssh) {
	byte *p;

	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);/* Type message */
	packet_add_uint32(&p, ssh->rec_num);				/* recipient channel */
	packet_add_uint32(&p, ssh->local_num);				/* local num */
	packet_add_uint32(&p, ssh->in_win_sz);				/* initial window size */
	packet_add_uint32(&p, ssh->packet_sz);				/* maximum packet size */

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	return 0;
}

/**
 * @brief Build channel open fail reply
 */
static int build_chopenfail_response(SSH *ssh) {
	byte *p;

	p = ssh->PacketBuffer;
	memset(p, 0, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_CHANNEL_OPEN_FAILURE);
	packet_add_uint32(&p, ssh->rec_num);				/* recipient channel */
	packet_add_uint32(&p, SSH_OPEN_UNKNOWN_CHANNEL_TYPE);/* reason code */
	packet_add_name_list(&p, NONE_STR);
	packet_add_name_list(&p, NONE_STR);

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	return 0;
}
