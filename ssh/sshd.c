/*
 * sshd.c
 *
 *  Created on: 7/07/2015
 *      Author: Cristian
 */

#include <string.h>     // memcpy
#include <stdlib.h>     // atoi
#include <stdio.h>      // sprintf

/* XDCtools Header files */
#include <xdc/std.h>
#include <xdc/runtime/Memory.h>
#include <xdc/runtime/System.h>
#include <xdc/runtime/Error.h>
#include <xdc/cfg/global.h>

#include <ti/ndk/inc/netmain.h>
#include <ti/ndk/inc/_stack.h>

#include "sshd.h"

#include <cyassl/certs_test.h>

/**
 * @brief Allocate memory for SSH object
 */
SSH* SSH_new(SSH_CTX* ctx) {
	Error_Block eb;
	SSH *ssh = NULL;

	Error_init(&eb);

	if (ctx == NULL)
		return ssh;

	ssh = (SSH *) Memory_alloc(NULL, sizeof(SSH), 0, &eb);
	if (ssh) {
		bzero((char *)ssh, sizeof(SSH));
		ssh->ctx = ctx;

		/* Malloc Packet Data Buffer */
		ssh->PacketBuffer = Memory_alloc(NULL, TCPPACKETSIZE, 0, &eb);
		if (!ssh->PacketBuffer) {
			if (ssh)
				Memory_free(NULL, ssh, sizeof(SSH));
		}
	}

	return ssh;
}

/**
 * @brief Free memory allocated to SSH object
 */
void SSH_free(SSH* ssh) {

	ssh->ctx->actSe = 0;
	if (ssh->PacketBuffer)
		Memory_free(NULL, ssh->PacketBuffer, TCPPACKETSIZE);
	if (ssh)
		Memory_free(NULL, ssh, sizeof(SSH));
}

/**
 * @brief Allocate memory to SSH_CTX object
 */
SSH_CTX* SSH_CTX_new(void) {
	Error_Block eb;
	SSH_CTX* ctx = NULL;

	Error_init(&eb);

	ctx = (SSH_CTX*) Memory_alloc(NULL, sizeof(SSH_CTX), 0, &eb);
	if (ctx) {
		bzero((char *)ctx, sizeof(ctx));
	}

	return ctx;
}

/**
 * @brief Free memory allocated to SSH_CTX object
 */
void SSH_CTX_free(SSH_CTX* ctx) {
	if (ctx)
		Memory_free(NULL, ctx, sizeof(SSH_CTX));
}

/**
 * @brief Return read file descriptor
 */
int SSH_get_fd(const SSH* ssh) {
    return ssh->rfd;
}

/**
 * @brief Assigns file descriptor
 */
void SSH_set_fd(SSH* ssh, int fd) {
    ssh->rfd = fd;      /* not used directly to allow IO callbacks */
    ssh->wfd = fd;
}

/**
 * Load keys in SSH_CTX object
 */
int SSH_CTX_load_keys(SSH_CTX* ctx) {
	int status;
	word32 idx = 0;
	byte *tmp;
	Error_Block eb;

	Error_init(&eb);

	tmp = (byte*) Memory_alloc(NULL, sizeof_dsa_key_der_1024, 0, &eb);
	memcpy(tmp, dsa_key_der_1024, sizeof_dsa_key_der_1024);
	InitDsaKey(&ctx->peerKey);

	status = DsaPrivateKeyDecode(tmp, &idx, &ctx->peerKey, sizeof_dsa_key_der_1024);
	if (status != 0) {
		status = -1;
	}

	if (tmp)
		Memory_free(NULL, tmp, sizeof_dsa_key_der_1024);

	return status;
}
