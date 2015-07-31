/*
 * Copyright (c) 2014-2015, Texas Instruments Incorporated
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * *  Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * *  Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * *  Neither the name of Texas Instruments Incorporated nor the names of
 *    its contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 *    ======== tcpEchoTLS.c ========
 */

#include <string.h>

#include <xdc/std.h>
#include <xdc/cfg/global.h>
#include <xdc/runtime/Error.h>
#include <xdc/runtime/System.h>

#include <ti/sysbios/BIOS.h>
#include <ti/sysbios/knl/Task.h>
#include <ti/drivers/GPIO.h>

/* NDK BSD support */
#include <sys/socket.h>
#include <arpa/inet.h>

/* Example/Board Header file */
#include "Board.h"
#include "servers/ssh/sshd.h"

#define TCPWORKERSTACKSIZE 14592
//#define TCPWORKERSTACKSIZE	20000
#define NUMTCPWORKERS 	   	1

/****************************************************************************/
/*  Tasks functions															*/
/****************************************************************************/
/**
 * @brief Toggle the Board_LED0
 * @param <i>arg0</i> Determines the sleep period of the task
 * @param <i>arg1</i> unused
 * @return Void
 */
Void heartBeatFxn(UArg arg0, UArg arg1)
{
	while (1) {
		Task_sleep((UInt)arg0);
		GPIO_toggle(Board_LED0);
		GPIO_toggle(Board_LED1);
	}
}

/*
 *  ======== exitApp ========
 *  Cleans up the SSH context and exits the application
 */
Void exitApp(SSH_CTX *ctx)
{
	if (ctx)
		SSH_CTX_free(ctx);

	//BIOS_exit(-1);
}

/*
 *  ======== tcpWorker ========
 *  Task to handle TCP connection. Can be multiple Tasks running
 *  this function.
 */
Void tcpWorker(UArg arg0, UArg arg1)
{
	int rc;
    int clientfd = 0;
    SSH *ssh = (SSH *)arg0;

    clientfd = SSH_get_fd(ssh);
    System_printf("tcpWorker: start clientfd = 0x%x\n", clientfd);

	/* Init structs */
	transportInit(ssh);

	/* Signal active session */
    ssh->ctx->actSe = 1;

	/* Version exchange */
    rc = transportVersion_hd(ssh);
	if (rc < 0 )
		goto ABORT;
	if (rc == 1)
		goto PROCESS;

	/* Main loop */
	for (;;) {
		/* Read plain/encrypt packet from client */
		rc = transportGetPacket(ssh);
		if (rc < 0)
			break;

PROCESS:
		rc = transportExtract(ssh);
		if (rc < 0)
			break;

		/* Process the reply packet */
		rc = transportProcessPacket(ssh);
		if (rc != 0)
			break;

		//System_flush();
	}

ABORT:
	System_printf("tcpWorker stop clientfd = 0x%x\n", clientfd);
	System_flush();

	if (ssh)
		SSH_free(ssh);
	close(clientfd);
}

/*
 *  ======== tcpHandler ========
 *  Creates new Task to handle new TCP connections.
 */
Void dtask_tcp_echo(UArg arg0, UArg arg1)
{
    int                status;
    int                clientfd;
    int                server;
    struct sockaddr_in localAddr;
    struct sockaddr_in clientAddr;
    int                optval;
    int                optlen = sizeof(optval);
    socklen_t          addrlen = sizeof(clientAddr);
    Task_Handle        taskHandle;
    Task_Params        taskParams;
    Error_Block        eb;
    SSH_CTX            *ctx;
    SSH                *ssh;

    /* Allocate memory */
	ctx = SSH_CTX_new();

	/* Load DSA Keys in ctx */
	if (SSH_CTX_load_keys(ctx) < 0) {
		System_printf("Error: keys load failed.\n");
		goto ABORT;
	}

	server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (server == -1) {
		System_printf("Error: socket not created.\n");
		goto ABORT;
	}

    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(arg0);

    status = bind(server, (struct sockaddr *)&localAddr, sizeof(localAddr));
    if (status == -1) {
        System_printf("Error: bind failed.\n");
        goto ABORT;
    }

    status = listen(server, NUMTCPWORKERS);
    if (status == -1) {
        System_printf("Error: listen failed.\n");
        goto ABORT;
    }

    optval = 1;
    if (setsockopt(server, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        System_printf("Error: setsockopt failed\n");
        goto ABORT;
    }

	/* TCP no push */
	if (setsockopt(server, IPPROTO_TCP, TCP_NOPUSH, &optval, optlen ) < 0) {
		System_printf("Error: setsockopt failed\n");
		goto ABORT;
	}

    while ((clientfd =
            accept(server, (struct sockaddr *)&clientAddr, &addrlen)) != -1) {

    	/* Only 1 active session */
    	if (ctx->actSe > 0) {
    		close(clientfd);
    		continue;
    	}

    	ctx->actSe = 1;

        /* Init the Error_Block */
        Error_init(&eb);
        ssh = SSH_new(ctx);
		if (ssh == NULL) {
			System_printf("Error: SSH_new failed.\n");
			close(clientfd);
			continue;
		}

        SSH_set_fd(ssh, clientfd);

        /* Initialize the defaults and set the parameters. */
        Task_Params_init(&taskParams);
        taskParams.arg0 = (UArg)ssh;
        taskParams.stackSize = TCPWORKERSTACKSIZE;
        taskHandle = Task_create((Task_FuncPtr)tcpWorker, &taskParams, &eb);
        if (taskHandle == NULL) {
            System_printf("Error: Failed to create new Task\n");
            close(clientfd);
        }

        /* addrlen is a value-result param, must reset for next accept call */
        addrlen = sizeof(clientAddr);

        /* get client ip address */
        struct sockaddr_in *s = (struct sockaddr_in *)&clientAddr;
        inet_ntop(AF_INET, &s->sin_addr, ssh->in_addr, sizeof(ssh->in_addr));

        System_flush();
    }

    System_printf("Error: accept failed.\n");
    System_flush();
ABORT:
	if (server > 0) {
		close(server);
	}
	exitApp(ctx);
}

/*
 *  ======== main ========
 */
int main(void)
{
    /* Call board init functions */
    Board_initGeneral();
    Board_initGPIO();
    Board_initEMAC();

    /* CyaSSL library needs time() for validating certificates. */
    //MYTIME_init();
    //MYTIME_settime(CURRENTTIME);

    System_printf("Starting the SSH/TCP Echo example\nSystem provider is set "
                  "to SysMin. Halt the target to view any SysMin contents in"
                  " ROV.\n");
    /* SysMin will only print to the console when you call flush or exit */
    System_flush();

    /* Start BIOS */
    BIOS_start();

    return (0);
}
