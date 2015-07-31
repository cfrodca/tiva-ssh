/*
 * console.h
 *
 *  Created on: 24/07/2015
 *      Author: Cristian
 */

#ifndef SERVERS_SSH_CONSOLE_H_
#define SERVERS_SSH_CONSOLE_H_


int build_welcome_msg_response(SSH *);
int check_password(byte *, byte *);
int console_hd(SSH *);

#endif /* SERVERS_SSH_CONSOLE_H_ */
