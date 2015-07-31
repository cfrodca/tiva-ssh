/*
 * channel.h
 *
 *  Created on: 24/07/2015
 *      Author: Cristian
 */

#ifndef SERVERS_SSH_CHANNEL_H_
#define SERVERS_SSH_CHANNEL_H_


int chopen_hd(SSH *);
int chrequest_hd(SSH *);
int ch_close_hd(SSH *);

#endif /* SERVERS_SSH_CHANNEL_H_ */
