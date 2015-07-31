/*
 * kex.h
 *
 *  Created on: 15/07/2015
 *      Author: Cristian
 */

#ifndef SERVERS_SSH_KEX_H_
#define SERVERS_SSH_KEX_H_

int kexinit_hd(SSH *);
int kexdh_hd(SSH *);
int kexnewk_hd(SSH *);

int getCipherBlockSize(SSH *);
void UpdateHash(Sha *, const byte *, word32);

#endif /* SERVERS_SSH_KEX_H_ */
