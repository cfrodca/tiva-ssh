/*
 * kex.c
 *
 *  Created on: 9/07/2015
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
#include "kex.h"
#include "primenum.h"

#define DH_GROUP14_STR				"diffie-hellman-group14-sha1"
#define DH_GROUP1_STR				"diffie-hellman-group1-sha1"

#define KEY_ALG_DH14_STR 			"diffie-hellman-group14-sha1,diffie-hellman-group1-sha1"
#define KEY_ALG_DH1_STR				"diffie-hellman-group1-sha1,diffie-hellman-group14-sha1"

#define HOSTKEY_ALG_DSS_STR			"ssh-dss"
#define HOSTKEY_ALG_RSA_STR			"ssh-rsa"

#define AES_256_CBC_STR				"aes256-cbc"
#define AES_192_CBC_STR				"aes192-cbc"
#define AES_128_CBC_STR				"aes128-cbc"

#define HMACSHA1_STR				"hmac-sha1"

#define COMPRESSION					"none"
#define LANGUAGES					""

/* Main functions */
static int parse_kexinit(SSH *);
static int build_kexinit_response(SSH *);
static int compute_dhinit(SSH *);
static int build_dhinit_response(SSH *);
static int build_newk(SSH *);
static int build_newk_response(SSH *);

/* Support functions */
static void getNameList(char **, char **, word32 *);
static void build_KS(SSH *, byte *, word32 *);
static void keymaker(SSH *, byte *, byte, byte);

/**
 * @brief Section 7.1 - Algorithm Negotiation
 */
int kexinit_hd(SSH *ssh) {

	/* Parse key exchange */
	if (parse_kexinit(ssh) < 0)
		return -1;

	/* Build key exchange reply */
	if (build_kexinit_response(ssh) < 0) {
		return -1;
	}

	/* Send reply to client */
	if (transportWritePacket(ssh) < 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Section 8 - Diffie-Hellman Key Exchange
 */
int kexdh_hd(SSH *ssh) {

	/* Compute algorithm, etc. */
	if (compute_dhinit(ssh) < 0) {
		return -1;
	}

	/* Build dh reply */
	if (build_dhinit_response(ssh) < 0) {
		return -1;
	}

	/* Send reply to client */
	if (transportWritePacket(ssh) < 0) {
		return -1;
	}

	return 0;
}

/**
 * @brief Section 7.2 - Output from Key Exchange
 */
int kexnewk_hd(SSH *ssh) {

	/* Compute encrypt/decrypt and hmac keys */
	if (build_newk(ssh) < 0) {
		return -1;
	}

	/* Build new keys reply  */
	build_newk_response(ssh);

	/* Send reply to client */
	if (transportWritePacket(ssh) < 0) {
		return -1;
	}

	/* Signal encrypt/decrytp */
	ssh->flEnc = 1;

	return 0;
}

/**
 * @brief Parse key exchange init
 */
static int parse_kexinit(SSH *ssh) {
	char* next;
	byte* p;
	byte* payload;
	word32 size;
	Sha* sha;
	DhKey* dh;

	char *kex_algos;
	char *host_keys;
	char *enc_c2s;
	char *mac_c2s;

	dh = &ssh->dh;
	sha = &ssh->sha;
	payload = ssh->sp.payload;

	/* Skip message code and cookie */
	next = (char *) payload + sizeof(byte) + COOKIE_SIZE;

	getNameList(&next, &kex_algos, &size);	/* kex_algorithms */
	getNameList(&next, &host_keys, &size);	/* server_host_key_algorithms */
	getNameList(&next, &enc_c2s, &size);	/* encryption_algorithms_client_to_server */
	getNameList(&next, NULL, &size);		/* encryption_algorithms_server_to_client */
	getNameList(&next, &mac_c2s, &size);	/* mac_algorithms_client_to_server */
	getNameList(&next, NULL, &size);		/* mac_algorithms_server_to_client */
	getNameList(&next, NULL, &size);		/* compression_algorithms_client_to_server */
	getNameList(&next, NULL, &size);		/* compression_algorithms_server_to_client */
	getNameList(&next, NULL, &size);		/* languages_algorithms_client_to_server */
	getNameList(&next, NULL, &size);		/* languages_algorithms_server_to_client */

	/* Skip kex first packet follows */
	next += sizeof(byte);

	/* Skip reserved */
	next += sizeof(word32);

	/* Verify payload length */
	if ((next - (char *) payload) > ssh->sp.payload_length)
		return -1;

	/* It supports Diffie-Hellman? */
	if (strstr(kex_algos, DH_GROUP14_STR) != NULL) {
		ssh->namelist[DH_GROUP_IND] = KEY_ALG_DH14_STR;
		p = (byte *) oakley14_prime;
		size = sizeof(oakley14_prime);
	} else if (strstr(kex_algos, DH_GROUP1_STR) != NULL) {
		ssh->namelist[DH_GROUP_IND] = KEY_ALG_DH1_STR;
		p = (byte *) oakley2_prime;
		size = sizeof(oakley2_prime);
	} else {
		return -1;
	}

	/* It supports DSA keys ? */
	if (strstr(host_keys, HOSTKEY_ALG_DSS_STR) != NULL) {
		ssh->namelist[HOST_KEY_IND] = HOSTKEY_ALG_DSS_STR;
	} else {
		return -1;
	}

	/* It supports AES? */
	if (strstr(enc_c2s, AES_256_CBC_STR) != NULL) {
		ssh->namelist[ENC_C2S_IND] = AES_256_CBC_STR;
		ssh->namelist[ENC_S2C_IND] = AES_256_CBC_STR;
	} else if (strstr(enc_c2s, AES_192_CBC_STR) != NULL) {
		ssh->namelist[ENC_C2S_IND] = AES_192_CBC_STR;
		ssh->namelist[ENC_S2C_IND] = AES_192_CBC_STR;
	} else if (strstr(enc_c2s, AES_128_CBC_STR) != NULL) {
		ssh->namelist[ENC_C2S_IND] = AES_128_CBC_STR;
		ssh->namelist[ENC_S2C_IND] = AES_128_CBC_STR;
	} else {
		return -1;
	}

	/* It supports hmac-sha1 ? */
	if (strstr(mac_c2s, HMACSHA1_STR) != NULL) {
		ssh->namelist[MAC_C2S_IND] = HMACSHA1_STR;
		ssh->namelist[MAC_S2C_IND] = HMACSHA1_STR;
	} else {
		return -1;
	}

	/* No compression */
	ssh->namelist[COM_C2S_IND] = COMPRESSION;
	ssh->namelist[COM_S2C_IND] = COMPRESSION;

	/* No language */
	ssh->namelist[LAN_C2S_IND] = LANGUAGES;
	ssh->namelist[LAN_S2C_IND] = LANGUAGES;

	/* Load prime numbers */
	DhSetKey(dh, (byte*) p, size, group1_g, sizeof(group1_g));

	/* Add I_C to sha */
	UpdateHash(sha, payload, ssh->sp.payload_length);

	return 0;
}

/**
 * @brief Build key exchange reply
 */
static int build_kexinit_response(SSH *ssh) {
	RNG rng;
	Sha* sha;
	byte block[16];
	byte *p;

	sha = &ssh->sha;

	/* Generate random */
	if (InitRng(&rng) != 0) {
		return -1;
	}

	if (RNG_GenerateBlock(&rng, block, sizeof(block))) {
		return -1;
	}

	p = ssh->PacketBuffer;
	bzero(p, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_KEXINIT);				/* Type message */
	packet_add_bin(&p, block, sizeof(block));		/* Random number 16 Byte */
	packet_add_name_list(&p, (byte *) ssh->namelist[DH_GROUP_IND]);	/* dh */
	packet_add_name_list(&p, (byte *) ssh->namelist[HOST_KEY_IND]);	/* keys */
	packet_add_name_list(&p, (byte *) ssh->namelist[ENC_C2S_IND]);	/* enc */
	packet_add_name_list(&p, (byte *) ssh->namelist[ENC_S2C_IND]);	/* enc */
	packet_add_name_list(&p, (byte *) ssh->namelist[MAC_C2S_IND]);	/* mac */
	packet_add_name_list(&p, (byte *) ssh->namelist[MAC_S2C_IND]);	/* mac */
	packet_add_name_list(&p, (byte *) ssh->namelist[COM_C2S_IND]);	/* compression */
	packet_add_name_list(&p, (byte *) ssh->namelist[COM_S2C_IND]);	/* compression */
	packet_add_name_list(&p, (byte *) ssh->namelist[LAN_C2S_IND]);	/* lenguage */
	packet_add_name_list(&p, (byte *) ssh->namelist[LAN_S2C_IND]);	/* lenguage */
	packet_add_byte(&p, 0);							/* aditional byte */
	packet_add_uint32(&p, 0);						/* reserve */

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	/* Load again ssh fields */
	transportExtract(ssh);

	/* Add I_S to SHA */
	UpdateHash(sha, ssh->sp.payload , ssh->sp.payload_length);

	return 0;
}

/**
 * @brief Compute hash, keys, signatures, etc
 */
static int compute_dhinit(SSH *ssh) {
	RNG rng;
	DhKey* dh;
	DsaKey* dsa;
	Sha* sha;
	byte* hash;
	byte* session;
	Sha sha2;
	byte hash2[SHA_DIGEST_SIZE];

	byte *tmp;
	word32 tmpSz;

	byte priv[257];
	word32 privSz;

	Error_Block eb;
	int ret = 0;

	/* Allocate memory */
	Error_init(&eb);
	tmp = (byte *) Memory_alloc(NULL, TCPPACKETSIZE, 0, &eb);
	if (!tmp) {
		return -1;
	}

	dh = &ssh->dh;
	dsa = &ssh->ctx->peerKey;
	sha = &ssh->sha;
	hash = ssh->H;
	session = ssh->session;

	if (InitRng(&rng) != 0) {
		ret = -1;
		goto ABORT;
	}

	/* Build K_S */
	build_KS(ssh, tmp, &tmpSz);

	/* Add K_S to sha */
	UpdateHash(sha, tmp, tmpSz);

	/* Add e to sha */
	tmpSz = htonl(*(word32 *)ssh->sp.data);
	UpdateHash(sha, ssh->sp.data + sizeof(word32), tmpSz);

	/* Generate f = g^y mod p */
	if (DhGenerateKeyPair(dh, &rng, priv, &privSz, ssh->f, &ssh->fSz) != 0) {	/* pub has (f) and priv has (y) */
		ret = -1;
		goto ABORT;
	}

	if (ssh->f[0] & 0x80) {  // add leading 0 per standard
		memmove(ssh->f + 1, ssh->f, ssh->fSz);
		ssh->f[0] = 0;
		ssh->fSz++;
	}

	UpdateHash(sha, ssh->f, ssh->fSz);

	/* Generate K = e^y mod p */
	if (DhAgree(dh, ssh->K, &ssh->KSz, priv, privSz, ssh->sp.data + sizeof(word32), tmpSz)) {
		ret = -1;
		goto ABORT;
	}

	if (ssh->K[0] & 0x80) {  // add leading 0 per standard
		memmove(ssh->K + 1, ssh->K, ssh->KSz);
		ssh->K[0] = 0;
		ssh->KSz++;
	}

	/* Add K to sha */
	UpdateHash(sha, ssh->K, ssh->KSz);

	/* Generate H = HASH(V_C || V_S || I_C || I_S || K_S || e || f || K) */
	ShaFinal(sha, hash);

	/*  Once computed, the session identifier is not changed,
   	 *  even if keys are later re-exchanged. */
	if (!ssh->flEnc) {
		memcpy(session, hash, SHA_DIGEST_SIZE);
	}

	/* Second sha */
	if (InitSha(&sha2) != 0) {
		ret = -1;
		goto ABORT;
	}

	ShaUpdate(&sha2, hash, SHA_DIGEST_SIZE);
	ShaFinal(&sha2, hash2);

	if (InitRng(&rng) != 0) {
		ret = -1;
		goto ABORT;
	}

	if (DsaSign(hash2, ssh->sign, dsa, &rng) != 0) {
		ret = -1;
		goto ABORT;
	}

ABORT:
	if (tmp)
		Memory_free(NULL, tmp, TCPPACKETSIZE);

	return ret;
}

/**
 * @brief Build dh reply
 */
static int build_dhinit_response(SSH *ssh) {
	byte *p;
	byte *tmp;
	word32 tmpSz;
	Error_Block eb;

	/* Allocate memory */
	Error_init(&eb);
	tmp = (byte *) Memory_alloc(NULL, TCPPACKETSIZE, 0, &eb);
	if (!tmp) {
		return -1;
	}

	p = ssh->PacketBuffer;
	bzero(p, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_KEXDH_REPLY);			/* Type message */

	build_KS(ssh, tmp, &tmpSz);						/* Generate again K_S */

	packet_add_uint32(&p, tmpSz);					/* Server public host key */
	packet_add_bin(&p, tmp, tmpSz);

	packet_add_uint32(&p, ssh->fSz);				/* f */
	packet_add_bin(&p, ssh->f, ssh->fSz);

	packet_add_uint32(&p, sizeof(word32) +			/* Signature s */
						  strlen(ssh->namelist[HOST_KEY_IND]) +
						  sizeof(word32) +
						  sizeof(ssh->sign));
	packet_add_name_list(&p, (byte *) ssh->namelist[HOST_KEY_IND]);
	packet_add_uint32(&p, sizeof(ssh->sign));
	packet_add_bin(&p, ssh->sign, sizeof(ssh->sign));

	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	Memory_free(NULL, tmp, TCPPACKETSIZE);
	return 0;
}

/**
 * @brief Generate new encrypt/decrypt keys and hmac
 */
static int build_newk(SSH *ssh) {
	byte keyA[16];
	byte keyB[16];
	byte keyC[32];
	byte keyD[32];
	byte keyE[20];
	byte keyF[20];
	int kSz;

	kSz = getCipherBlockSize(ssh);
	if (kSz < 0) {
		return -1;
	}

	keymaker(ssh, keyA, 'A', 16);
	keymaker(ssh, keyB, 'B', 16);
	keymaker(ssh, keyC, 'C', kSz);
	keymaker(ssh, keyD, 'D', kSz);
	keymaker(ssh, keyE, 'E', 20);
	keymaker(ssh, keyF, 'F', 20);

	AesSetKey(&ssh->dec, keyC, kSz, keyA, AES_DECRYPTION);
	AesSetKey(&ssh->enc, keyD, kSz, keyB, AES_ENCRYPTION);
	HmacSetKey(&ssh->hmacV, SHA, keyE, sizeof(keyE));
	HmacSetKey(&ssh->hmacB, SHA, keyF, sizeof(keyF));

	return 0;
}

/**
 * @brief Build new keys reply
 */
static int build_newk_response(SSH *ssh) {
	byte *p;

	p = ssh->PacketBuffer;
	bzero(p, TCPPACKETSIZE);

	packet_begin(&p, SSH_MSG_NEWKEYS);
	ssh->Length = (p - ssh->PacketBuffer);

	packet_finalize(ssh);

	return 0;
}

/**
 * @brief Devuelve los nombres identificados en la lista
 */
static void getNameList(char **next, char **list, word32 *size) {

	*size = htonl(*(word32 *)*next);
	*next = *next + sizeof(word32);
	if (list != NULL)
		*list = *next;
	*next = *next + *size;
}

/**
 *  @brief Generate keys
 */
void keymaker(SSH *ssh, byte *key, byte X, byte len) {
	Sha sha;

	byte k1[SHA_DIGEST_SIZE];
	byte k2[SHA_DIGEST_SIZE];

	byte tmp[4];   // for network k size

	if (InitSha(&sha) != 0)
		return;

	// K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
	// K encoded as mpint
	word32 netSz = htonl(ssh->KSz);
	memcpy(tmp, &netSz, sizeof(tmp));

	ShaUpdate(&sha, tmp, sizeof(tmp));
	ShaUpdate(&sha, ssh->K, ssh->KSz);
	ShaUpdate(&sha, ssh->H, SHA_DIGEST_SIZE);
	ShaUpdate(&sha, &X, 1);
	ShaUpdate(&sha, ssh->session, SHA_DIGEST_SIZE);

	ShaFinal(&sha, k1);

	memcpy(key, k1, SHA_DIGEST_SIZE);

	if (len <= SHA_DIGEST_SIZE) {
		return;
	}

	// K2 = HASH(K || H || K1), K3 = HASH(K || H || K1 || K2)
	ShaUpdate(&sha, tmp, sizeof(tmp));
	ShaUpdate(&sha, ssh->K, ssh->KSz);
	ShaUpdate(&sha, ssh->H, SHA_DIGEST_SIZE);
	ShaUpdate(&sha, k1, SHA_DIGEST_SIZE);
	ShaFinal(&sha, k2);

	memcpy(key + SHA_DIGEST_SIZE, k2, (len - SHA_DIGEST_SIZE));
}

/**
 * @brief Build K_S
 */
static void build_KS(SSH *ssh, byte *ks, word32 *ksSz) {
	byte *ptr;
	word32 tmpSz;

	ptr = ks;
	/* String host key */
	packet_add_name_list(&ptr, (byte *) ssh->namelist[HOST_KEY_IND]);

	/* Integer p */
	tmpSz = mp_unsigned_bin_size((mp_int*)&ssh->ctx->peerKey.p);
	mp_to_unsigned_bin((mp_int*)&ssh->ctx->peerKey.p, ptr + 4);
	if (ptr[4] & 0x80) {  // add leading 0 per standard
		ptr[4] = 0;
		mp_to_unsigned_bin((mp_int*)&ssh->ctx->peerKey.p, ptr + 5);
		tmpSz++;
	}
	packet_add_uint32(&ptr, tmpSz);
	ptr += tmpSz;

	/* Integer a */
	tmpSz = mp_unsigned_bin_size((mp_int*)&ssh->ctx->peerKey.q);
	mp_to_unsigned_bin((mp_int*)&ssh->ctx->peerKey.q, ptr + 4);
	if (ptr[4] & 0x80) {  // add leading 0 per standard
		ptr[4] = 0;
		mp_to_unsigned_bin((mp_int*)&ssh->ctx->peerKey.q, ptr + 5);
		tmpSz++;
	}
	packet_add_uint32(&ptr, tmpSz);
	ptr += tmpSz;

	/* Integer g */
	tmpSz = mp_unsigned_bin_size((mp_int*)&ssh->ctx->peerKey.g);
	mp_to_unsigned_bin((mp_int*)&ssh->ctx->peerKey.g, ptr + 4);
	if (ptr[4] & 0x80) {  // add leading 0 per standard
		ptr[4] = 0;
		mp_to_unsigned_bin((mp_int*)&ssh->ctx->peerKey.g, ptr + 5);
		tmpSz++;
	}
	packet_add_uint32(&ptr, tmpSz);
	ptr += tmpSz;

	/* Integer y */
	tmpSz = mp_unsigned_bin_size((mp_int*)&ssh->ctx->peerKey.y);
	mp_to_unsigned_bin((mp_int*)&ssh->ctx->peerKey.y, ptr + 4);
	if (ptr[4] & 0x80) {  // add leading 0 per standard
		ptr[4] = 0;
		mp_to_unsigned_bin((mp_int*)&ssh->ctx->peerKey.y, ptr + 5);
		tmpSz++;
	}
	packet_add_uint32(&ptr, tmpSz);
	ptr += tmpSz;

	*ksSz = (ptr - ks);
}

/**
 *  @brief Return the cipher block size (bytes) selected
 */
int getCipherBlockSize(SSH *ssh) {
	/* Según el algoritmo escogido, definimos la longitud necesitada */
	if (strcmp(ssh->namelist[ENC_C2S_IND], AES_256_CBC_STR) == 0)
		return 32;
	else if (strcmp(ssh->namelist[ENC_C2S_IND], AES_192_CBC_STR) == 0)
		return 24;
	else if (strcmp(ssh->namelist[ENC_C2S_IND], AES_128_CBC_STR) == 0)
		return 16;
	else
		return -1;
}

/**
 * @brief Update sha with size in net order
 */
void UpdateHash(Sha *sha, const byte *data, word32 size) {
    word32 netSz = htonl(size);
    byte   tmp[4];

    memcpy(tmp, &netSz, sizeof(tmp));

    ShaUpdate(sha, tmp, sizeof(tmp));
    ShaUpdate(sha, data, size);
}
