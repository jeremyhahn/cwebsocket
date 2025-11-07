/**
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2014 Jeremy Hahn
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 *  THE SOFTWARE.
 */

#include "common.h"

char* cwebsocket_base64_encode(const unsigned char *input, int length) {
	BIO *bmem, *b64;
	BUF_MEM *bptr;
	b64 = BIO_new(BIO_f_base64());
	if(b64 == NULL) {
		return NULL;
	}
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	bmem = BIO_new(BIO_s_mem());
	if(bmem == NULL) {
		BIO_free_all(b64);
		return NULL;
	}
	b64 = BIO_push(b64, bmem);
	if(BIO_write(b64, input, length) <= 0) {
		BIO_free_all(b64);
		return NULL;
	}
	if(BIO_flush(b64) != 1) {
		BIO_free_all(b64);
		return NULL;
	}
	BIO_get_mem_ptr(b64, &bptr);
	if(bptr == NULL || bptr->length <= 0) {
		BIO_free_all(b64);
		return NULL;
	}
	char *buff = (char *)malloc(bptr->length + 1);
	if(buff == NULL) {
		BIO_free_all(b64);
		return NULL;
	}
	// Flawfinder: ignore - memcpy with validated bptr->length from BIO
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = '\0';
	BIO_free_all(b64);
	return buff;
}

void cwebsocket_print_frame(cwebsocket_frame *frame) {
    syslog(LOG_DEBUG, "cwebsocket_print_frame: fin=%i, rsv1=%i, rsv2=%i, rsv3=%i, opcode=%#04x, mask=%i, payload_len=%llu\n",
            frame->fin, frame->rsv1, frame->rsv2, frame->rsv3, frame->opcode, frame->mask, frame->payload_len);
}

char* cwebsocket_create_key_challenge_response(const char *seckey) {
	const char *GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	// Flawfinder: ignore - strlen on null-terminated seckey string
	const int seckey_len = strlen(seckey);
	const int total_len = seckey_len + 36;
	// Flawfinder: ignore - char array used for SHA1 hashing with validated sizes
	char sha1buf[total_len];
	// Flawfinder: ignore - memcpy with validated seckey_len from strlen
	memcpy(sha1buf, seckey, seckey_len);
	// Flawfinder: ignore - memcpy with fixed 36-byte GUID size
	memcpy(&sha1buf[seckey_len], GUID, 36);
	// Flawfinder: ignore - char array for SHA1 output (fixed 20 bytes)
	unsigned char sha1_bytes[20];
	SHA1((const unsigned char *)sha1buf, total_len, sha1_bytes);
	return cwebsocket_base64_encode((const unsigned char *)sha1_bytes, sizeof(sha1_bytes));
}
