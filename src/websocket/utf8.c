/**
 *  cwebsocket: A fast, lightweight websocket client/server
 *
 *  Copyright (c) 2014 Jeremy Hahn
 *
 *  This file is part of cwebsocket.
 *
 *  cwebsocket is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  cwebsocket is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with cwebsocket.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "utf8.h"

int utf8_count_code_points(uint8_t* s, size_t* count) {

	uint32_t codepoint;
	uint32_t state = 0;

	for(*count = 0; *s; ++s)
		if(!utf8_decode(&state, &codepoint, *s))
			*count += 1;

	return state != UTF8_ACCEPT;
}

uint32_t inline utf8_decode(uint32_t* state, uint32_t* codep, uint32_t byte) {

	uint32_t type = utf8d[byte];
	*codep = (*state != UTF8_ACCEPT) ?
			(byte & 0x3fu) | (*codep << 6) :
			(0xff >> type) & (byte);

	*state = utf8d[256 + *state*16 + type];
	return *state;
}
