/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "rand.h"

#ifndef RAND_PLATFORM_INDEPENDENT

// The following code is not supposed to be used in a production environment.
// It's included only to make the library testable.
// The message above tries to prevent any accidental use outside of the test environment.
//
// You are supposed to replace the random32() function with your own secure code.
// There is also a possibility to replace the random_buffer() function as it is defined as a weak symbol.

#include <stdio.h>
#include <time.h>

uint32_t random32(void)
{
	static int initialized = 0;
	if (!initialized) {
		srand((unsigned)time(NULL));
		initialized = 1;
	}
	return ((rand() & 0xFF) | ((rand() & 0xFF) << 8) | ((rand() & 0xFF) << 16) | ((uint32_t) (rand() & 0xFF) << 24));
}

#endif /* RAND_PLATFORM_INDEPENDENT */

//
// The following code is platform independent
//

void __attribute__((weak)) random_buffer(uint8_t *buf, size_t len)
{
	uint32_t r = 0;
	for (size_t i = 0; i < len; i++) {
		if (i % 4 == 0) {
			r = random32();
		}
		buf[i] = (r >> ((i % 4) * 8)) & 0xFF;
	}
}

uint32_t random_uniform(uint32_t n)
{
	uint32_t x, max = 0xFFFFFFFF - (0xFFFFFFFF % n);
	while ((x = random32()) >= max);
	return x / (max / n);
}

void random_permute(char *str, size_t len)
{
	for (int i = len - 1; i >= 1; i--) {
		int j = random_uniform(i + 1);
		char t = str[j];
		str[j] = str[i];
		str[i] = t;
	}
}
