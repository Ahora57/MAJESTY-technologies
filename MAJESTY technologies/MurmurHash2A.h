#pragma once
#include "NoCRT.h"
#define mmix(h,k) { k *= m; k ^= k >> r; k *= m; h *= m; h ^= k; }
#define MurmurHashStr(str) MurmurHash2A(str,NoCRT::string::strlen(str),  NoCRT::string::strlen(str) )


__forceinline constexpr uint64_t  MurmurHash2A(uint64_t key, int len, uint64_t  seed)
{
	const unsigned int m = 0x5bd1e995;
	const auto r = 24;
	unsigned int l = len;
	auto data = static_cast<uint64_t >(key);

	

	  uint64_t   h = seed * __TIME__[4];
	uint64_t  k = 0;

	while (len >= 4)
	{
		k = data;

		mmix(h, k);

		data += 4;
		len -= 4;
	}

	uint64_t  t = 0;

	switch (len)
	{
	case 3: t ^= data << 16;
	case 2: t ^= data << 8;
	case 1: t ^= data;
	};

	mmix(h, t);
	mmix(h, l);

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}