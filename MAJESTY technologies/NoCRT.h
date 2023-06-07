#pragma once
#include "Struct.h"


namespace NoCRT {
	namespace mem {

		__forceinline  int  memicmp(const void* s1, const void* s2, unsigned __int64 n)
		{
			if (n != 0)
			{
				const unsigned char* p1 = (unsigned char*)s1, * p2 = (unsigned char*)s2;
				do
				{
					if (toupper(*p1) != toupper(*p2)) return (*p1 - *p2);
					p1++;
					p2++;
				} while (--n != 0);
			}
			return 0;
		}



		__forceinline  void* memcpy(void* dest, const void* src, unsigned __int64 count)
		{
			char* char_dest = (char*)dest;
			char* char_src = (char*)src;
			if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
			{
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest++;
					char_src++;
					count--;

				}
			}
			else
			{
				char_dest = (char*)dest + count - 1;
				char_src = (char*)src + count - 1;
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest--;
					char_src--;
					count--;
				}
			}
			return dest;
		}

		__forceinline  void* memccpy(void* to, const void* from, int c, unsigned __int64 count)
		{
			char t;
			unsigned __int64 i;
			char* dst = (char*)to;
			const char* src = (const char*)from;
			for (i = 0; i < count; i++)
			{
				dst[i] = t = src[i];
				if (t == 0) break;
				if (t == c) return &dst[i + 1];
			}
			return 0;
		}
		__forceinline  void* memchr(const void* s, int c, unsigned __int64 n)
		{
			if (n)
			{
				const char* p = (const char*)s;
				do
				{
					if (*p++ == c) return (void*)(p - 1);
				} while (--n != 0);
			}
			return 0;
		}
		__forceinline  int  memcmp(const void* s1, const void* s2, unsigned __int64 n)
		{
			if (n != 0)
			{
				const unsigned char* p1 = (unsigned char*)s1, * p2 = (unsigned char*)s2;
				do
				{
					if (*p1++ != *p2++) return (*--p1 - *--p2);
				} while (--n != 0);
			}
			return 0;
		}

		__forceinline  void* memmove(void* dest, const void* src, unsigned __int64 count)
		{
			char* char_dest = (char*)dest;
			char* char_src = (char*)src;
			if ((char_dest <= char_src) || (char_dest >= (char_src + count)))
			{
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest++;
					char_src++;
					count--;
				}
			}
			else
			{
				char_dest = (char*)dest + count - 1;
				char_src = (char*)src + count - 1;
				while (count > 0)
				{
					*char_dest = *char_src;
					char_dest--;
					char_src--;
					count--;
				}
			}
			return dest;

		}
		__forceinline  void* memset(void* dest, char c, unsigned int len)
		{
			unsigned int i;
			unsigned int fill;
			unsigned int chunks = len / sizeof(fill);
			char* char_dest = (char*)dest;
			unsigned int* uint_dest = (unsigned int*)dest;
			fill = (c << 24) + (c << 16) + (c << 8) + c;

			for (i = len; i > chunks * sizeof(fill); i--) {
				char_dest[i - 1] = c;
			}

			for (i = chunks; i > 0; i--) {
				uint_dest[i - 1] = fill;
			}

			return dest;
		}


	}
	namespace string
	{


		__forceinline  int tolower(int c)
		{
			if (c >= 'A' && c <= 'Z') return c - 'A' + 'a';
			return c;
		}

		__forceinline  int wtolower(int c)
		{
			if (c >= L'A' && c <= L'Z') return c - L'A' + L'a';
			if (c >= L'�' && c <= L'�') return c - L'�' + L'�';
			if (c == L'�') return L'�';
			return c;
		}

		__forceinline   int strlen(const char* string)
		{
			int cnt = 0;
			if (string)
			{
				for (; *string != 0; ++string) ++cnt;
			}
			return cnt;
		}

		__forceinline  int strcmp(const char* cs, const char* ct)
		{
			if (cs && ct)
			{
				while (*cs == *ct)
				{
					if (*cs == 0 && *ct == 0) return 0;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return *cs - *ct;
			}
			return -1;
		}


		__forceinline  int stricmp(const char* cs, const char* ct)
		{
			if (cs && ct)
			{
				while (tolower(*cs) == tolower(*ct))
				{
					if (*cs == 0 && *ct == 0) return 0;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return tolower(*cs) - tolower(*ct);
			}
			return -1;
		}





		__forceinline  int wstrlen(const wchar_t* string)
		{
			int cnt = 0;
			if (string)
			{
				for (; *string != 0; ++string) ++cnt;
			}
			return cnt;
		}


		__forceinline  const char* strstr(char const* _Str, char const* _SubStr)
		{
			const char* bp = _SubStr;
			const char* back_pos;
			while (*_Str != 0 && _Str != 0 && _SubStr != 0)
			{
				back_pos = _Str;
				while (tolower(*back_pos++) == tolower(*_SubStr++))
				{
					if (*_SubStr == 0)
					{
						return (char*)(back_pos - strlen(bp));
					}
				}
				++_Str;
				_SubStr = bp;
			}
			return 0;
		}

		__forceinline  int wstrcmp(const wchar_t* cs, const wchar_t* ct)
		{
			if (cs && ct)
			{
				while (*cs == *ct)
				{
					if (*cs == 0 && *ct == 0) return 0;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return *cs - *ct;
			}
			return -1;
		}

		__forceinline  int wstricmp(const wchar_t* cs, const wchar_t* ct)
		{
			if (cs && ct)
			{
				while (wtolower(*cs) == wtolower(*ct))
				{
					if (*cs == 0 && *ct == 0) return 0;
					if (*cs == 0 || *ct == 0) break;
					cs++;
					ct++;
				}
				return wtolower(*cs) - wtolower(*ct);
			}
			return -1;
		}


		__forceinline  wchar_t* wstrstr(const wchar_t* s, const wchar_t* find)
		{
			wchar_t c, sc;
			if ((c = *find++) != 0)
			{
				do
				{
					do
					{
						if ((sc = *s++) == 0)
							return 0;
					} while (sc != c);
				} while (wstricmp(s, find) != 0);
				s--;
			}
			return (wchar_t*)s;
		}
		__forceinline  wchar_t* wstrset(wchar_t* szToFill, int szFill)
		{
			wchar_t* t = szToFill;
			while (*szToFill != 0)
			{
				*szToFill = szFill;
				szToFill++;
			}
			return t;
		}
		__forceinline  wchar_t* wstrnset(wchar_t* szToFill, int szFill, unsigned __int64 sizeMaxFill)
		{
			wchar_t* t = szToFill;
			int i = 0;
			while (*szToFill != 0 && i < (int)sizeMaxFill)
			{
				*szToFill = szFill;
				szToFill++;
				i++;
			}
			return t;
		}
		__forceinline  wchar_t* wstrrev(wchar_t* s)
		{
			wchar_t a, * b, * e;
			b = e = s;
			while (*e) e++;
			e--;
			while (b < e)
			{
				a = *b;
				*b = *e;
				*e = a;
				b++;
				e--;
			}
			return s;
		}

		__forceinline  bool iswdigit(wchar_t c) { return c >= L'0' && c <= L'9'; }
		constexpr 	__forceinline  __int64 wtoi64(const wchar_t* nptr)
		{
			wchar_t* s = (wchar_t*)nptr;
			__int64 acc = 0;
			int neg = 0;
			if (nptr == 0) return 0;
			while (*s = L' ') s++;
			if (*s == L'-')
			{
				neg = 1;
				s++;
			}
			else if (*s == L'+') s++;
			while (iswdigit(*s))
			{
				acc = 10 * acc + (*s - L'0');
				s++;
			}
			if (neg) acc *= -1;
			return acc;
		}
		__forceinline  int wtoi(const wchar_t* nptr)
		{
			wchar_t* s = (wchar_t*)nptr;
			int acc = 0;
			int neg = 0;
			if (nptr == 0) return 0;
			while (*s = L' ') s++;
			if (*s == L'-')
			{
				neg = 1;
				s++;
			}
			else if (*s == L'+') s++;
			while (iswdigit(*s))
			{
				acc = 10 * acc + (*s - L'0');
				s++;
			}
			if (neg) acc *= -1;
			return acc;
		}
		__forceinline  wchar_t* itow(int number, wchar_t* destination, int base)
		{
			int count = 0;
			do
			{
				int digit = number % base;
				destination[count++] = (digit > 9) ? digit - 10 + L'A' : digit + L'0';
			} while ((number /= base) != 0);
			destination[count] = 0;
			int i;
			for (i = 0; i < count / 2; ++i)
			{
				wchar_t symbol = destination[i];
				destination[i] = destination[count - i - 1];
				destination[count - i - 1] = symbol;
			}
			return destination;
		}

		__forceinline char* strcat_a(char* dest, const char* src)
		{
			if ((dest == 0) || (src == 0))
				return dest;

			while (*dest != 0)
				dest++;

			while (*src != 0) {
				*dest = *src;
				dest++;
				src++;
			}

			*dest = 0;
			return dest;
		}

		__forceinline wchar_t* strcat_w(wchar_t* dest, const wchar_t* src)
		{
			if ((dest == 0) || (src == 0))
				return dest;

			while (*dest != 0)
				dest++;

			while (*src != 0) {
				*dest = *src;
				dest++;
				src++;
			}

			*dest = 0;
			return dest;
		}
	}
}