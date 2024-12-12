#include <emmintrin.h>
#include <smmintrin.h>

void process_case_0(__m128i *prand, __m128i *prandex, const __m128i *pbuf, __m128i &acc, uint64_t selector) {
	const __m128i temp1 = _mm_load_si128(prandex);
	const __m128i temp2 = _mm_load_si128(&pbuf[(selector & 1) ? -1 : 1]);
	const __m128i add1 = _mm_xor_si128(temp1, temp2);
	const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
	acc = _mm_xor_si128(clprod1, acc);

	const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

	const __m128i temp12 = _mm_load_si128(prand);
	_mm_store_si128(prand, tempa2);

	const __m128i temp22 = _mm_load_si128(pbuf);
	const __m128i add12 = _mm_xor_si128(temp12, temp22);
	const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
	acc = _mm_xor_si128(clprod12, acc);

	const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
	const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
	_mm_store_si128(prandex, tempb2);
}

void process_case_4(__m128i *prand, __m128i *prandex, const __m128i *pbuf, __m128i &acc, uint64_t selector) {
	const __m128i temp1 = _mm_load_si128(prand);
	const __m128i temp2 = _mm_load_si128(pbuf);
	const __m128i add1 = _mm_xor_si128(temp1, temp2);
	const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
	acc = _mm_xor_si128(clprod1, acc);
	const __m128i clprod2 = _mm_clmulepi64_si128(temp2, temp2, 0x10);
	acc = _mm_xor_si128(clprod2, acc);

	const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

	const __m128i temp12 = _mm_load_si128(prandex);
	_mm_store_si128(prandex, tempa2);

	const __m128i temp22 = _mm_load_si128(&pbuf[(selector & 1) ? -1 : 1]);
	const __m128i add12 = _mm_xor_si128(temp12, temp22);
	acc = _mm_xor_si128(add12, acc);

	const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
	_mm_store_si128(prand, _mm_xor_si128(tempb1, temp12));
}

void process_case_8(__m128i *prand, __m128i *prandex, const __m128i *pbuf, __m128i &acc, uint64_t selector) {
	const __m128i temp1 = _mm_load_si128(prandex);
	const __m128i temp2 = _mm_load_si128(pbuf);
	const __m128i add1 = _mm_xor_si128(temp1, temp2);
	acc = _mm_xor_si128(add1, acc);

	const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

	const __m128i temp12 = _mm_load_si128(prand);
	_mm_store_si128(prand, tempa2);

	const __m128i temp22 = _mm_load_si128(&pbuf[(selector & 1) ? -1 : 1]);
	const __m128i add12 = _mm_xor_si128(temp12, temp22);
	const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
	acc = _mm_xor_si128(clprod12, acc);
	const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
	acc = _mm_xor_si128(clprod22, acc);

	const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
	const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
	_mm_store_si128(prandex, tempb2);
}

void process_case_0c(__m128i *prand, __m128i *prandex, const __m128i *pbuf, __m128i &acc, uint64_t selector) {
	const __m128i temp1 = _mm_load_si128(prand);
	const __m128i temp2 = _mm_load_si128(&pbuf[(selector & 1) ? -1 : 1]);
	const __m128i add1 = _mm_xor_si128(temp1, temp2);

	// cannot be zero here
	const int32_t divisor = (uint32_t)selector;

	acc = _mm_xor_si128(add1, acc);

	const int64_t dividend = _mm_cvtsi128_si64(acc);
	const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
	acc = _mm_xor_si128(modulo, acc);

	const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp1);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp1);

	if (dividend & 1) {
		const __m128i temp12 = _mm_load_si128(prandex);
		_mm_store_si128(prandex, tempa2);

		const __m128i temp22 = _mm_load_si128(pbuf);
		const __m128i add12 = _mm_xor_si128(temp12, temp22);
		const __m128i clprod12 = _mm_clmulepi64_si128(add12, add12, 0x10);
		acc = _mm_xor_si128(clprod12, acc);
		const __m128i clprod22 = _mm_clmulepi64_si128(temp22, temp22, 0x10);
		acc = _mm_xor_si128(clprod22, acc);

		const __m128i tempb1 = _mm_mulhrs_epi16(acc, temp12);
		const __m128i tempb2 = _mm_xor_si128(tempb1, temp12);
		_mm_store_si128(prand, tempb2);
	} else {
		_mm_store_si128(prand, _mm_load_si128(prandex));
		_mm_store_si128(prandex, tempa2);
		acc = _mm_xor_si128(_mm_load_si128(pbuf), acc);
	}
}

void process_case_10(__m128i *prand, __m128i *prandex, const __m128i *pbuf, __m128i &acc, uint64_t selector) {
	// a few AES operations
	const __m128i *rc = prand;
	__m128i tmp;

	__m128i temp1 = _mm_load_si128(&pbuf[(selector & 1) ? -1 : 1]);
	__m128i temp2 = _mm_load_si128(pbuf);

	AES2(temp1, temp2, 0);
	MIX2(temp1, temp2);

	AES2(temp1, temp2, 4);
	MIX2(temp1, temp2);

	AES2(temp1, temp2, 8);
	MIX2(temp1, temp2);

	acc = _mm_xor_si128(temp2, _mm_xor_si128(temp1, acc));

	const __m128i tempa1 = _mm_load_si128(prand);
	const __m128i tempa2 = _mm_mulhrs_epi16(acc, tempa1);

	_mm_store_si128(prand, _mm_load_si128(prandex));
	_mm_store_si128(prandex, _mm_xor_si128(tempa1, tempa2));
}

void process_case_14(__m128i *prand, __m128i *prandex, const __m128i *pbuf, __m128i &acc, uint64_t selector) {
	// we'll just call this one the monkins loop, inspired by Chris - modified to cast to uint64_t on shift for more variability in the loop
	const __m128i *buftmp = &pbuf[(selector & 1) ? -1 : 1];
	__m128i tmp; // used by MIX2

	uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
	__m128i *rc = prand;
	uint64_t aesroundoffset = 0;
	__m128i onekey;

	do
	{
		if (selector & (((uint64_t)0x10000000) << rounds)) {
			//onekey = _mm_load_si128(rc++);
			const __m128i temp2 = _mm_load_si128(rounds & 1 ? pbuf : buftmp);
			const __m128i add1 = _mm_xor_si128(rc[0], temp2); rc++;
			const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
			acc = _mm_xor_si128(clprod1, acc);
		} else {
			onekey = _mm_load_si128(rc++);
			__m128i temp2 = _mm_load_si128(rounds & 1 ? buftmp : pbuf);
			AES2(onekey, temp2, aesroundoffset);
			aesroundoffset += 4;
			MIX2(onekey, temp2);
			acc = _mm_xor_si128(onekey, acc);
			acc = _mm_xor_si128(temp2, acc);
		}
	} while (rounds--);

	const __m128i tempa1 = _mm_load_si128(prand);
	const __m128i tempa2 = _mm_mulhrs_epi16(acc, tempa1);
	const __m128i tempa3 = _mm_xor_si128(tempa1, tempa2);

	const __m128i tempa4 = _mm_load_si128(prandex);
	_mm_store_si128(prandex, tempa3);
	_mm_store_si128(prand, tempa4);
}

void process_case_18(__m128i *prand, __m128i *prandex, const __m128i *pbuf, __m128i &acc, uint64_t selector) {
	const __m128i *buftmp = &pbuf[(selector & 1) ? -1 : 1];
	__m128i tmp; // used by MIX2

	uint64_t rounds = selector >> 61; // loop randomly between 1 and 8 times
	__m128i *rc = prand;
	__m128i onekey;

	do
	{
		if (selector & (((uint64_t)0x10000000) << rounds)) {
			//	onekey = _mm_load_si128(rc++);
			const __m128i temp2 = _mm_load_si128(rounds & 1 ? pbuf : buftmp);
			onekey = _mm_xor_si128(rc[0], temp2); rc++;
			// cannot be zero here, may be negative
			const int32_t divisor = (uint32_t)selector;
			const int64_t dividend = _mm_cvtsi128_si64(onekey);
			const __m128i modulo = _mm_cvtsi32_si128(dividend % divisor);
			acc = _mm_xor_si128(modulo, acc);
		} else {
			//	onekey = _mm_load_si128(rc++);
			__m128i temp2 = _mm_load_si128(rounds & 1 ? buftmp : pbuf);
			const __m128i add1 = _mm_xor_si128(rc[0], temp2); rc++;
			onekey = _mm_clmulepi64_si128(add1, add1, 0x10);
			const __m128i clprod2 = _mm_mulhrs_epi16(acc, onekey);
			acc = _mm_xor_si128(clprod2, acc);
		}
	} while (rounds--);

	const __m128i tempa3 = _mm_load_si128(prandex);

	_mm_store_si128(prandex, onekey);
	_mm_store_si128(prand, _mm_xor_si128(tempa3, acc));
	//	_mm_store_si128(prand, tempa4);
}

void process_case_1c(__m128i *prand, __m128i *prandex, const __m128i *pbuf, __m128i &acc, uint64_t selector) {
	const __m128i temp1 = _mm_load_si128(pbuf);
	const __m128i temp2 = _mm_load_si128(prandex);
	const __m128i add1 = _mm_xor_si128(temp1, temp2);
	const __m128i clprod1 = _mm_clmulepi64_si128(add1, add1, 0x10);
	acc = _mm_xor_si128(clprod1, acc);

	const __m128i tempa1 = _mm_mulhrs_epi16(acc, temp2);
	const __m128i tempa2 = _mm_xor_si128(tempa1, temp2);

	const __m128i tempa3 = _mm_load_si128(prand);
	_mm_store_si128(prand, tempa2);

	acc = _mm_xor_si128(tempa3, acc);
	const __m128i temp4 = _mm_load_si128(&pbuf[(selector & 1) ? -1 : 1]);
	acc = _mm_xor_si128(temp4, acc);
	const __m128i tempb1 = _mm_mulhrs_epi16(acc, tempa3);
	*prandex = _mm_xor_si128(tempb1, tempa3);
}
