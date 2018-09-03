/*
	reference

 	reference.go:  Serpent algorithm implementation in Go.

	Based on reference implementation in C from https://www.cl.cam.ac.uk/~rja14/serpent.html

	Copyright (C) 2018 by Piotr Pszczółkowski (piotr@beesoft.pl)

	This library is free software; you can redistribute it and/or
	modify it under the terms of the GNU Lesser General Public
	License as published by the Free Software Foundation; either
	version 2.1 of the License, or (at your option) any later version.
	This library is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
	Lesser General Public License for more details.
	You should have received a copy of the GNU Lesser General Public
	License along with this library; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	If you require this code under a license other than LGPL, please ask.
*/
package serpent

import (
	"log"
)

func setBit(x []uint, p int, v byte) {
	const One = uint(0x1)
	if v > 0 {
		x[p/BITS_PER_WORD] |= (One << (uint(p) % BITS_PER_WORD))
	} else {
		x[p/BITS_PER_WORD] &= ^(One << (uint(p) % BITS_PER_WORD))
	}
}

func getBit(x []uint, p int) byte {
	n := uint(p) % BITS_PER_WORD
	return byte(x[p/BITS_PER_WORD] & (uint(0x1) << n) >> n)
}

func getBitFromWord(x uint, p int) byte {
	return byte((x & (uint(0x1) << uint(p))) >> uint(p))
}

func getBitFromNibble(x byte, p int) byte {
	return ((x & (0x1 << uint(p))) >> uint(p))
}

func getNibble(x uint, p int) byte {
	return byte(0xf & (x >> uint(p*BITS_PER_NIBBLE)))
}

func makeNibble(b0, b1, b2, b3 byte) byte {
	return (b0 | (b1 << 1) | (b2 << 2) | (b3 << 3))
}

func xorBlock(in1, in2, out []uint) {
	for i := 0; i < WORDS_PER_BLOCK; i++ {
		out[i] = in1[i] ^ in2[i]
	}
}

func applyPermutation(t []int, in, out []uint) {
	for i := 0; i < WORDS_PER_BLOCK; i++ {
		out[i] = 0
	}
	for i := 0; i < BITS_PER_BLOCK; i++ {
		setBit(out, i, getBit(in, t[i]))
	}
}

func applyXorTable(t [][]byte, in, out []uint) {
	for i := 0; i < BITS_PER_BLOCK; i++ {
		b := byte(0)
		for j := 0; t[i][j] != MARKER; j++ {
			b ^= getBit(in, int(t[i][j]))
		}
		setBit(out, i, b)
	}
}

func S(box int, input byte) byte {
	return SBox[box][input]
}

func SInverse(box int, output byte) byte {
	return SBoxInverse[box][output]
}

func rotateLeft(x uint, p int) uint {
	return ((x << uint(p)) | (x >> (BITS_PER_WORD - uint(p)))) & 0xffffffff
}

func shortToLongKey(key []uint, bitsInShortKey int) {
	key[bitsInShortKey/BITS_PER_WORD] |= ((uint(0x1)) << uint(bitsInShortKey%BITS_PER_WORD))
}

func IP(input, output []uint) {
	// IP - Initial Permutation
	applyPermutation(IPTable, input, output)
}

func FP(input, output []uint) {
	// FP - Final Permutation
	applyPermutation(FPTable, input, output)
}

func IPInverse(output, input []uint) {
	applyPermutation(FPTable, output, input)
}

func FPInverse(output, input []uint) {
	applyPermutation(IPTable, output, input)
}

func SHat(box int, input, output []uint) {
	for w := 0; w < WORDS_PER_BLOCK; w++ {
		output[w] = 0
		for n := 0; n < NIBBLES_PER_WORD; n++ {
			output[w] |= (uint(S(box, getNibble(input[w], n))) << uint(n*BITS_PER_NIBBLE))
		}
	}
}

func SHatInverse(box int, output, input []uint) {
	for w := 0; w < WORDS_PER_BLOCK; w++ {
		input[w] = 0
		for n := 0; n < NIBBLES_PER_WORD; n++ {
			input[w] |= (uint(SInverse(box, getNibble(output[w], n))) << uint(n*BITS_PER_NIBBLE))
		}
	}
}

func LT(input, output []uint) {
	applyXorTable(LTTable, input, output)
}

func LTInverse(output, input []uint) {
	applyXorTable(LTTableInverse, output, input)
}

func R(i int, BHati []uint, KHat [][]uint, BHatiPlus1 []uint) {
	xored := NewBlockSlice()
	SHati := NewBlockSlice()

	xorBlock(BHati, KHat[i], xored)
	SHat(i, xored, SHati)

	if 0 <= i && i <= (r-2) {
		LT(SHati, BHatiPlus1)
	} else if i == (r - 1) {
		xorBlock(SHati, KHat[r], BHatiPlus1)
	} else {
		log.Fatalf("ERROR: round %d is out of 0..%d range", i, r-1)
	}
}

func RInverse(i int, BHatiPlus1 []uint, KHat [][]uint, BHati []uint) {
	xored := NewBlockSlice()
	SHati := NewBlockSlice()

	if 0 <= i && i <= (r-2) {
		LTInverse(BHatiPlus1, SHati)
	} else if i == (r - 1) {
		xorBlock(BHatiPlus1, KHat[r], SHati)
	} else {
		log.Fatalf("ERROR: round %d is out of 0..%d range", i, r-1)
	}

	SHatInverse(i, SHati, xored)
	xorBlock(xored, KHat[i], BHati)
}

func makeSubkeysBitslice(userKey []uint, K [][]uint) {
	w := make(map[int]uint, 140)

	for i := -8; i < 0; i++ {
		w[i] = userKey[i+8]
	}
	for i := 0; i < 132; i++ {
		xor := w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ uint(i)
		w[i] = rotateLeft(xor, 11)
	}

	var k [132]uint
	var b0, b1, b2, b3 byte

	for i := 0; i < (r + 1); i++ {
		whichS := int((r + 3 - i) % r)
		k[0+4*i] = 0
		k[1+4*i] = 0
		k[2+4*i] = 0
		k[3+4*i] = 0
		for j := 0; j < 32; j++ {
			b0 = getBitFromWord(w[0+4*i], j)
			b1 = getBitFromWord(w[1+4*i], j)
			b2 = getBitFromWord(w[2+4*i], j)
			b3 = getBitFromWord(w[3+4*i], j)
			input := makeNibble(b0, b1, b2, b3)
			output := S(whichS, input)
			for l := 0; l < 4; l++ {
				k[l+4*i] |= (uint(getBitFromNibble(output, l)) << uint(j))
			}
		}

		for i := 0; i < 33; i++ {
			for j := 0; j < 4; j++ {
				K[i][j] = k[4*i+j]
			}
		}
	}
}

func makeSubkeys(userKey []uint, KHat [][]uint) {
	K := newKeySchedule()

	makeSubkeysBitslice(userKey, K[:])
	for i := 0; i < 33; i++ {
		IP(K[i], KHat[i])
	}
}

func encryptGivenKHat(plainText []uint, KHat [][]uint, cipherText []uint) {
	BHat := NewBlockSlice()

	IP(plainText, BHat)
	for i := 0; i < r; i++ {
		R(i, BHat, KHat, BHat)
	}
	FP(BHat, cipherText)
}

func decryptGivenKHat(cipherText []uint, KHat [][]uint, plainText []uint) {
	BHat := NewBlockSlice()

	FPInverse(cipherText, BHat)
	for i := (r - 1); i >= 0; i-- {
		RInverse(i, BHat, KHat, BHat)
	}
	IPInverse(BHat, plainText)
}
