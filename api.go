/*
	api.go:  Serpent algorithm implementation in Go.

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

const (
	DIR_ENCRYPT = 0
	DIR_DECRYPT = 1
	MODE_ECB    = 1
	MODE_CBC    = 2
	MODE_CFB1   = 3
)

const (
	BAD_KEY_DIR                  = -1
	BAD_KEY_MAT                  = -2
	BAD_KEY_INSTANCE             = -3
	BAD_CIPHER_MODE              = -4
	BAD_CIPHER_STATE             = -5
	DECRYPTION_MISMATCH          = -7
	ENCRYPTION_MISMATCH          = -8
	BAD_HEX_DIGIT                = -9
	BAD_LENGTH                   = -10
	BAD_IV                       = -11
	BAD_NUMBER_OF_BITS_PROCESSED = -12
	BAD_INPUT                    = -13
)

const (
	MAX_KEY_SIZE = 64
	MAX_IV_SIZE  = 16
)

const OK = 1
const r = 32
const phi = uint(0x9e3779b9)
const MARKER = 0xff

const (
	MAX_XOR_TAPS_PER_BIT   = 7
	BITS_PER_BYTE          = 8
	BITS_PER_NIBBLE        = 4
	BYTES_PER_WORD         = 4
	WORDS_PER_BLOCK        = 4
	WORDS_PER_KEY          = 8
	BITS_PER_HEX_DIGIT     = BITS_PER_NIBBLE
	NIBBLES_PER_WORD       = (BITS_PER_WORD / BITS_PER_NIBBLE)
	BITS_PER_WORD          = (BITS_PER_BYTE * BYTES_PER_WORD)
	BYTES_PER_IV           = MAX_IV_SIZE
	BYTES_PER_BLOCK        = (BITS_PER_BLOCK / BITS_PER_BYTE)
	BYTES_PER_KEY_SCHEDULE = (BYTES_PER_WORD * WORDS_PER_KEY_SCHEDULE)
	HEX_DIGITS_PER_WORD    = (BITS_PER_WORD / BITS_PER_HEX_DIGIT)
	HEX_DIGITS_PER_BLOCK   = (HEX_DIGITS_PER_WORD * WORDS_PER_BLOCK)
	HEX_DIGITS_PER_KEY     = (HEX_DIGITS_PER_WORD * WORDS_PER_KEY)
	BITS_PER_BLOCK         = (BITS_PER_WORD * WORDS_PER_BLOCK)
	WORDS_PER_IV           = (BYTES_PER_IV / BYTES_PER_WORD)
	BITS_PER_KEY           = (BITS_PER_WORD * WORDS_PER_KEY)
	WORDS_PER_KEY_SCHEDULE = ((r + 1) * WORDS_PER_BLOCK)
	BITS_PER_SHORTEST_KEY  = 128
	BITS_PER_KEY_STEP      = 64
	OUTER_LOOP_MAX         = 400
	INNER_LOOP_MAX         = 10000
	MAX_CHARS_PER_LINE     = 80
)

// type permutationTable [BITS_PER_BLOCK]int
// type xorTable [BITS_PER_BLOCK][MAX_XOR_TAPS_PER_BIT + 1]byte
// type keySchedule [r + 1][WORDS_PER_BLOCK]uint32
// type Block [WORDS_PER_BLOCK]uint32
// type Key [WORDS_PER_KEY]uint32

func newKeySchedule() [][]uint {
	k := make([][]uint, r+1)
	for i := 0; i < (r + 1); i++ {
		k[i] = make([]uint, WORDS_PER_BLOCK)
	}
	return k
}

type keyInstance struct {
	direction   byte
	keyLen      int
	keyMaterial []byte
	userKey     []uint
	KHat        [][]uint
}

func newKeyInstance() *keyInstance {
	ki := new(keyInstance)
	ki.keyMaterial = make([]byte, MAX_KEY_SIZE)
	ki.userKey = make([]uint, WORDS_PER_KEY)
	ki.KHat = newKeySchedule()
	return ki
}

type cipherInstance struct {
	mode      byte
	iv        [MAX_IV_SIZE]byte
	blockSize int
}

func newCipherInstance() *cipherInstance {
	ci := new(cipherInstance)
	return ci
}
