/*
	aux.go:  Serpent algorithm implementation in Go.

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

func makeKey(key *keyInstance, keyLen int, keyMaterial []byte) int {
	if (keyLen % BITS_PER_WORD) > 0 {
		return BAD_KEY_MAT
	}
	if keyLen > BITS_PER_KEY || keyLen < BITS_PER_SHORTEST_KEY {
		return BAD_KEY_MAT
	}
	key.keyLen = keyLen

	if (keyMaterial != nil) && (len(keyMaterial) > 0) {
		key.keyMaterial = keyMaterial
	}
	if stringToWords(key.keyMaterial, key.userKey, WORDS_PER_KEY) != OK {
		return BAD_KEY_MAT
	}
	if keyLen < BITS_PER_KEY {
		shortToLongKey(key.userKey, keyLen)
	}
	makeSubkeys(key.userKey, key.KHat)
	return OK
}

func blockEncrypt(key *keyInstance, input, output []uint) {
	encryptGivenKHat(input, key.KHat, output)
}

func blockDecrypt(key *keyInstance, input, output []uint) {
	decryptGivenKHat(input, key.KHat, output)
}
