/*
	helpers.go:  Serpent algorithm implementation in Go.

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
	"fmt"
	"log"
)

func NewBlockSlice() []uint {
	return make([]uint, WORDS_PER_BLOCK)
}

func blockStr(x []uint) string {
	return fmt.Sprintf("[%x, %x, %x, %x]", x[0], x[1], x[2], x[3])
}

func keyScheduleAreEqual(k1, k2 [][]uint) bool {
	if len(k1) != (r+1) || len(k2) != (r+1) {
		log.Fatal("Invalid size of key schedule.")
	}
	for i := 0; i < len(k1); i++ {
		v1 := k1[i]
		v2 := k2[i]
		if len(v1) != WORDS_PER_BLOCK || len(v2) != WORDS_PER_BLOCK {
			log.Fatal("Invalid size of element of key schedule.")
		}
		for j := 0; j < WORDS_PER_BLOCK; j++ {
			if v1[j] != v2[j] {
				return false
			}
		}
	}
	return true
}

func printKeySchedule(w [][]uint) {
	fmt.Printf("{\n")
	for i := 0; i < len(w); i++ {
		fmt.Printf("\t{")
		b := w[i]
		for j := 0; j < len(b); j++ {
			fmt.Printf("0x%x,", b[j])
		}
		fmt.Printf("},\n")
	}
	fmt.Printf("\n}\n")
}

func byteSlicesAreEqual(b1, b2 []byte) bool {
	n1 := len(b1)
	n2 := len(b2)
	if n1 != n2 {
		return false
	}
	for i := 0; i < n1; i++ {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

func slicesAreEqual(b1, b2 []uint) bool {
	n1 := len(b1)
	n2 := len(b2)
	if n1 != n2 {
		return false
	}
	for i := 0; i < n1; i++ {
		if b1[i] != b2[i] {
			return false
		}
	}
	return true
}

func slicesAreEqual2(b1, b2 [][]uint) bool {
	n1 := len(b1)
	n2 := len(b2)
	if n1 != n2 {
		return false
	}
	for i := 0; i < n1; i++ {
		sb1 := b1[i]
		sb2 := b2[i]
		sn1 := len(sb1)
		sn2 := len(sb2)
		if sn1 != sn2 {
			return false
		}
		for j := 0; j < sn1; j++ {
			if sb1[j] != sb2[j] {
				return false
			}
		}
	}
	return true
}

func bytesToUint32(data []byte) uint32 {
	retv := uint32(0)
	retv = (retv << 8) + uint32(data[3])
	retv = (retv << 8) + uint32(data[2])
	retv = (retv << 8) + uint32(data[1])
	retv = (retv << 8) + uint32(data[0])
	return retv
}

func uint32ToBytes(value uint32) []byte {
	buffer := make([]byte, 4, 4)
	buffer[0] = byte(value & 0xff)
	value = (value >> 8)
	buffer[1] = byte(value & 0xff)
	value = (value >> 8)
	buffer[2] = byte(value & 0xff)
	value = (value >> 8)
	buffer[3] = byte(value & 0xff)
	return buffer
}

// 4 * uint32 = 16 bajtow (128 bitow)
func bytesToBlock(data []byte) []uint {
	v1 := uint(bytesToUint32(data[:4]))
	v2 := uint(bytesToUint32(data[4:8]))
	v3 := uint(bytesToUint32(data[8:12]))
	v4 := uint(bytesToUint32(data[12:16]))
	return []uint{v1, v2, v3, v4}
}

func blockToBytes(data []uint) []byte {
	buffer := uint32ToBytes(uint32(data[0]))
	buffer = append(buffer, uint32ToBytes(uint32(data[1]))...)
	buffer = append(buffer, uint32ToBytes(uint32(data[2]))...)
	buffer = append(buffer, uint32ToBytes(uint32(data[3]))...)
	return buffer
}
