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

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
)

//
// isxdigit
//
func isxdigit(c byte) bool {
	if c >= '0' && c <= '9' {
		return true
	}
	if c >= 'a' && c <= 'f' {
		return true
	}
	if c >= 'A' && c <= 'F' {
		return true
	}
	return false
}

//
// checkHexNumber
//
func checkHexNumber(s []byte) int {
	i := 0
	for _, c := range s {
		if isxdigit(c) {
			i += 1
		} else {
			return -1
		}

	}
	return i
}

//
// hex
//
func hex(n int) byte {
	if n >= 0 && n <= 9 {
		return byte(n + '0')
	}
	if n >= 10 && n <= 15 {
		return byte(n - 10 + 'a')
	}
	log.Fatalf("ERROR: %d can't be converted to a hex digit", n)
	return 0
}

//
// stringToWords - zamiana tablicy 'byte' na tablice 'uit32'
//
func stringToWords(s []byte, w []uint, words int) int {
	digits := checkHexNumber(s)
	if digits < 0 {
		log.Println("ERROR. Bad hex digit.")
		return BAD_HEX_DIGIT
	}
	if (digits > (words * HEX_DIGITS_PER_WORD)) || ((digits % HEX_DIGITS_PER_WORD) > 0) {
		return BAD_LENGTH
	}

	highestWordWithData := digits / HEX_DIGITS_PER_WORD
	for i := 0; i < highestWordWithData; i++ {
		w[i] = 0
	}

	for i := 0; i < highestWordWithData; i++ {
		digits -= HEX_DIGITS_PER_WORD
		idx0 := int(digits)
		idx1 := int(digits + HEX_DIGITS_PER_WORD)
		n, err := strconv.ParseUint(string(s[idx0:idx1]), 16, 32)
		if err != nil {
			log.Fatal("Cant't parse hex string to uint:", err)
		}
		w[i] = uint(n)
	}
	return OK
}

func stringAsWords(textInHex string) ([]uint, error) {
	textBytes := []byte(textInHex)
	digits := checkHexNumber(textBytes)
	if digits < 0 {
		return nil, errors.New("ERROR.stringAsWords: Bad hex digit.")
	}
	if (digits % HEX_DIGITS_PER_WORD) > 0 {
		return nil, errors.New("ERROR.stringAsWords: bad length")
	}

	highestWordWithData := digits / HEX_DIGITS_PER_WORD
	buffer := make([]uint, highestWordWithData)

	for i := 0; i < highestWordWithData; i++ {
		digits -= HEX_DIGITS_PER_WORD
		idx0 := int(digits)
		idx1 := int(digits + HEX_DIGITS_PER_WORD)
		n, err := strconv.ParseUint(string(textBytes[idx0:idx1]), 16, 32)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Error.stringAsWords: Cant't parse hex string to uint: %v", err))
		}
		buffer[i] = uint(n)
	}
	return buffer, nil
}

// wordsAsString
// convert array of uints to big-endian hex format
func wordsAsString(words []uint) string {
	n := len(words)
	var sbuilder strings.Builder
	sbuilder.Grow(n * HEX_DIGITS_PER_WORD)
	for i := (n - 1); i >= 0; i-- {
		fmt.Fprintf(&sbuilder, "%08x", words[i])
	}
	return sbuilder.String()
}
