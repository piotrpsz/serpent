/*
	reference.go:  Unit tests of Serpent algorithm components.

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

// for test run command: go test -v

package serpent

import (
	"fmt"
	"testing"
)

//
// blockDecrypt
//
func TestBlockDecrypt(t *testing.T) {
	var userKey []byte
	var cipherText, expectedPlainText string
	var expectedPlainTextAsBlock []uint

	userKey = []byte("abcdef1234567890abcdef1234567890")
	cipherText = "1a72aa13935f45f22094272fc2960a26"
	expectedPlainText = "5206d69ccbc02d5e972d0ec9b077d3f9"
	expectedPlainTextAsBlock = []uint{0xb077d3f9, 0x972d0ec9, 0xcbc02d5e, 0x5206d69c}

	cipherTextAsBlock, err := StringAsWords(cipherText)
	if err != nil {
		t.Error(err)
	}
	keyInstance := NewKeyInstance()
	output := NewBlockSlice()

	MakeKey(keyInstance, len(userKey)*4, userKey)
	BlockDecrypt(keyInstance, cipherTextAsBlock, output)
	if !slicesAreEqual(output, expectedPlainTextAsBlock) {
		t.Errorf("ERROR. Invalid cipher text as block.\n\tIs:     %v,\n\tshould: %v\n", blockStr(output), blockStr(expectedPlainTextAsBlock))
	}
	plainText := WordsAsString(output)
	if plainText != expectedPlainText {
		t.Errorf("ERROR. Invalid decrypted text.\n\tIs      %s,\n\tshould: %s.", plainText, expectedPlainText)
	}
	// ---------------------------------------------------------------
	userKey = []byte("1234567890abcdef1234567890abcdef")
	cipherText = "1a72aa13935f45f22094272fc2960a26"
	expectedPlainText = "1f356dbd0829ffb383cbf6629551dbd7"
	expectedPlainTextAsBlock = []uint{0x9551dbd7, 0x83cbf662, 0x829ffb3, 0x1f356dbd}

	cipherTextAsBlock, err = StringAsWords(cipherText)
	if err != nil {
		t.Error(err)
	}
	keyInstance = NewKeyInstance()
	output = NewBlockSlice()

	MakeKey(keyInstance, len(userKey)*4, userKey)
	BlockDecrypt(keyInstance, cipherTextAsBlock, output)
	if !slicesAreEqual(output, expectedPlainTextAsBlock) {
		t.Errorf("ERROR. Invalid cipher text as block.\n\tIs:     %v,\n\tshould: %v\n", blockStr(output), blockStr(expectedPlainTextAsBlock))
	}
	plainText = WordsAsString(output)
	if plainText != expectedPlainText {
		t.Errorf("ERROR. Invalid decrypted text.\n\tIs      %s,\n\tshould: %s.", plainText, expectedPlainText)
	}
	//---------------------------------------------------------------------
	userKey = []byte("1234567890abcdef1234567890abcdef")
	cipherText = "0a26aa13935f45f22094272fc2961a72"
	expectedPlainText = "b442679e3e38d3101421537f193e2e0f"
	expectedPlainTextAsBlock = []uint{0x193e2e0f, 0x1421537f, 0x3e38d310, 0xb442679e}

	cipherTextAsBlock, err = StringAsWords(cipherText)
	if err != nil {
		t.Error(err)
	}
	keyInstance = NewKeyInstance()
	output = NewBlockSlice()

	MakeKey(keyInstance, len(userKey)*4, userKey)
	BlockDecrypt(keyInstance, cipherTextAsBlock, output)
	if !slicesAreEqual(output, expectedPlainTextAsBlock) {
		t.Errorf("ERROR. Invalid cipher text as block.\n\tIs:     %v,\n\tshould: %v\n", blockStr(output), blockStr(expectedPlainTextAsBlock))
	}
	plainText = WordsAsString(output)
	if plainText != expectedPlainText {
		t.Errorf("ERROR. Invalid decrypted text.\n\tIs      %s,\n\tshould: %s.", plainText, expectedPlainText)
	}
}

//
// blockEncrypt
//
func TestBlockEncrypt(t *testing.T) {
	var userKey []byte
	var plainText, expectedCipherText string
	var expectedCipherTextAsBlock []uint

	userKey = []byte("1234567890abcdef1234567890abcdef")
	plainText = "1F356DBD0829FFB383CBF6629551DBD7"
	expectedCipherText = "1a72aa13935f45f22094272fc2960a26"
	expectedCipherTextAsBlock = []uint{0xc2960a26, 0x2094272f, 0x935f45f2, 0x1a72aa13}

	plainTextAsBlock, err := StringAsWords(plainText)
	if err != nil {
		t.Error(err)
	}
	keyInstance := NewKeyInstance()
	output := NewBlockSlice()

	MakeKey(keyInstance, len(userKey)*4, userKey)
	BlockEncrypt(keyInstance, plainTextAsBlock, output)
	if !slicesAreEqual(output, expectedCipherTextAsBlock) {
		t.Errorf("Invalid cipher text as block.")
	}
	cipherText := WordsAsString(output)
	if cipherText != expectedCipherText {
		t.Errorf("ERROR. Invalid encypted text. Is %s, should: %s.", cipherText, expectedCipherText)
	}
	//---------------------------------------------------------------
	userKey = []byte("1234567890abcdef1234567890abcdef")
	plainText = "383cbf6629551dbd71f356dbd0829ffb"
	expectedCipherText = "4959d294e1c204dcd2e085e14936da62"
	expectedCipherTextAsBlock = []uint{0x4936da62, 0xd2e085e1, 0xe1c204dc, 0x4959d294}

	plainTextAsBlock, err = StringAsWords(plainText)
	if err != nil {
		t.Error(err)
	}
	keyInstance = NewKeyInstance()
	output = NewBlockSlice()

	MakeKey(keyInstance, len(userKey)*4, userKey)
	BlockEncrypt(keyInstance, plainTextAsBlock, output)
	if !slicesAreEqual(output, expectedCipherTextAsBlock) {
		t.Errorf("Invalid cipher text as block.")
	}
	cipherText = WordsAsString(output)
	if cipherText != expectedCipherText {
		t.Errorf("ERROR. Invalid cipher text. Is %s, should: %s.", cipherText, expectedCipherText)
	}
	//----------------------------------------------------------------
	userKey = []byte("abcdef1234567890abcdef1234567890")
	plainText = "383cbf6629551dbd71f356dbd0829ffb"
	expectedCipherText = "d93dcd724d148939e2b82183d39981ce"
	expectedCipherTextAsBlock = []uint{0xd39981ce, 0xe2b82183, 0x4d148939, 0xd93dcd72}

	plainTextAsBlock, err = StringAsWords(plainText)
	if err != nil {
		t.Error(err)
	}
	keyInstance = NewKeyInstance()
	output = NewBlockSlice()

	MakeKey(keyInstance, len(userKey)*4, userKey)
	BlockEncrypt(keyInstance, plainTextAsBlock, output)
	if !slicesAreEqual(output, expectedCipherTextAsBlock) {
		t.Errorf("Invalid cipher text as block.")
	}
	cipherText = WordsAsString(output)
	if cipherText != expectedCipherText {
		t.Errorf("ERROR. Invalid cipher text. Is %s, should: %s.", cipherText, expectedCipherText)
	}
}

//
// makeKey
//
func TestMakeKey(t *testing.T) {
	var expectedUserKey []uint
	var expectedKHat [][]uint
	var userKey []byte

	keyInstance := NewKeyInstance()
	userKey = []byte("1234567890abcdef1234567890abcdef")
	expectedUserKey = []uint{0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678, 0x1, 0x0, 0x0, 0x0}
	expectedKHat = [][]uint{
		{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xbfc2c981},
		{0xfc4e68a5, 0x4cde80ee, 0x12735620, 0x208085cf},
		{0x7c96dfd9, 0x68102a61, 0x68575b0b, 0xd36be69},
		{0x2550b1e5, 0xd48b78aa, 0x4f47d821, 0xa41b2c7d},
		{0x68166ba0, 0x27da1f2c, 0x4fda779e, 0x3d817285},
		{0x8ee7ad56, 0x8d99ec02, 0x7c7324a9, 0xcb96d096},
		{0x53cefcf, 0xf0c37e2, 0x4f8e28ef, 0xd1fddd33},
		{0x8d11eb9e, 0xee74f9a1, 0x7a11a4ef, 0x3498e317},
		{0xf99365df, 0x598cb1b1, 0xf273142, 0x66e31d0b},
		{0x78c6d97f, 0xd0b8b4ef, 0x513454ae, 0x4bbea9c},
		{0xd705f92e, 0x57f9d950, 0x72231b84, 0xdd49258c},
		{0x109389d4, 0x8148581e, 0xcf443968, 0x249d572b},
		{0x2153c368, 0xe49698c2, 0x6ee80750, 0xfb3d39db},
		{0x4c0271d8, 0xba98a888, 0xa12f22e5, 0xc307b3b2},
		{0x4aac741, 0xd6faddd0, 0x3fc3b56a, 0x217c351a},
		{0xc60768fe, 0xa4fa111, 0x5faa767c, 0x94469433},
		{0x30adc32d, 0x7a56cc1, 0xca99a262, 0x3f39c983},
		{0xa779857b, 0x47015b15, 0x5ad83e06, 0xbd0f6409},
		{0x8bf45ffc, 0xa1d28d59, 0x7d840bfa, 0x6035f954},
		{0x278d0715, 0x90e3b9d0, 0xfa00e6fb, 0x6785624c},
		{0xc4bb27c9, 0x676602cb, 0xa2c810fa, 0x51d5aaa1},
		{0xbe41ac4f, 0x2753c6b3, 0x4fdad542, 0xb2517367},
		{0x2bd9d97a, 0x84fb0afd, 0x238966d0, 0xd636c279},
		{0xd215d9f2, 0x7b456e98, 0x779d2af0, 0x51dd5d52},
		{0x3e9efbd6, 0xd07f1826, 0xff6448ee, 0xe3e6d0c7},
		{0xe564ef2f, 0x6f65cb47, 0x1b19ad77, 0xbf77a829},
		{0xf008de22, 0xd78be6fc, 0x385b51b0, 0x1bb35b64},
		{0x137e1e55, 0xbee22391, 0xda1584e8, 0xb1b4c4c7},
		{0xedd74591, 0x65f47aa4, 0x620e0111, 0x1c2f7b8e},
		{0x9db49e0b, 0xa2d54157, 0xdc65fd49, 0x3ed8856f},
		{0xa48626c1, 0xb80177f5, 0x92966732, 0x7bd6ded2},
		{0xcc9807d1, 0x9d654d97, 0x7c6af61e, 0xde7e114f},
		{0x2cc6ac2, 0x5154e521, 0xd6445e2b, 0xeb48c033},
	}
	retv := MakeKey(keyInstance, len(userKey)*4, userKey)
	if retv != OK {
		t.Errorf("Bad retv. Is: %d, should: %d", retv, OK)
	}
	if !byteSlicesAreEqual(keyInstance.keyMaterial, userKey) {
		t.Errorf("Bad keyMaterial. Is %v, should: %v\n", keyInstance.keyMaterial, userKey)
	}
	if !slicesAreEqual(keyInstance.userKey, expectedUserKey) {
		t.Errorf("Bad keyMaterial. Is %v, should: %v\n", keyInstance.userKey, expectedUserKey)
	}
	if !keyScheduleAreEqual(keyInstance.KHat, expectedKHat) {
		t.Errorf("Bad KHat")
	}

	keyInstance = NewKeyInstance()
	userKey = []byte("f234567890abcdef1234567890abcde1")
	expectedUserKey = []uint{0x90abcde1, 0x12345678, 0x90abcdef, 0xf2345678, 0x1, 0x0, 0x0, 0x0}
	expectedKHat = [][]uint{
		{0x937557cf, 0xda60de4f, 0xc2d90dd8, 0x69c2c918},
		{0xfc632307, 0xb9e5750e, 0x953e162d, 0x9e80df53},
		{0x81487086, 0x9b9bb581, 0x4b183b4a, 0x9831464c},
		{0x3cf9875, 0x6d2a9d3, 0xdf768e33, 0xaedd2ada},
		{0xbb51bba3, 0x61db868e, 0x6c65568, 0xad5bc662},
		{0x7bfb35d7, 0x803fa42c, 0x60412af4, 0x62794ddb},
		{0x3f20ad2f, 0x6006345b, 0xe76f2e9, 0xb67c79cb},
		{0xc466239b, 0xcce95272, 0x1edd413b, 0xd00a5f9c},
		{0xae843952, 0x91d756df, 0x5a74896f, 0x95eeac64},
		{0x2a01edb0, 0x82314f29, 0xc980e72d, 0x4d9c40e5},
		{0xa357fa2d, 0x6a5e7114, 0xf68c46df, 0xf0a78dbf},
		{0x28c1ba0, 0x5600b8cf, 0x6ae039fe, 0xf19e5195},
		{0xd5e86c35, 0x4552712d, 0x8da356d9, 0xdf59f797},
		{0xc5b22ec, 0x7ac4bb69, 0xafb34b84, 0xdeabf2d3},
		{0xccd3e357, 0x20b1b566, 0xcac88fd8, 0xf3dd4de8},
		{0xa63c7426, 0x2ee6ac12, 0xcfea4858, 0xd3979062},
		{0x500377ee, 0x4a25f185, 0xcfb2699, 0x8563b189},
		{0x9b9440bf, 0xd96207f7, 0x32f6d6e7, 0xe4d46471},
		{0x3c77255b, 0x9e476edc, 0x5bb64815, 0xa10e7acf},
		{0x1852e1bb, 0x7c1d118d, 0x71736e2b, 0x817ca24e},
		{0xef158037, 0x3c681222, 0x481f8670, 0x2e2ec471},
		{0x91f3d0a, 0xad57f4fa, 0xca78723, 0x14a13d91},
		{0xb101d42a, 0x8f4d4892, 0x2af0c6d1, 0x63bdc087},
		{0xe90006c8, 0x1f7db599, 0xb3eeec63, 0x2a460e24},
		{0xf04b1150, 0x708d9a59, 0x2699045e, 0x12380d7e},
		{0x95841a76, 0x6f9ab9e8, 0xd919e25f, 0xcd257fd1},
		{0x5285897d, 0x7c410c3b, 0xb0f7f0c9, 0x7f4f9f1d},
		{0xe2ab84d8, 0x73b11cb3, 0xf6bbe124, 0x2b7594f},
		{0xefd5460e, 0xb3f200ed, 0x30bc3eac, 0x8b8f6c97},
		{0x92d533d5, 0x5faf7b5f, 0x3f05561a, 0x6115ead2},
		{0x4f983c5f, 0x91ae9156, 0x1f037412, 0x3cdbedca},
		{0xaca5f488, 0xaf468c9b, 0x3c65c3b9, 0xffe1e869},
		{0x1ee2823, 0xcf1a6930, 0xf06da607, 0x7050a10},
	}
	retv = MakeKey(keyInstance, len(userKey)*4, userKey)
	if retv != OK {
		t.Errorf("Bad retv. Is: %d, should: %d", retv, OK)
	}
	if !byteSlicesAreEqual(keyInstance.keyMaterial, userKey) {
		t.Errorf("Bad keyMaterial. Is %v, should: %v\n", keyInstance.keyMaterial, userKey)
	}
	if !slicesAreEqual(keyInstance.userKey, expectedUserKey) {
		t.Errorf("Bad keyMaterial. Is %v, should: %v\n", keyInstance.userKey, expectedUserKey)
	}
	if !keyScheduleAreEqual(keyInstance.KHat, expectedKHat) {
		t.Errorf("Bad KHat")
	}

	keyInstance = NewKeyInstance()
	userKey = []byte("ef34567890abcdef1234567890abcd12")
	expectedUserKey = []uint{0x90abcd12, 0x12345678, 0x90abcdef, 0xef345678, 0x1, 0x0, 0x0, 0x0}
	expectedKHat = [][]uint{
		{0xb06310f, 0x16511e47, 0x50d9d440, 0x692c2e78},
		{0x4b67ced7, 0x3800757a, 0x803a56fc, 0x41f4b28b},
		{0xd700f74f, 0x3454c066, 0x315a94c4, 0x78c2c347},
		{0x362064f4, 0xbbbd19ed, 0x38207ede, 0x5053fe82},
		{0xa463b34, 0x5888643f, 0xe68cd38f, 0xdd2a1552},
		{0xfa72e39, 0x839254e0, 0x41188a9a, 0xfbb404c1},
		{0xcae8d0ee, 0xf9237473, 0x2e0a12e3, 0xd6636a83},
		{0x344dc8a6, 0xcb67a241, 0x2d6b8bc, 0x1fad91c},
		{0x3771ba6c, 0x3ac14022, 0x3af48131, 0x1eb73a5d},
		{0xd3f1bedb, 0xa1ec53, 0xb94ff658, 0xf8d0655},
		{0x20f64516, 0x1bc499a9, 0x5dfa5b9c, 0x324ed1a3},
		{0x4d1bc6f2, 0x9fdaef59, 0xb9290b5d, 0xd4c5ba88},
		{0xa7ffb8ca, 0xe69ee075, 0x26730f0, 0xf4e1baed},
		{0x345afc80, 0xac66fdac, 0x3c30a80e, 0x53b17928},
		{0x39963ead, 0xe14112a6, 0x2105c263, 0x4f2cbe2a},
		{0x54fe732b, 0x1f312c2b, 0xfe16977b, 0x481edde},
		{0x57be0b3b, 0xd7d287df, 0x92206a4e, 0x8ce354fa},
		{0xefccc2a6, 0x17230c1d, 0xf14a4121, 0x30c342f2},
		{0x12dac955, 0x4221b549, 0x3b117fea, 0xfe0bf12e},
		{0x4038f08e, 0x1dc22bc, 0xe2a546cb, 0x3d6b7f59},
		{0xf24fd211, 0xdd872420, 0x54563f94, 0x6d0e6417},
		{0xada98b2b, 0xab1b13a7, 0xca086388, 0x9136bcef},
		{0xde0fbd0e, 0xaab7df12, 0xc5ae0126, 0x1b9d1354},
		{0x82924330, 0x265b1e8f, 0x7a731a8e, 0x304c6b5},
		{0x5e2e74e5, 0xa5cc24ba, 0x368e343b, 0x9e752d48},
		{0x5469cd99, 0x845135b7, 0x1f7cc48f, 0xa2188a06},
		{0x6175a980, 0xe2a84790, 0x213a027a, 0x4d755b5a},
		{0x34405272, 0x8af63b01, 0xb19a2caf, 0xc15384ed},
		{0x83d2f49f, 0xb09d2d45, 0xb3e0d1e4, 0x9385b648},
		{0x5579dc67, 0x986c1167, 0xd82b69b9, 0x18fb768a},
		{0x5d26370b, 0xbc573428, 0xcb3b7cda, 0x127727fc},
		{0x215d18ea, 0x343e97e9, 0xaef073d, 0x7b55f80},
		{0xf66599fb, 0x39db016a, 0x1dc8b5f6, 0x85e5b21},
	}
	retv = MakeKey(keyInstance, len(userKey)*4, userKey)
	if retv != OK {
		t.Errorf("Bad retv. Is: %d, should: %d", retv, OK)
	}
	if !byteSlicesAreEqual(keyInstance.keyMaterial, userKey) {
		t.Errorf("Bad keyMaterial. Is %v, should: %v\n", keyInstance.keyMaterial, userKey)
	}
	if !slicesAreEqual(keyInstance.userKey, expectedUserKey) {
		t.Errorf("Bad keyMaterial. Is %v, should: %v\n", keyInstance.userKey, expectedUserKey)
	}
	if !keyScheduleAreEqual(keyInstance.KHat, expectedKHat) {
		t.Errorf("Bad KHat")
	}
}

//
// makeSubkeysBitslice
//
func TestMakeSubkeysBitslice(t *testing.T) {
	var userKey []uint
	var K [][]uint
	var expected [][]uint

	userKey = []uint{0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678, 0x1, 0x0, 0x0, 0x0}
	K = [][]uint{
		{0x0, 0xffff00001fa0, 0x0, 0xffff},
		{0x100, 0xffff, 0x0, 0x0},
		{0x0, 0x0, 0xff80000000000000, 0xc00a},
		{0x0, 0x0, 0x8000000000000000, 0x4007},
		{0xd65af80000000000, 0x4012, 0xff00, 0xff0000000000},
		{0xffff, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0xd614852ad0d30092, 0x7ffeefbfeca0},
		{0x7fff9f44f6b8, 0x7ffeefbfec00, 0x0, 0x1000038a6},
		{0x7ffeefbfeda0, 0x7fff669fe6e7, 0x7ffeefbfeeef, 0x0},
		{0xffff0024, 0x7ffeefbfeeef, 0x8, 0x0},
		{0x0, 0x0, 0x7fff669fe70e, 0x0},
		{0x0, 0x32aaaba2, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x7ffeefbfee03, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x170000001700, 0x7fff9f4501a8, 0x7fff9f44f6b8, 0x0},
		{0x0, 0x100003868, 0x7ffeefbfed40, 0x7fff669e7d89},
		{0x7fff9f4501a8, 0x1, 0x7ffeefbfed70, 0x7fff669f074d},
		{0x7ffeefbfee30, 0x0, 0x100003868, 0x7fff9f4501a8},
		{0x7ffeefbfee70, 0x7fff669ee7cb, 0x0, 0x1600},
		{0x150000001603, 0xd614852ad0d30092, 0x7fff9f44ff78, 0x40},
		{0x0, 0x0, 0x7ffeefbff020, 0x7ffeefbff020},
		{0x3837363534333231, 0x10, 0x0, 0x0},
		{0x0, 0x0, 0x3000000010, 0x7ffeefbff420},
		{0x363261303639320a, 0x3d7478, 0xd614852ad0d30092, 0x0},
		{0x3000000008, 0x7ffeefbfee80, 0x7ffeefbfed80, 0x7fff669bdbd5},
		{0xd614852ad0d30092, 0x0, 0x0, 0x0},
		{0x7ffeefbfeea0, 0x1000027df, 0x1d0d30092, 0x700000002},
		{0x800000008, 0x7ffeefbff008, 0x7ffeefbfef00, 0x100002b69},
		{0x100000001, 0x7ffeefbfeeef, 0x800000008, 0x400000004},
		{0x800000000, 0x7ffeefbff008, 0x7ffeefbfefc0, 0x1},
	}
	expected = [][]uint{
		{0xc5a655e5, 0xd0783278, 0x68963522, 0xee377183},
		{0x5b82081, 0x8176139a, 0x72cf3f9, 0x2b007bd6},
		{0x693d21af, 0x3e958e94, 0x56b882de, 0x4d45446f},
		{0x3359986d, 0x9a521b8a, 0x47f8c863, 0x954cb70a},
		{0xd96e6c24, 0x8c5dd69e, 0x49ed6598, 0x62733546},
		{0x6ab17016, 0x51ba0979, 0x99e44c77, 0xea43fcec},
		{0xff414c65, 0x235b4f2d, 0xbcd3565f, 0xbc77521f},
		{0xa7b12d76, 0x8dcbea0d, 0x4987f849, 0x384bcecf},
		{0x1d5ccff7, 0xf1790a99, 0xe452908f, 0x25407ae3},
		{0x32e8a98f, 0x3c232b93, 0x499d87bb, 0x3f03bb6d},
		{0xd49cfedc, 0x8f4604b, 0xe581ead9, 0xd3063c8d},
		{0x3d4c4ab6, 0x874a0110, 0x5cf22903, 0x31c5952e},
		{0xff062874, 0xe9e49196, 0x92e6d22a, 0xd770ae09},
		{0x5e51a00e, 0x5fbec818, 0x901300ca, 0x8a92ff43},
		{0x6edcae05, 0xa9db7034, 0x3466ee4e, 0x1169be38},
		{0x8bca1712, 0x137e585b, 0x74cf30db, 0x88715887},
		{0xf5305195, 0xe14f68a6, 0x48825e19, 0x5ef82639},
		{0xd1a85f77, 0x984d44e3, 0x5ca5c966, 0xd1740499},
		{0x3ec6676e, 0xa8879066, 0x9bd2263f, 0xc67ade7},
		{0x50839e57, 0xcccf38c4, 0xdb8e2255, 0x21cbae30},
		{0xf10a4135, 0xec3f53c, 0xb022f2c6, 0x2eb303b3},
		{0xbd6c7391, 0xcf51d7c9, 0x2bee6c67, 0x80780acd},
		{0xa352337e, 0x76cc36c3, 0xda0e632a, 0x8932b77d},
		{0xfef2d2be, 0x1cecc43, 0xbed2bc9a, 0x3436478e},
		{0x49c0b8ae, 0xf1e333dd, 0xbbfbb15b, 0xaac7947e},
		{0xf1f75545, 0xfa4be5af, 0x7007fbfd, 0xcd5c4c8d},
		{0xfcbed288, 0x76925e87, 0xb28cf8c, 0x6452bb9c},
		{0xe1b087eb, 0xa142fc74, 0x1f966037, 0xaacbe214},
		{0x9c076877, 0x3dd0ae90, 0x5990f9fc, 0x571026e2},
		{0xa59d37e9, 0xc328c125, 0x67fe3b54, 0x79cda0ed},
		{0xeaa69f01, 0xd55f8e9c, 0xbe1c0f56, 0x6ea0c2a2},
		{0xad8ad727, 0x71bd2104, 0xf3ed7dc6, 0xd159c6f2},
		{0x4389e500, 0xc3470a4d, 0xa8fcbc3a, 0xd8850836},
	}
	makeSubkeysBitslice(userKey, K)
	if !slicesAreEqual2(K, expected) {
		t.Errorf("Bad result. Is:")
		printKeySchedule(K)
		fmt.Println("Schould:")
		printKeySchedule(expected)
	}

}

//
// RInverse
//
func TestRInverse(t *testing.T) {
	var BHati, BHatiPlus1, expected []uint
	var KHat [][]uint
	var i int

	KHat = [][]uint{
		{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xbfc2c981},
		{0xfc4e68a5, 0x4cde80ee, 0x12735620, 0x208085cf},
		{0x7c96dfd9, 0x68102a61, 0x68575b0b, 0xd36be69},
		{0x2550b1e5, 0xd48b78aa, 0x4f47d821, 0xa41b2c7d},
		{0x68166ba0, 0x27da1f2c, 0x4fda779e, 0x3d817285},
		{0x8ee7ad56, 0x8d99ec02, 0x7c7324a9, 0xcb96d096},
		{0x53cefcf, 0xf0c37e2, 0x4f8e28ef, 0xd1fddd33},
		{0x8d11eb9e, 0xee74f9a1, 0x7a11a4ef, 0x3498e317},
		{0xf99365df, 0x598cb1b1, 0xf273142, 0x66e31d0b},
		{0x78c6d97f, 0xd0b8b4ef, 0x513454ae, 0x4bbea9c},
		{0xd705f92e, 0x57f9d950, 0x72231b84, 0xdd49258c},
		{0x109389d4, 0x8148581e, 0xcf443968, 0x249d572b},
		{0x2153c368, 0xe49698c2, 0x6ee80750, 0xfb3d39db},
		{0x4c0271d8, 0xba98a888, 0xa12f22e5, 0xc307b3b2},
		{0x4aac741, 0xd6faddd0, 0x3fc3b56a, 0x217c351a},
		{0xc60768fe, 0xa4fa111, 0x5faa767c, 0x94469433},
		{0x30adc32d, 0x7a56cc1, 0xca99a262, 0x3f39c983},
		{0xa779857b, 0x47015b15, 0x5ad83e06, 0xbd0f6409},
		{0x8bf45ffc, 0xa1d28d59, 0x7d840bfa, 0x6035f954},
		{0x278d0715, 0x90e3b9d0, 0xfa00e6fb, 0x6785624c},
		{0xc4bb27c9, 0x676602cb, 0xa2c810fa, 0x51d5aaa1},
		{0xbe41ac4f, 0x2753c6b3, 0x4fdad542, 0xb2517367},
		{0x2bd9d97a, 0x84fb0afd, 0x238966d0, 0xd636c279},
		{0xd215d9f2, 0x7b456e98, 0x779d2af0, 0x51dd5d52},
		{0x3e9efbd6, 0xd07f1826, 0xff6448ee, 0xe3e6d0c7},
		{0xe564ef2f, 0x6f65cb47, 0x1b19ad77, 0xbf77a829},
		{0xf008de22, 0xd78be6fc, 0x385b51b0, 0x1bb35b64},
		{0x137e1e55, 0xbee22391, 0xda1584e8, 0xb1b4c4c7},
		{0xedd74591, 0x65f47aa4, 0x620e0111, 0x1c2f7b8e},
		{0x9db49e0b, 0xa2d54157, 0xdc65fd49, 0x3ed8856f},
		{0xa48626c1, 0xb80177f5, 0x92966732, 0x7bd6ded2},
		{0xcc9807d1, 0x9d654d97, 0x7c6af61e, 0xde7e114f},
		{0x2cc6ac2, 0x5154e521, 0xd6445e2b, 0xeb48c033},
	}

	i = 31
	BHatiPlus1 = []uint{0x447c23fa, 0x84a096b6, 0x3c8f47d4, 0x512c80d4}
	BHati = []uint{0x447c23fa, 0x84a096b6, 0x3c8f47d4, 0x512c80d4}
	expected = []uint{0x53eb9b04, 0x834cc05f, 0x37cdfa3c, 0xa5878207}
	RInverse(i, BHati, KHat, BHatiPlus1)
	if !slicesAreEqual(BHatiPlus1, expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(BHati), blockStr(expected))
	}

	i = 10
	BHatiPlus1 = []uint{0xf4899731, 0x825e2faf, 0xe2339397, 0x6c6b84d0}
	BHati = []uint{0xf4899731, 0x825e2faf, 0xe2339397, 0x6c6b84d0}
	expected = []uint{0x7528fcd3, 0x8d347064, 0x9d4ba128, 0xe7b564ec}
	RInverse(i, BHati, KHat, BHatiPlus1)
	if !slicesAreEqual(BHatiPlus1, expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(BHati), blockStr(expected))
	}

	i = 1
	BHatiPlus1 = []uint{0xd529dbe1, 0xa165319c, 0xd9f3c360, 0x5a7cff21}
	BHati = []uint{0xd529dbe1, 0xa165319c, 0xd9f3c360, 0x5a7cff21}
	expected = []uint{0x7369be1f, 0xcfd8032e, 0xd21d4bfc, 0xd83f5f53}
	RInverse(i, BHati, KHat, BHatiPlus1)
	if !slicesAreEqual(BHatiPlus1, expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(BHati), blockStr(expected))
	}

}

//
// R
//
func TestR(t *testing.T) {
	var BHati, BHatiPlus1, expected []uint
	var KHat [][]uint
	var i int

	KHat = [][]uint{
		{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xbfc2c981},
		{0xfc4e68a5, 0x4cde80ee, 0x12735620, 0x208085cf},
		{0x7c96dfd9, 0x68102a61, 0x68575b0b, 0xd36be69},
		{0x2550b1e5, 0xd48b78aa, 0x4f47d821, 0xa41b2c7d},
		{0x68166ba0, 0x27da1f2c, 0x4fda779e, 0x3d817285},
		{0x8ee7ad56, 0x8d99ec02, 0x7c7324a9, 0xcb96d096},
		{0x53cefcf, 0xf0c37e2, 0x4f8e28ef, 0xd1fddd33},
		{0x8d11eb9e, 0xee74f9a1, 0x7a11a4ef, 0x3498e317},
		{0xf99365df, 0x598cb1b1, 0xf273142, 0x66e31d0b},
		{0x78c6d97f, 0xd0b8b4ef, 0x513454ae, 0x4bbea9c},
		{0xd705f92e, 0x57f9d950, 0x72231b84, 0xdd49258c},
		{0x109389d4, 0x8148581e, 0xcf443968, 0x249d572b},
		{0x2153c368, 0xe49698c2, 0x6ee80750, 0xfb3d39db},
		{0x4c0271d8, 0xba98a888, 0xa12f22e5, 0xc307b3b2},
		{0x4aac741, 0xd6faddd0, 0x3fc3b56a, 0x217c351a},
		{0xc60768fe, 0xa4fa111, 0x5faa767c, 0x94469433},
		{0x30adc32d, 0x7a56cc1, 0xca99a262, 0x3f39c983},
		{0xa779857b, 0x47015b15, 0x5ad83e06, 0xbd0f6409},
		{0x8bf45ffc, 0xa1d28d59, 0x7d840bfa, 0x6035f954},
		{0x278d0715, 0x90e3b9d0, 0xfa00e6fb, 0x6785624c},
		{0xc4bb27c9, 0x676602cb, 0xa2c810fa, 0x51d5aaa1},
		{0xbe41ac4f, 0x2753c6b3, 0x4fdad542, 0xb2517367},
		{0x2bd9d97a, 0x84fb0afd, 0x238966d0, 0xd636c279},
		{0xd215d9f2, 0x7b456e98, 0x779d2af0, 0x51dd5d52},
		{0x3e9efbd6, 0xd07f1826, 0xff6448ee, 0xe3e6d0c7},
		{0xe564ef2f, 0x6f65cb47, 0x1b19ad77, 0xbf77a829},
		{0xf008de22, 0xd78be6fc, 0x385b51b0, 0x1bb35b64},
		{0x137e1e55, 0xbee22391, 0xda1584e8, 0xb1b4c4c7},
		{0xedd74591, 0x65f47aa4, 0x620e0111, 0x1c2f7b8e},
		{0x9db49e0b, 0xa2d54157, 0xdc65fd49, 0x3ed8856f},
		{0xa48626c1, 0xb80177f5, 0x92966732, 0x7bd6ded2},
		{0xcc9807d1, 0x9d654d97, 0x7c6af61e, 0xde7e114f},
		{0x2cc6ac2, 0x5154e521, 0xd6445e2b, 0xeb48c033},
	}

	i = 0
	BHati = []uint{0xd3ed897d, 0x7fe7de7d, 0x23c9682f, 0x3009c9ab}
	BHatiPlus1 = []uint{0xd3ed897d, 0x7fe7de7d, 0x23c9682f, 0x3009c9ab}
	expected = []uint{0x7369be1f, 0xcfd8032e, 0xd21d4bfc, 0xd83f5f53}
	R(i, BHati, KHat, BHatiPlus1)
	if !slicesAreEqual(BHatiPlus1, expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(BHatiPlus1), blockStr(expected))
	}

	i = 12
	BHati = []uint{0x3470d472, 0x6ccb0bf8, 0xec2886a9, 0xb65df4e5}
	BHatiPlus1 = []uint{0x3470d472, 0x6ccb0bf8, 0xec2886a9, 0xb65df4e5}
	expected = []uint{0x59c17e5b, 0xbdaa24a7, 0x7f8862ed, 0x1bd237c1}
	R(i, BHati, KHat, BHatiPlus1)
	if !slicesAreEqual(BHatiPlus1, expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(BHatiPlus1), blockStr(expected))
	}

	i = 25
	BHati = []uint{0x4f3f617e, 0xf63a2c13, 0x64e19f57, 0x6a49490a}
	BHatiPlus1 = []uint{0x4f3f617e, 0xf63a2c13, 0x64e19f57, 0x6a49490a}
	expected = []uint{0x328a02cd, 0x7da770e2, 0xead8fa4f, 0x4a8244f6}
	R(i, BHati, KHat, BHatiPlus1)
	if !slicesAreEqual(BHatiPlus1, expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(BHatiPlus1), blockStr(expected))
	}

	i = 31
	BHati = []uint{0x53eb9b04, 0x834cc05f, 0x37cdfa3c, 0xa5878207}
	BHatiPlus1 = []uint{0x53eb9b04, 0x834cc05f, 0x37cdfa3c, 0xa5878207}
	expected = []uint{0x447c23fa, 0x84a096b6, 0x3c8f47d4, 0x512c80d4}
	R(i, BHati, KHat, BHatiPlus1)
	if !slicesAreEqual(BHatiPlus1, expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(BHatiPlus1), blockStr(expected))
	}
}

//
// SHatInverse
//
func TestSHatInverse(t *testing.T) {
	var box int
	var output, expected []uint
	var input [WORDS_PER_BLOCK]uint

	box = 31
	output = []uint{0x46b04938, 0xd5f47397, 0xeacb19ff, 0xba6440e7}
	expected = []uint{0x9f739cd5, 0x1e298dc8, 0x4ba70c22, 0x7bf99348}
	SHatInverse(box, output, input[:])
	if !slicesAreEqual(input[:], expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(input[:]), blockStr(expected))
	}

	box = 20
	output = []uint{0xe80d068, 0x6561db62, 0x384e80db, 0x77103aad}
	expected = []uint{0x5d25f572, 0x7970f678, 0x32ad25f6, 0xee053bbf}
	SHatInverse(box, output, input[:])
	if !slicesAreEqual(input[:], expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(input[:]), blockStr(expected))
	}

	box = 10
	output = []uint{0xe77b8c2b, 0xbe0be193, 0x52ad4ee0, 0x9e2036a8}
	expected = []uint{0xa22d05fd, 0xdacda934, 0xef68baac, 0x3afc4160}
	SHatInverse(box, output, input[:])
	if !slicesAreEqual(input[:], expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(input[:]), blockStr(expected))
	}

	box = 0
	output = []uint{0xa3dc4e2a, 0xb53e0263, 0xb8bba6cb, 0xec7233f4}
	expected = []uint{0x409fa8b4, 0x7608db50, 0x717745f7, 0x8fcb002a}
	SHatInverse(box, output, input[:])
	if !slicesAreEqual(input[:], expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(input[:]), blockStr(expected))
	}
}

//
// SHat
//
func TestSHat(t *testing.T) {
	var box int
	var input, expected []uint
	var output [WORDS_PER_BLOCK]uint

	input = []uint{0x409fa8b4, 0x7608db50, 0x717745f7, 0x8fcb002a}
	expected = []uint{0xa3dc4e2a, 0xb53e0263, 0xb8bba6cb, 0xec7233f4}
	box = 0
	SHat(box, input, output[:])
	if !slicesAreEqual(output[:], expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(output[:]), blockStr(expected))
	}

	input = []uint{0x8f27d6ba, 0x830683c0, 0xc06e1ddc, 0xf8bfda9c}
	expected = []uint{0x142ad58e, 0x17f5176f, 0x6f53cdd6, 0x4184deb6}
	box = 1
	SHat(box, input, output[:])
	if !slicesAreEqual(output[:], expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(output[:]), blockStr(expected))
	}

	input = []uint{0x8c2e17ec, 0xa6803f94, 0x5fe8a4f2, 0xfaf1a4ed}
	expected = []uint{0x2987f679, 0x4b213d5c, 0xd724cd8, 0xd4df4c7e}
	box = 4
	SHat(box, input, output[:])
	if !slicesAreEqual(output[:], expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(output[:]), blockStr(expected))
	}

	input = []uint{0xba6c1aed, 0x4eb4d3a4, 0x73c5c205, 0xa85cb688}
	expected = []uint{0xac29dc53, 0xe5ae30ce, 0xb0989f18, 0xc789a277}
	box = 15
	SHat(box, input, output[:])
	if !slicesAreEqual(output[:], expected) {
		t.Errorf("Bad result. Is %s, should: %s\n", blockStr(output[:]), blockStr(expected))
	}
}

//
// shortToLongKey
//
func TestShortToLongKey(t *testing.T) {
	var key, expected []uint
	var bits int

	key = []uint{0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678, 0, 0, 0, 0}
	expected = []uint{0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678, 1, 0, 0, 0}
	bits = 128
	shortToLongKey(key, bits)
	if !slicesAreEqual(key, expected) {
		t.Errorf("Bad result. Is %v, should: %v\n", key, expected)
	}
}

//
// rotateLeft
//
func TestRotateLeft(t *testing.T) {
	var x, result, expected uint
	var p int

	x = 0x1ca8e22e
	p = 11
	expected = 0x471170e5
	result = rotateLeft(x, p)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}

	x = 0xc93e6ff7
	p = 11
	expected = 0xf37fbe49
	result = rotateLeft(x, p)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}

	x = 0xe8b417df
	p = 11
	expected = 0xa0beff45
	result = rotateLeft(x, p)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}
}

//
// SInverse
//
func TestSInverse(t *testing.T) {
	var box int
	var output, result, expected byte

	box = 31
	output = 8
	expected = 5
	result = SInverse(box, output)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}

	box = 29
	output = 2
	expected = 2
	result = SInverse(box, output)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}

	box = 26
	output = 14
	expected = 10
	result = SInverse(box, output)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}
}

//
// S
//
func TestS(t *testing.T) {
	var box int
	var input, result, expected byte

	box = 3
	input = 5
	expected = 9
	result = S(box, input)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}

	box = 2
	input = 10
	expected = 14
	result = S(box, input)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}

	box = 31
	input = 0
	expected = 1
	result = S(box, input)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}

	box = 29
	input = 14
	expected = 7
	result = S(box, input)
	if result != expected {
		t.Errorf("Bad result. Is %x, should: %x\n", result, expected)
	}
}

//
// applyXorTable
//
func TestApplyXorTable(t *testing.T) {
	var in, expected []uint
	var out [WORDS_PER_BLOCK]uint

	in = []uint{0x2987f679, 0x4b213d5c, 0xd724cd8, 0xd4df4c7e}
	expected = []uint{0x1754e133, 0x9a98ee8d, 0x4d873aa8, 0x428d4f76}
	applyXorTable(LTTable, in, out[:])
	if !slicesAreEqual(out[:], expected[:]) {
		t.Errorf("Bad result. Is %x, should: %x\n", out, expected)
	}

	in = []uint{0x351919dd, 0x58065eb4, 0xa175ec72, 0xb50995e4}
	expected = []uint{0xc57c3802, 0x419cabf0, 0xd1ddd441, 0xbb0313cc}
	applyXorTable(LTTable, in, out[:])
	if !slicesAreEqual(out[:], expected[:]) {
		t.Errorf("Bad result. Is %x, should: %x\n", out, expected)
	}
}

//
// applyPermutation
//
func TestApplyPermutation(t *testing.T) {
	var in, expected []uint
	var out [WORDS_PER_BLOCK]uint

	in = []uint{0xc5a655e5, 0xd0783278, 0x68963522, 0xee377183}
	expected = []uint{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xbfc2c981}
	applyPermutation(IPTable[:], in, out[:])
	if !slicesAreEqual(out[:], expected[:]) {
		t.Errorf("Bad result. Is %x, should: %x\n", out, expected)
	}

	in = []uint{0x5b82081, 0x8176139a, 0x72cf3f9, 0x2b007bd6}
	expected = []uint{0xfc4e68a5, 0x4cde80ee, 0x12735620, 0x208085cf}
	applyPermutation(IPTable[:], in, out[:])
	if !slicesAreEqual(out[:], expected[:]) {
		t.Errorf("Bad result. Is %x, should: %x\n", out, expected)
	}

	in = []uint{0xd96e6c24, 0x8c5dd69e, 0x49ed6598, 0x62733546}
	expected = []uint{0x68166ba0, 0x27da1f2c, 0x4fda779e, 0x3d817285}
	applyPermutation(IPTable[:], in, out[:])
	if !slicesAreEqual(out[:], expected[:]) {
		t.Errorf("Bad result. Is %x, should: %x\n", out, expected)
	}
}

//
// xorBlock
//
func TestXorBlock(t *testing.T) {
	var in1, in2, expected []uint
	var out [WORDS_PER_BLOCK]uint

	in1 = []uint{0xd3ed897d, 0x7fe7de7d, 0x23c9682f, 0x3009c9ab}
	in2 = []uint{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xbfc2c981}
	expected = []uint{0x409fa8b4, 0x7608db50, 0x717745f7, 0x8fcb002a}
	xorBlock(in1, in2, out[:])
	if !slicesAreEqual(out[:], expected) {
		t.Errorf("Bad result. Is %x, should: %x\n", out, expected)
	}

	in1 = []uint{0x7369be1f, 0xcfd8032e, 0xd21d4bfc, 0xd83f5f53}
	in2 = []uint{0xfc4e68a5, 0x4cde80ee, 0x12735620, 0x208085cf}
	expected = []uint{0x8f27d6ba, 0x830683c0, 0xc06e1ddc, 0xf8bfda9c}
	xorBlock(in1, in2, out[:])
	if !slicesAreEqual(out[:], expected) {
		t.Errorf("Bad result. Is %x, should: %x\n", out, expected)
	}

	in1 = []uint{0xe4387c4c, 0x815a20b8, 0x1032d36c, 0xc770d668}
	in2 = []uint{0x68166ba0, 0x27da1f2c, 0x4fda779e, 0x3d817285}
	expected = []uint{0x8c2e17ec, 0xa6803f94, 0x5fe8a4f2, 0xfaf1a4ed}
	xorBlock(in1, in2, out[:])
	if !slicesAreEqual(out[:], expected) {
		t.Errorf("Bad result. Is %x, should: %x\n", out, expected)
	}
}

//
// makeNibble
//
func TestMakeNibble(t *testing.T) {
	var b0, b1, b2, b3 byte
	var nb byte

	b0 = 0x1
	b1 = 0x0
	b2 = 0x1
	b3 = 0x0
	nb = makeNibble(b0, b1, b2, b3)
	if nb != 0x5 {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0x5)
	}

	b0 = 0x0
	b1 = 0x0
	b2 = 0x1
	b3 = 0x0
	nb = makeNibble(b0, b1, b2, b3)
	if nb != 0x4 {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0x4)
	}

	b0 = 0x1
	b1 = 0x0
	b2 = 0x1
	b3 = 0x1
	nb = makeNibble(b0, b1, b2, b3)
	if nb != 0xd {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0xd)
	}

	b0 = 0x0
	b1 = 0x1
	b2 = 0x1
	b3 = 0x1
	nb = makeNibble(b0, b1, b2, b3)
	if nb != 0xe {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0xe)
	}
}

//
// getNibble
//
func TestGetNibble(t *testing.T) {
	var x uint
	var p int
	var nb byte

	x = 0x409fa8b4
	p = 0
	nb = getNibble(x, p)
	if nb != 0x4 {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0x4)
	}

	x = 0x409fa8b4
	p = 2
	nb = getNibble(x, p)
	if nb != 0x8 {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0x8)
	}

	x = 0x409fa8b4
	p = 7
	nb = getNibble(x, p)
	if nb != 0x4 {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0x4)
	}

	x = 0x7608db50
	p = 4
	nb = getNibble(x, p)
	if nb != 0x8 {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0x8)
	}

	x = 0x7608db50
	p = 5
	nb = getNibble(x, p)
	if nb != 0x0 {
		t.Errorf("Bad result. Is %x, should: %x\n", nb, 0x0)
	}
}

//
// getBitFromNibble
//
func TestGetBitFromNibble(t *testing.T) {
	var x byte // nibble
	var p int
	var s byte

	x = 0x9
	p = 0
	s = getBitFromNibble(x, p)
	if s != 0x1 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x1)
	}
	x = 0x9
	p = 3
	s = getBitFromNibble(x, p)
	if s != 0x1 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x1)
	}
	x = 0xc
	p = 3
	s = getBitFromNibble(x, p)
	if s != 0x1 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x1)
	}
	x = 0x2
	p = 3
	s = getBitFromNibble(x, p)
	if s != 0x0 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x0)
	}
}

//
// getBitFromWord
//
func TestGetBitFromWord(t *testing.T) {
	var x uint
	var p int
	var s byte

	x = 0x471170e5
	p = 0
	s = getBitFromWord(x, p)
	if s != 0x1 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x1)
	}

	x = 0x471170e5
	p = 1
	s = getBitFromWord(x, p)
	if s != 0x0 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x0)
	}

	x = 0x471170e5
	p = 5
	s = getBitFromWord(x, p)
	if s != 0x1 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x1)
	}

	x = 0x471170e5
	p = 12
	s = getBitFromWord(x, p)
	if s != 0x1 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x1)
	}

	x = 0x471170e5
	p = 21
	s = getBitFromWord(x, p)
	if s != 0x0 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x0)
	}
	x = 0x471170e5
	p = 31
	s = getBitFromWord(x, p)
	if s != 0x0 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x0)
	}
}

//
// getBit
//
func TestGetBit(t *testing.T) {
	x := []uint{0, 0, 0, 0}
	p := int(0)
	s := byte(0)

	p = 0
	x = []uint{0xc5a655e5, 0xd0783278, 0x68963522, 0xee377183}
	s = getBit(x, p)
	if s != 0x1 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x1)
	}

	p = 32
	x = []uint{0xc5a655e5, 0xd0783278, 0x68963522, 0xee377183}
	s = getBit(x, p)
	if s != 0x0 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x0)
	}

	p = 64
	x = []uint{0xc5a655e5, 0xd0783278, 0x68963522, 0xee377183}
	s = getBit(x, p)
	if s != 0x0 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x0)
	}

	p = 96
	x = []uint{0xc5a655e5, 0xd0783278, 0x68963522, 0xee377183}
	s = getBit(x, p)
	if s != 0x1 {
		t.Errorf("Bad result. Is %x, should: %x\n", s, 0x1)
	}
}

//
// setBit
//
func TestSetBit(t *testing.T) {
	var x, expected []uint
	p := int(0)
	s := byte(0)

	// 1-sze słowo -------
	p = 1
	s = 0
	x = []uint{0x1, 0x0, 0x0, 0x0}
	expected = []uint{0x1, 0x0, 0x0, 0x0}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}

	p = 6
	s = 1
	x = []uint{0x9, 0x0, 0x0, 0x0}
	expected = []uint{0x49, 0x0, 0x0, 0x0}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}

	p = 22
	s = 1
	x = []uint{0x3221c9, 0, 0, 0}
	expected = []uint{0x7221c9, 0x0, 0x0, 0x0}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}

	// 2-gie słowo
	p = 32
	s = 1
	x = []uint{0x937221c9, 0, 0, 0}
	expected = []uint{0x937221c9, 0x1, 0x0, 0x0}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}

	// 3-cie słowo -------
	p = 70
	s = 1
	x = []uint{0x937221c9, 0x9ef052d, 0x18, 0}
	expected = []uint{0x937221c9, 0x9ef052d, 0x58, 0x0}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}

	p = 89
	s = 1
	x = []uint{0x937221c9, 0x9ef052d, 0xbe2dd8, 0}
	expected = []uint{0x937221c9, 0x9ef052d, 0x2be2dd8, 0x0}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}

	// 4-te słowo -------
	p = 104
	s = 1
	x = []uint{0x937221c9, 0x9ef052d, 0x52be2dd8, 0x81}
	expected = []uint{0x937221c9, 0x9ef052d, 0x52be2dd8, 0x181}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}

	p = 112
	s = 0
	x = []uint{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xc981}
	expected = []uint{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xc981}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}

	p = 113
	s = 1
	x = []uint{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xc981}
	expected = []uint{0x937221c9, 0x9ef052d, 0x52be2dd8, 0x2c981}
	setBit(x, p, s)
	if !slicesAreEqual(x, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(x), blockStr(expected))
	}
}

func TestMakeSubkeys(t *testing.T) {
	var userKey []uint
	var KHat, expected [][]uint

	userKey = []uint{0x90abcdef, 0x12345678, 0x90abcdef, 0x12345678, 0x1, 0x0, 0x0, 0x0}
	KHat = [][]uint{
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x3ff0000000000000},
		{0x0, 0x0, 0x0, 0x3ff0000000000000},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0xbff0000000000000},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x7},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x32aaaba2, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x3, 0x0, 0x32aaaba2, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x3, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0x0, 0x0, 0x0},
		{0x0, 0xd0000000d00, 0x7fff9f4501a8, 0x7fff9f44f6b8},
		{0x0, 0x0, 0x100003868, 0x7ffeefbff300},
		{0x7fff669e7d89, 0x7fff9f4501a8, 0x1, 0x7ffeefbff330},
		{0x7fff669f074d, 0x7ffeefbff3f0, 0x0, 0x100003868},
		{0x7fff9f4501a8, 0x7ffeefbff430, 0x7fff669ee7cb, 0x4442443635334631},
		{0xc00, 0xb0000000c03, 0x185ece30c01c0037, 0x7fff9f44ff78},
		{0x40, 0x0, 0x0, 0x0},
		{0x0, 0x10, 0x8, 0x3000000008},
		{0x7ffeefbff3f0, 0x7ffeefbff2f0, 0x18, 0x185ece30c01c0037},
		{0x0, 0x0, 0x0, 0x7ffeefbff410},
		{0x1000027df, 0x3000000008, 0x7ffeefbff440, 0x7ffeefbff340},
		{0x7ffeefbff530, 0x185ece30c01c0037, 0x0, 0x0},
		{0x0, 0x7ffeefbff470, 0x100002ce7, 0x400000000},
		{0x1efbff530, 0xa00000008, 0x4ffffffff, 0x7ffeefbff530},
	}
	expected = [][]uint{
		{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xbfc2c981},
		{0xfc4e68a5, 0x4cde80ee, 0x12735620, 0x208085cf},
		{0x7c96dfd9, 0x68102a61, 0x68575b0b, 0xd36be69},
		{0x2550b1e5, 0xd48b78aa, 0x4f47d821, 0xa41b2c7d},
		{0x68166ba0, 0x27da1f2c, 0x4fda779e, 0x3d817285},
		{0x8ee7ad56, 0x8d99ec02, 0x7c7324a9, 0xcb96d096},
		{0x53cefcf, 0xf0c37e2, 0x4f8e28ef, 0xd1fddd33},
		{0x8d11eb9e, 0xee74f9a1, 0x7a11a4ef, 0x3498e317},
		{0xf99365df, 0x598cb1b1, 0xf273142, 0x66e31d0b},
		{0x78c6d97f, 0xd0b8b4ef, 0x513454ae, 0x4bbea9c},
		{0xd705f92e, 0x57f9d950, 0x72231b84, 0xdd49258c},
		{0x109389d4, 0x8148581e, 0xcf443968, 0x249d572b},
		{0x2153c368, 0xe49698c2, 0x6ee80750, 0xfb3d39db},
		{0x4c0271d8, 0xba98a888, 0xa12f22e5, 0xc307b3b2},
		{0x4aac741, 0xd6faddd0, 0x3fc3b56a, 0x217c351a},
		{0xc60768fe, 0xa4fa111, 0x5faa767c, 0x94469433},
		{0x30adc32d, 0x7a56cc1, 0xca99a262, 0x3f39c983},
		{0xa779857b, 0x47015b15, 0x5ad83e06, 0xbd0f6409},
		{0x8bf45ffc, 0xa1d28d59, 0x7d840bfa, 0x6035f954},
		{0x278d0715, 0x90e3b9d0, 0xfa00e6fb, 0x6785624c},
		{0xc4bb27c9, 0x676602cb, 0xa2c810fa, 0x51d5aaa1},
		{0xbe41ac4f, 0x2753c6b3, 0x4fdad542, 0xb2517367},
		{0x2bd9d97a, 0x84fb0afd, 0x238966d0, 0xd636c279},
		{0xd215d9f2, 0x7b456e98, 0x779d2af0, 0x51dd5d52},
		{0x3e9efbd6, 0xd07f1826, 0xff6448ee, 0xe3e6d0c7},
		{0xe564ef2f, 0x6f65cb47, 0x1b19ad77, 0xbf77a829},
		{0xf008de22, 0xd78be6fc, 0x385b51b0, 0x1bb35b64},
		{0x137e1e55, 0xbee22391, 0xda1584e8, 0xb1b4c4c7},
		{0xedd74591, 0x65f47aa4, 0x620e0111, 0x1c2f7b8e},
		{0x9db49e0b, 0xa2d54157, 0xdc65fd49, 0x3ed8856f},
		{0xa48626c1, 0xb80177f5, 0x92966732, 0x7bd6ded2},
		{0xcc9807d1, 0x9d654d97, 0x7c6af61e, 0xde7e114f},
		{0x2cc6ac2, 0x5154e521, 0xd6445e2b, 0xeb48c033},
	}
	makeSubkeys(userKey, KHat)
	if !slicesAreEqual2(KHat, expected) {
		t.Errorf("Bad result. Is:")
		printKeySchedule(KHat)
		fmt.Println("Schould:")
		printKeySchedule(expected)
	}
}

func TestEncryptGivenKHat(t *testing.T) {
	var plainText, expected []uint
	var KHat [][]uint

	plainText = []uint{0x9551dbd7, 0x83cbf662, 0x829ffb3, 0x1f356dbd}
	expected = []uint{0xc2960a26, 0x2094272f, 0x935f45f2, 0x1a72aa13}
	KHat = [][]uint{
		{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xbfc2c981},
		{0xfc4e68a5, 0x4cde80ee, 0x12735620, 0x208085cf},
		{0x7c96dfd9, 0x68102a61, 0x68575b0b, 0xd36be69},
		{0x2550b1e5, 0xd48b78aa, 0x4f47d821, 0xa41b2c7d},
		{0x68166ba0, 0x27da1f2c, 0x4fda779e, 0x3d817285},
		{0x8ee7ad56, 0x8d99ec02, 0x7c7324a9, 0xcb96d096},
		{0x53cefcf, 0xf0c37e2, 0x4f8e28ef, 0xd1fddd33},
		{0x8d11eb9e, 0xee74f9a1, 0x7a11a4ef, 0x3498e317},
		{0xf99365df, 0x598cb1b1, 0xf273142, 0x66e31d0b},
		{0x78c6d97f, 0xd0b8b4ef, 0x513454ae, 0x4bbea9c},
		{0xd705f92e, 0x57f9d950, 0x72231b84, 0xdd49258c},
		{0x109389d4, 0x8148581e, 0xcf443968, 0x249d572b},
		{0x2153c368, 0xe49698c2, 0x6ee80750, 0xfb3d39db},
		{0x4c0271d8, 0xba98a888, 0xa12f22e5, 0xc307b3b2},
		{0x4aac741, 0xd6faddd0, 0x3fc3b56a, 0x217c351a},
		{0xc60768fe, 0xa4fa111, 0x5faa767c, 0x94469433},
		{0x30adc32d, 0x7a56cc1, 0xca99a262, 0x3f39c983},
		{0xa779857b, 0x47015b15, 0x5ad83e06, 0xbd0f6409},
		{0x8bf45ffc, 0xa1d28d59, 0x7d840bfa, 0x6035f954},
		{0x278d0715, 0x90e3b9d0, 0xfa00e6fb, 0x6785624c},
		{0xc4bb27c9, 0x676602cb, 0xa2c810fa, 0x51d5aaa1},
		{0xbe41ac4f, 0x2753c6b3, 0x4fdad542, 0xb2517367},
		{0x2bd9d97a, 0x84fb0afd, 0x238966d0, 0xd636c279},
		{0xd215d9f2, 0x7b456e98, 0x779d2af0, 0x51dd5d52},
		{0x3e9efbd6, 0xd07f1826, 0xff6448ee, 0xe3e6d0c7},
		{0xe564ef2f, 0x6f65cb47, 0x1b19ad77, 0xbf77a829},
		{0xf008de22, 0xd78be6fc, 0x385b51b0, 0x1bb35b64},
		{0x137e1e55, 0xbee22391, 0xda1584e8, 0xb1b4c4c7},
		{0xedd74591, 0x65f47aa4, 0x620e0111, 0x1c2f7b8e},
		{0x9db49e0b, 0xa2d54157, 0xdc65fd49, 0x3ed8856f},
		{0xa48626c1, 0xb80177f5, 0x92966732, 0x7bd6ded2},
		{0xcc9807d1, 0x9d654d97, 0x7c6af61e, 0xde7e114f},
		{0x2cc6ac2, 0x5154e521, 0xd6445e2b, 0xeb48c033},
	}
	cipherText := NewBlockSlice()

	encryptGivenKHat(plainText, KHat, cipherText)
	if !slicesAreEqual(cipherText, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(cipherText), blockStr(expected))
	}
}

func TestDencryptGivenKHat(t *testing.T) {
	var cipherText, expected []uint
	var KHat [][]uint

	cipherText = []uint{0xc2960a26, 0x2094272f, 0x935f45f2, 0x1a72aa13}
	expected = []uint{0x9551dbd7, 0x83cbf662, 0x829ffb3, 0x1f356dbd}
	KHat = [][]uint{
		{0x937221c9, 0x9ef052d, 0x52be2dd8, 0xbfc2c981},
		{0xfc4e68a5, 0x4cde80ee, 0x12735620, 0x208085cf},
		{0x7c96dfd9, 0x68102a61, 0x68575b0b, 0xd36be69},
		{0x2550b1e5, 0xd48b78aa, 0x4f47d821, 0xa41b2c7d},
		{0x68166ba0, 0x27da1f2c, 0x4fda779e, 0x3d817285},
		{0x8ee7ad56, 0x8d99ec02, 0x7c7324a9, 0xcb96d096},
		{0x53cefcf, 0xf0c37e2, 0x4f8e28ef, 0xd1fddd33},
		{0x8d11eb9e, 0xee74f9a1, 0x7a11a4ef, 0x3498e317},
		{0xf99365df, 0x598cb1b1, 0xf273142, 0x66e31d0b},
		{0x78c6d97f, 0xd0b8b4ef, 0x513454ae, 0x4bbea9c},
		{0xd705f92e, 0x57f9d950, 0x72231b84, 0xdd49258c},
		{0x109389d4, 0x8148581e, 0xcf443968, 0x249d572b},
		{0x2153c368, 0xe49698c2, 0x6ee80750, 0xfb3d39db},
		{0x4c0271d8, 0xba98a888, 0xa12f22e5, 0xc307b3b2},
		{0x4aac741, 0xd6faddd0, 0x3fc3b56a, 0x217c351a},
		{0xc60768fe, 0xa4fa111, 0x5faa767c, 0x94469433},
		{0x30adc32d, 0x7a56cc1, 0xca99a262, 0x3f39c983},
		{0xa779857b, 0x47015b15, 0x5ad83e06, 0xbd0f6409},
		{0x8bf45ffc, 0xa1d28d59, 0x7d840bfa, 0x6035f954},
		{0x278d0715, 0x90e3b9d0, 0xfa00e6fb, 0x6785624c},
		{0xc4bb27c9, 0x676602cb, 0xa2c810fa, 0x51d5aaa1},
		{0xbe41ac4f, 0x2753c6b3, 0x4fdad542, 0xb2517367},
		{0x2bd9d97a, 0x84fb0afd, 0x238966d0, 0xd636c279},
		{0xd215d9f2, 0x7b456e98, 0x779d2af0, 0x51dd5d52},
		{0x3e9efbd6, 0xd07f1826, 0xff6448ee, 0xe3e6d0c7},
		{0xe564ef2f, 0x6f65cb47, 0x1b19ad77, 0xbf77a829},
		{0xf008de22, 0xd78be6fc, 0x385b51b0, 0x1bb35b64},
		{0x137e1e55, 0xbee22391, 0xda1584e8, 0xb1b4c4c7},
		{0xedd74591, 0x65f47aa4, 0x620e0111, 0x1c2f7b8e},
		{0x9db49e0b, 0xa2d54157, 0xdc65fd49, 0x3ed8856f},
		{0xa48626c1, 0xb80177f5, 0x92966732, 0x7bd6ded2},
		{0xcc9807d1, 0x9d654d97, 0x7c6af61e, 0xde7e114f},
		{0x2cc6ac2, 0x5154e521, 0xd6445e2b, 0xeb48c033},
	}
	plainText := NewBlockSlice()

	decryptGivenKHat(cipherText, KHat, plainText)
	if !slicesAreEqual(plainText, expected) {
		t.Errorf("Bad values. Is %s, should: %s\n", blockStr(plainText), blockStr(expected))
	}
}
