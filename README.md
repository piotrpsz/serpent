# serpent
Serpent in Go

Here you can find my implementation of the encryption algorithm called Serpent (authors: Ross Anderson, Eli Biham and Lars Knudsen). 
This implementation is based on the reference implementation in C from https://www.cl.cam.ac.uk/~rja14/serpent.html.
Only the ECB version has been implemented.
100% of the code is covered with unit tests based on data from the original implementation in C.
The code has an educational value, it is not optimized.

Serpent is a 128-bit block cipher alpgotihm. 
Hi was a candidate in the Advanced Encryption Standard (AES) competition and became its finalist (on second place).
The winner, Rijndael, got 86 votes and Serpent - 59 votes.
Serpent is the safest of all finalists, but Rijndael was faster 
(although it is less secure because it performs encryption in fewer rounds).

# Example: How to test
```Go
package main

import (
	"fmt"
	"log"
	"serpent"
)

func main() {
	userKey := []byte("abcdef1234567890abcdef1234567890")
	oryginalPlainText := "383cbf6629551dbd71f356dbd0829ffb"
	expectedCipherText := "d93dcd724d148939e2b82183d39981ce"

	fmt.Println("Oryginal plain text:", oryginalPlainText)

	keyInstance := serpent.NewKeyInstance()
	serpent.MakeKey(keyInstance, len(userKey)*4, userKey)

	output1 := serpent.NewBlockSlice()
	input1, _ := serpent.StringAsWords(oryginalPlainText)
	serpent.BlockEncrypt(keyInstance, input1, output1)

	if serpent.WordsAsString(output1) == expectedCipherText {
		fmt.Println("Encryption OK. Cipher text:", serpent.WordsAsString(output1))
	} else {
		log.Fatal("Error in encryption")
	}

	output2 := serpent.NewBlockSlice()
	serpent.BlockDecrypt(keyInstance, output1, output2)
	if serpent.WordsAsString(output2) == oryginalPlainText {
		fmt.Println("Decryption OK. Plain text:", serpent.WordsAsString(output2))
	} else {
		log.Fatal("Error in decryption")
	}
}
```
