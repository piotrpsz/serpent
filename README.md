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
