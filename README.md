
* PSU-Crypt

* Jacob Ferretti (Email: jfer2@pdx.edu)
* CS 585 - Cryptography
* Professor Sarah Mocas
* Winter 2021

* --- Description ---
* PSU-Crypt is a block-encryption algorithm that utilizes a Feistel structure for encryption.
* This algorithm is on Twofish and Skipjack. This algorithm uses an 80-bit key and encrypts
* plaintext ASCII characters in 64-bit blocks (8 ASCII characters). After the whitening the
* block 20 rounds of encryption are performed within the Feistel structure and the result is
* output to a text file in hex.

* --- Compiling and Running PSU-Crypt ---
* 
*     1.) Compile 'psu_crypt.cpp' with g++
*     2.) After running the command 'g++ psu_crypt.cpp'. There will now be an exectuable called 'a.out' in the current directory
* 

* --- Instructions for Encryption ---
* 
*    1.) Open 'pt.txt' located in the 'input' folder. This text file has default text for an encryption test. If you would rather use a
*        different message or text, delete this default text, paste your own ASCII text, and then save and exit the text file.
*    2.) The 80-bit key is also located the 'input' folder and is required for encryption. By default this key is 'abcdef0123456789abcd'
*    3.) Run the command './a.out 1 input/key.txt input/pt.txt'
*    4.) Step 3 will encrypt 'pt.txt' and create an output text file called 'ciphertext.txt' in the folder 'output'
* 

* --- Instructions for Decryption ---
* 
*    1.) Move the 'ciphertext.txt' text file that was created during encryption in step 3 to the folder 'input'
*    2.) Run the command './a.out 0 input/key.txt'
*    3.) Step 2 will output a file called 'plaintext_after_dec.txt' and will be located in the 'output' folder
*    4.) The text file 'plaintext_after_dec.txt' should be the original ASCII message/text that was originally encrypted
* 

* --- Notes on Interoperability ---
* 
*  I followed the format that Evan has posted on Slack regarding the format of reading in the ciphertext.
*  The ciphertext.txt file that is both outputted and read, during encryption and decryption respecively,
*  is formatted such that each line conforms to an 8 character ASCII block (64 bits). Therefore each line
*  is read in as a single block and the newline is discarded.
* 

* --- Notes on Padding ---
* 
*  I padded the very last block with '.' characters. This does not affect the message much as simple deletions are required
*  after decryption to restore the message to the original.
* 

* -- List of Files ---
* 
* psu_crypt.cpp:    Program file that contains all code for encryption and decryption as specified for Program 1
* 
* 
* ftable.h:         Skipjack F-table that contains an array of hex values. Length is 256.
* 
* 
* 'input' folder:   containing key.txt which has an 80-bit hex key and pt.txt which has generic plaintext found in
*                   'Notes on 80 bit test vector' that was supplied to us (through D2L) as part of this project
* 
*
* 'output' folder:  Empty. This folder is where 'ciphertext.txt' is output for encryption and where 'plaintext_after_dec.txt'
*                   is outputted after running the program in decryption mode.












