--------------------
Program Description:
--------------------

This program is a basic encryption program that is used to encrypt some data and send it over to another person who canuse the sam e program to decrypt it and access the data .

The application has two modes of operation: 
1.Encrypt mode (-e):
This mode can be used to encrypt a message, the program will take four inputs. 
-the destinations public key
-senders private key
-input text file
-output file name

2.Decrypt mode (-d):
This mode can be used to decrypt a message that was previously encrypted, the program will take four inputs. 
-the destinations private key
-senders public key
-input cipher file
-output decrypted file name

---------------------
Program Requirements:
---------------------
Python version : 2.7

Libraries required : 
1.argparse
2.cryptography.hazmat
3.os
4.base64
5.pickle
-----------------------
How to run the program:
-----------------------
1. Run the program in encryption mode:
   
   python fcrypt.py -e destination_public_key_filename sender_private_key_filename       input_plaintext_file ciphertext_file
   
   Provide destination public key file, sender private key file, input text file , output file name.
   This will create a file with the same name as the output file name, which will contain the message    data in an encrypted format.

2. Run the program in decryption:

   python fcrypt.py -d destination_private_key_filename sender_public_key_filename ciphertext_file    output_plaintext_file

   Provide destination private key, sender public key, input cipher file, output message file name.
   This will create a file with the same name as the output message file name, which will contain the    decrypted data. This message will be same as the message provided as input in the encryption mode.   





