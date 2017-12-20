#importing libraries
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import argparse
import os
import base64
import pickle


#making argparse functionality

parser = argparse.ArgumentParser(prog = 'Fcrypt')

parser.add_argument('-e' ,
  	                help = "enter to make an encrypted file, provide:" + '\n'
					'destination public key, sender privte key, input text file and output file name',
				    nargs = 4,
				   )
parser.add_argument('-d' ,
	                help = "enter to decrypt an encrypted file, provide:" + '\n'
					'destination private key, sender public key, input cipher file and output file name',
				    nargs = 4,
				   )


#####################################################################################
def encrypt(receiver_public_key,sender_private_key,
	input_text_file,output_cipher_file):

	'''
	Function is used to encrypt and sign a message

	This function takes the destination public key, sender's private key,
	input text file and name of the output file. And produces the output
	file which contains the cipher text produced after encrypting the input
	message, which was present in the input text file

	Arguments:
		receiver_public_key : the destination public key
		sender_private_key  : the sender's private key
		input_text_file		: the message that needs to be encrypted
		output_cipher_file	: the file which will contain the encrypted output

	Returns:
		This function does not return anything
	'''

	#creating a random key at runtime
	#and an initialization vector for the mode
	runtime_key = os.urandom(32) # in bytes, 128 bits
	iv =os.urandom(16) #must be of same size as block size of the cipher

	#reading the input file
	filename = input_text_file
	f_input = open(filename, "rb")
	data = f_input.read()
	f_input.close()

	#here we are using GCM mode which is astream cipher so we dont need any padding
	# GCM Mode, we also need an IV along with the Key
	cipher_for_message = Cipher(algorithms.AES(runtime_key),
								modes.GCM(iv),
								backend=default_backend())
	encryptor = cipher_for_message.encryptor()

	cipher_text = encryptor.update(data) + encryptor.finalize()
	tag = encryptor.tag


	#RSA encrypt the runtime key generated previously
	key_file_name = receiver_public_key
	f_key = open(key_file_name, "rb") #opening .der file
	public_der_data = f_key.read()	  #reading .der file
	f_key.close()

	#loading public key from the DER data
	public_key = serialization.load_der_public_key(public_der_data, backend=default_backend())

	#Here message is the runtime key we generated
	message = runtime_key

	#Encrypting runtime key using RSA
	key_ciphertext = public_key.encrypt(
		message,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None))

	#take sender private key and sign the whole document
	#loading the sender private key
	with open(sender_private_key, "rb") as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend())

	#signing the cipher_text
	#we are actually creating a hash of the message and then signing the hash
	signature = private_key.sign(
		cipher_text,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	)

	#make dictionary with encrypted data
	d ={'signature' : signature,
		'key' : key_ciphertext,
		'message' : cipher_text,
		'tag': tag,
		'iv': iv}

	#pickle the data_dictionary and send write it to the output file
	pickle_data = pickle.dumps(d)

	#writing the pickled data into the output file
	fo = open(output_cipher_file, "wb")
	fo.write(pickle_data)
	fo.close()

	print "message successfully written into: "+ output_cipher_file

#######################################################################################

def decrypt(receiver_private_key, sender_public_key,
		input_cipher_text_file, output_plaintxt_file):

	'''
	Function is used to encrypt and sign a message

	This function takes the destination private key, sender's public key,
	input cipher text file and name of the output file. And produces
	the output file which contains the plain text produced after decrypting
	the input cipher, which was present in the input file

	Arguments:
		receiver_private_key   : the destination private key
		sender_public_key      : the sender's public key
		input_cipher_text_file : the message that needs to be decrypted
		output_plaintext_file  : the file which will contain the decrypted output

	Returns:
		This function does not return anything
	'''

	#Reading the input cipher file
	with open(input_cipher_text_file, "rb") as f:
		cipher_file_read = f.read()

	#unpickling the data to get the dictionary
	cipher_file_dictionary = pickle.loads(cipher_file_read)

	#Separating the key, signature, message, iv and tag from the data
	runtime_key = cipher_file_dictionary['key']
	signature = cipher_file_dictionary['signature']
	encrypted_message = cipher_file_dictionary['message']
	tag = cipher_file_dictionary['tag']
	iv = cipher_file_dictionary['iv']

	#verifying signature, move to decrypt function later
	#loading the sender_public_key
	f_key = open(sender_public_key, "rb")    #opening .der file
	sender_public_key_data = f_key.read()		#reading .der file
	f_key.close()
	sender_public_key = serialization.load_der_public_key(sender_public_key_data,
												backend=default_backend())

	try:
		#checking the hash
		sender_public_key.verify(
			signature,
			encrypted_message,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		signature_flag = True
	except:
		signature_flag = False
		print 'signature mismatch!'

	if signature_flag:

		#reading the receiver_private_key to decrypt
		with open(receiver_private_key, "rb") as key_file:
			receiver_private_key = serialization.load_pem_private_key(
				key_file.read(),
				password=None,
				backend=default_backend())

		#decrypting the runtime key
		runtime_key = receiver_private_key.decrypt(
					  runtime_key,
    				  padding.OAEP(
        				  mgf=padding.MGF1(algorithm=hashes.SHA256()),
        				  algorithm=hashes.SHA256(),
        				  label=None))

		#decrypt the message using the runtime key
		decryptor = Cipher(algorithms.AES(runtime_key),
			              modes.GCM(iv, tag),
						  backend=default_backend()).decryptor()
		message = decryptor.update(encrypted_message) + decryptor.finalize()

		#write the message into the output_plaintxt_file
		fo = open(output_plaintxt_file, "wb")
		fo.write(message)
		fo.close()

		print "plaintext message successfully written into: "+ output_plaintxt_file

###############################################################################################


try:
	args = parser.parse_args()

	if args.d == None and len(args.e) == 4:
		print 'in encryption mode'

		receiver_public_key= args.e[0]
		sender_private_key = args.e[1]
		input_text_file = args.e[2]
		output_cipher_file = args.e[3]

		encrypt(receiver_public_key,
				sender_private_key,
				input_text_file,
				output_cipher_file)


	elif args.e == None and len(args.d) == 4:
		print 'in decryption mode'

		receiver_private_key= args.d[0]
		sender_public_key = args.d[1]
		input_cipher_text_file = args.d[2]
		output_plaintxt_file = args.d[3]

		decrypt(receiver_private_key,
				sender_public_key,
				input_cipher_text_file,
				output_plaintxt_file)

	else:
		print "Worng input please try again"


except SystemExit:
		print ('Please enter:' +'\n'
			   'the correct number of arguments')
except ValueError:
	print 'Please enter the correct file name with extention'

except IOError:
		print 'Please enter the correct file name with extention'
except:
	print "some unexpected error occured. Kindly try again"
