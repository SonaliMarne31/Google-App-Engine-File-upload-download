#Name: Sonali Tukaram Marne
#Course Number: 6331
#Lab: Programming Assignment- 1
#Section: 13:00-15:00


#Reference:
# 1. Source code provided in Class 1 and code sheet that was given in class
# 2. For file uploading file on Google Cloud
#https://developers.google.com/drive/web/quickstart/quickstart-python
#http://oblalex.blogspot.com/2014/09/google-drive-api-upload-files-to-folder.html
#https://github.com/googledrive/python-quickstart/blob/master/main.py
#
# 3. For Listing Google Cloud Objects
#https://cloud.google.com/storage/docs/json_api/v1/json-api-python-samples

'''Copyright (c) 2015 HG,DL,UTA
   Python program runs on local host, uploads, downloads, encrypts local files to google.
   Please use python 2.7.X, pycrypto 2.6.1 and Google Cloud python module '''

#import statements.
import argparse
import httplib2
import os
import sys
import json
import time
import datetime
import io
import hashlib
#Google apliclient (Google App Engine specific) libraries.
from apiclient import discovery
from oauth2client import file
from oauth2client import client
from oauth2client import tools
from apiclient.http import MediaIoBaseDownload
#pycry#pto libraries.
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import MD5
import glob


# Encryption using AES
#http://stackoverflow.com/questions/20852664/
#You can read more about this in the following link
#http://eli.thegreenplace.net/2010/06/25/aes-encryption-of-files-in-python-with-pycrypto


#Initial password to create a key
password = raw_input("Enter the password : ")
#password = 'bluecloud'
#key to use
key1 = hashlib.sha256(password).digest()
#key = MD5.new(password).hexdigest()
#print key

#this implementation of AES works on blocks of "text", put "0"s at the end if too small.
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)

_BUCKET_NAME = 'bucketassign1' #name of your google bucket.
_API_VERSION = 'v1'

# Parser for command-line arguments.
parser = argparse.ArgumentParser(
    description=__doc__,
    formatter_class=argparse.RawDescriptionHelpFormatter,
    parents=[tools.argparser])


# client_secret.json is the JSON file that contains the client ID and Secret.
#You can download the json file from your google cloud console.
CLIENT_SECRETS = os.path.join(os.path.dirname(__file__), 'client_secret.json')

# Set up a Flow object to be used for authentication.
# Add one or more of the following scopes. 
# These scopes are used to restrict the user to only specified permissions (in this case only to devstorage) 
FLOW = client.flow_from_clientsecrets(CLIENT_SECRETS,
  scope=[
      'https://www.googleapis.com/auth/devstorage.full_control',
      'https://www.googleapis.com/auth/devstorage.read_only',
      'https://www.googleapis.com/auth/devstorage.read_write',
    ],
    message=tools.message_if_missing(CLIENT_SECRETS))


#text file
def prepareMD5(service):
	os.chdir("C:\Users\Sonali\Desktop\Assign1")
	for file1 in glob.glob("SonaliMarne.txt"):
		print(file1)
	hasher = hashlib.md5()
	with open(file1, 'rb') as afile:
		buf = afile.read()
	hasher.update(buf)
	txh = hasher.hexdigest()
	print(txh)

#with open("tasmeen.md5" , "wb") as f:
#	f.write (file1 +","+hasher.hexdigest())
#jpg file
	os.chdir("C:\Users\Sonali\Desktop\Assign1")
	for file in glob.glob("SonaliMarne.jpg"):
		print(file)
#MD5 cose
	hasher = hashlib.md5()
	with open(file, 'rb') as afile:
		buf = afile.read()
	hasher.update(buf)
	jxh = hasher.hexdigest()
	print(jxh)

	md = open("sonali_md5.txt" , "wb")
	md.write (file1 +","+txh)
	md.write ("\n")
	md.write (file +","+jxh)
	md.close 

	fileupload = "sonali_md5.txt"
	enc_file = encrypt_file(fileupload, key1)
	req = service.objects().insert(
			bucket=_BUCKET_NAME,
			name=fileupload,
			media_body=enc_file)
	resp = req.execute()
    #os.remove(fileupload) #to remove the local copies
   
    
#Function to encrypt a given file
def encrypt_file(file_name, key1):
    fileDescriptor = open(file_name, 'rb')
    plaintextFile = fileDescriptor.read()
    encryptedFile = encrypt(plaintextFile, key1)
    print "File on drive encrypted.."
    
    encFileDesc = open(file_name, 'wb')
    encFileDesc.write(encryptedFile)
    print "Encrypted file created..."
    
    fileDescriptor.close()
    encFileDesc.close()
    
    return encFileDesc.name

#Function to encrypt the message
def encrypt(message, key1, key_size=256):
    message = pad(message)
    #iv is the initialization vector
    iv = Random.new().read(AES.block_size)
    #encrypt entire message
    cipher = AES.new(key1, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(message)


#Downloads the specified object from the given bucket and deletes it from the bucket.
def get(service):
  listobj(service)
  decodefile = raw_input("Enter the filename from the above list that is to be downloaded from Google drive \n")
  try:
# Get Metadata
    req = service.objects().get(
            bucket=_BUCKET_NAME,
            object=decodefile,
            fields='bucket,name,metadata(my-key)',    
        
        )                   
    resp = req.execute()
    print json.dumps(resp, indent=2)

# Get Payload Data
    req = service.objects().get_media(
       	bucket=_BUCKET_NAME	,
        object=decodefile
    )

# The BytesIO object may be replaced with any io.Base instance.
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, req, chunksize=1024*1024) #show progress at download
    done = False
    while not done:
	status, done = downloader.next_chunk()
	if status:
	    print 'Download %d%%.' % int(status.progress() * 100)
	print 'Download Complete!'
    dec = decrypt(fh.getvalue(),key1)
    with open(decodefile, 'wb') as fo:
        fo.write(dec)
    print json.dumps(resp, indent=2)
    

  except client.AccessTokenRefreshError:
    print ("Error in the credentials")

#Puts a object into file after encryption and deletes the object from the local PC.
def put(service):  
  try:
    #putFileName = raw_input("Enter the file to be uploaded on Google drive : \n")
    uploadFile = os.path.isfile("C:\Python27\URLs.txt")
    print "File uploaded to drive "
    
    #putThisFile = encrypt_file(putFileName, key)
    #request = service.objects().insert(bucket=_BUCKET_NAME,name=putFileName,media_body=putThisFile)
    #
    #response = request.execute()
    #
    #os.remove(putThisFile)
    #os.remove(putFileName)
    #
  except client.AccessTokenRefreshError:
    print ("Error in the credentials")

#Lists all the objects from the given bucket name
def listobj(service):
    print "Objects on drive"
    allObjects = 'nextPageToken,items(name,size,contentType,metadata(my-key))'
    req = service.objects().list(bucket=_BUCKET_NAME, fields=allObjects)
    
    #For too many tokens the below logic will loop through each tocken
    while req is not None:
      resp = req.execute()
      print json.dumps(resp, indent=2)
      req = service.objects().list_next(req, resp)
      
    
    print "Objects on Local Drive"
    filesOnLocal = os.listdir("C:\Users\Sonali\Desktop\Assign1")
    for f in filesOnLocal:
	print f
    

#This deletes the object from the bucket
def deleteobj(service):
  listobj(service)
  objDelete = raw_input("Enter the file to be deleted from the above list : \n")
  try:
    service.objects().delete(
        bucket=_BUCKET_NAME,
        object=objDelete).execute()
    print "File Deleted..."
  except client.AccessTokenRefreshError:
    print ("Error in the credentials")

def main(argv):
  # Parse the command-line flags.
  flags = parser.parse_args(argv[1:])

  
  #sample.dat file stores the short lived access tokens, which your application requests user data, attaching the access token to the request.
  #so that user need not validate through the browser everytime. This is optional. If the credentials don't exist 
  #or are invalid run through the native client flow. The Storage object will ensure that if successful the good
  # credentials will get written back to the file (sample.dat in this case). 
  storage = file.Storage('sample.dat')
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    credentials = tools.run_flow(FLOW, storage, flags)

  # Create an httplib2.Http object to handle our HTTP requests and authorize it
  # with our good Credentials.
  http = httplib2.Http()
  http = credentials.authorize(http)

  # Construct the service object for the interacting with the Cloud Storage API.
  service = discovery.build('storage', _API_VERSION, http=http)

  #This is kind of switch equivalent in C or Java.
  #Store the option and name of the function as the key value pair in the dictionary.
  options = {1: put, 2: get, 3:listobj, 4:deleteobj, 5:prepareMD5}
  while(True):
      print "*********** MENU **************"
      print "1. Upload file on Drive \n"
      print "2. Download a file from Drive \n"
      print "3. List of files on Drive and on Local Drive \n"
      print "4. Delete a file from Drive \n"
      print "5. Prepare MD5 \n"
      print "6. Exit"
      print "*******************************"
      option = raw_input("Select one option : ")
      if option =="1":
          options[1](service)
      elif option =="2":
          options[2](service)
      elif option =="3":
          options[3](service)
      elif option =="4":
          options[4](service)
      elif option =="5":
          options[5](service)
      elif option == "6":
	  sys.exit(0)
      else:
          print "Please select a valid choice !!!\n"

if __name__ == '__main__':
  main(sys.argv)
# [END all]
