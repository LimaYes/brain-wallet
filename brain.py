#!/usr/bin/python
# for my education, following along with bitcoins the hard way blog post:
# http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
# Extended by the famous Ordinary Dude, 2016

import random
import hashlib
import ecdsa
import struct
import hashlib, binascii
from python_bitcoinlib.wallet import CBitcoinSecret, P2PKHBitcoinAddress
from python_bitcoinlib.signmessage import BitcoinMessage, VerifyMessage, SignMessage
import sys

from lib.ECDSA_BTC import *
import lib.python_sha3

from ethereum.keys import privtoaddr
from ethereum.transactions import Transaction
from eth_accounts import Account
from uuid import uuid4

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

b58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58encode(n):
  result = ''
  while n > 0:
    result = b58[n%58] + result
    n /= 58
  return result

def base58decode(s):
  result = 0
  for i in range(0, len(s)):
    result = result * 58 + b58.index(s[i])
  return result

def base256encode(n):
  result = ''
  while n > 0:
    result = chr(n % 256) + result
    n /= 256
  return result

def base256decode(s):
  result = 0
  for c in s:
    result = result * 256 + ord(c)
  return result

def countLeadingChars(s, ch):
  count = 0
  for c in s:
    if c == ch:
      count += 1
    else:
      break
  return count

# https://en.bitcoin.it/wiki/Base58Check_encoding
def base58CheckEncode(version, payload):
  s = chr(version) + payload
  checksum = hashlib.sha256(hashlib.sha256(s).digest()).digest()[0:4]
  result = s + checksum
  leadingZeros = countLeadingChars(result, '\0')
  return '1' * leadingZeros + base58encode(base256decode(result))


def base58CheckDecode(s):
  leadingOnes = countLeadingChars(s, '1')
  s = base256encode(base58decode(s))
  result = '\0' * leadingOnes + s[:-4]
  chk = s[-4:]
  checksum = hashlib.sha256(hashlib.sha256(result).digest()).digest()[0:4]
  assert(chk == checksum)
  version = result[0]
  return result[1:]

def privateKeyToWif(key_hex, compressed=False):
  if compressed: 
    key_hex=key_hex+'01'
  return base58CheckEncode(0x80, key_hex.decode('hex')) 


def privateKeyToPublicKey(s, compressed=False):

  sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
  vk = sk.verifying_key

  if compressed:
    from ecdsa.util import number_to_string
    order = vk.pubkey.order
    # print "order", order
    x_str = number_to_string(vk.pubkey.point.x(), order).encode('hex')
    # print "x_str", x_str 
    sign = '02' if vk.pubkey.point.y() % 2 == 0 else '03'
    # print "sign", sign 
    return (sign+x_str)
  else:
    return ('\04' + vk.to_string()).encode('hex')


def pubKeyToAddr(s):
  ripemd160 = hashlib.new('ripemd160')
  ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
  return base58CheckEncode(0, ripemd160.digest())

def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
  def makeOutput(data):
    redemptionSatoshis, outputScript = data
    return (struct.pack("<Q", redemptionSatoshis).encode('hex') +
           '%02x' % len(outputScript.decode('hex')) + outputScript)
  formattedOutputs = ''.join(map(makeOutput, outputs))
  return (
    "01000000" + # 4 bytes version
    "01" + # variant for number of inputs
    outputTransactionHash.decode('hex')[::-1].encode('hex') + # reverse OutputTransactionHash
    struct.pack('<L', sourceIndex).encode('hex') +
    '%02x' % len(scriptSig.decode('hex')) + scriptSig +
    "ffffffff" + # sequence
    "%02x" % len(outputs) + # number of outputs
    formattedOutputs +
    "00000000" # lockTime
  )

private_key = None
is_bitcoin = False
btc_name = ""
addr_version = 0x04
is_ethereum = False

def derive_privkey(hash_string):
  if len(hash_string) < 20:
        print bcolors.FAIL + "Your passphrase must be at least 20 characters, rather more",bcolors.ENDC
        sys.exit(1)
  dk = hashlib.pbkdf2_hmac('sha256', hash_string, b'scriptkiddie', 100000)
  private_key = binascii.hexlify(dk)
  return private_key

def hexa(cha):
  hexas=hex(cha)[2:-1]
  while len(hexas)<64:
    hexas="0"+hexas
  return hexas

def eth_compute_adr(priv_num):
  try:
    pubkey = Public_key( generator_256, mulG(int(priv_num,16)) )
    pubkeyhex = (hexa(pubkey.point.x())+hexa(pubkey.point.y())).decode("hex")
    return pubkeyhex, lib.python_sha3.sha3_256(pubkeyhex).hexdigest()[-40:]
  except KeyboardInterrupt:
    return "x"


print bcolors.FAIL + "Please note that this script should be viewed as EXPERIMENTAL.\nYour wallet or bitcoins may be lost, deleted, or corrupted due to bugs or glitches. Please take caution.",bcolors.ENDC

if len(sys.argv)>2:
  if sys.argv[1] == "-b":
    hash_string = sys.argv[2];
    private_key = derive_privkey(hash_string)
    print bcolors.BOLD + "\n===== Your Input =====",bcolors.ENDC
    print bcolors.OKBLUE + "Wallet Type:\t\t","Bitcoin",bcolors.ENDC
    print bcolors.OKBLUE + "Private passphrase:\t",hash_string,bcolors.ENDC
    is_bitcoin = True
    btc_name = "Bitcoin"
  elif sys.argv[1] == "-e":
    hash_string = sys.argv[2];
    private_key = derive_privkey(hash_string)
    print bcolors.BOLD + "\n===== Your Input =====",bcolors.ENDC
    print bcolors.OKBLUE + "Wallet Type:\t\t","Ethereum",bcolors.ENDC
    print bcolors.OKBLUE + "Private passphrase:\t",hash_string,bcolors.ENDC
    is_ethereum = True
  else:
    print bcolors.FAIL + "\nUse one of the following flags:\n-b\tBitcoin\n-e\tEthereum\n\nExample: python brain.py -e \"This is a very long passphrase\"",bcolors.ENDC
    sys.exit(1)
else: 
    print bcolors.FAIL + "\nUse one of the following flags:\n-b\tBitcoin\n-e\tEthereum\nAND specify a passphrase\n\nExample: python brain.py -e \"This is a very long passphrase\"",bcolors.ENDC
    sys.exit(1)
print bcolors.BOLD + "\n===== Overview =====",bcolors.ENDC

if is_bitcoin:
  global wif, cpublic_key
  wif = privateKeyToWif(private_key, compressed=True)
  print bcolors.OKBLUE + "The WIF:\t\t",wif,bcolors.ENDC
  cpublic_key = privateKeyToPublicKey(private_key,compressed=True)
  print bcolors.OKBLUE +"The",btc_name,"pubkey:\t", cpublic_key,bcolors.ENDC
  print bcolors.OKBLUE + "The",btc_name,"address:\t", pubKeyToAddr(cpublic_key),bcolors.ENDC
if is_ethereum:
  global pubkey_hex, addr
  pubkey_hex, addr = eth_compute_adr(private_key)
  print bcolors.OKBLUE +"The Ethereum pubkey:\t", binascii.hexlify(pubkey_hex),bcolors.ENDC
  print bcolors.OKBLUE + "The Ethereum address:\t", addr,bcolors.ENDC



print bcolors.BOLD + "\n===== Now, verifying that the key actually works =====",bcolors.ENDC
if is_bitcoin:
  msg_to_sign = "Well ladies and gentlemen, I don't think any of our contestants this evening have succeeded in encapsulating the intricacies of Proust's masterwork, so I'm going to award the first prize this evening to the girl with the biggest t--s.";
  print "Message to sign:\t", msg_to_sign
  key = CBitcoinSecret(wif)
  address = P2PKHBitcoinAddress.from_pubkey(key.pub)   
  message = BitcoinMessage(msg_to_sign)
  signature = SignMessage(key, message)
  print bcolors.OKBLUE + "Address:\t\t%s" % address,bcolors.ENDC
  print bcolors.OKBLUE + "Signature:\t\t%s" % signature,bcolors.ENDC
  ver = VerifyMessage(address, message, signature) & (binascii.hexlify(key.pub) == cpublic_key)
  if ver == True:
      print bcolors.OKGREEN + "Verified:\t\t%s" % ver,bcolors.ENDC
  else:
      print bcolors.FAIL + "!!!!!! FAILURE! DO NOT USE THIS",btc_name,"ADDRESS, YOU WILL NOT BE ABLE TO ACCESS YOUR BTC! !!!!!!",bcolors.ENDC
      sys.exit(1)

  print bcolors.BOLD + "\nTo verify using",btc_name.upper(),"core (you really wanna do this):",bcolors.ENDC
  print "`",btc_name.lower(),"-cli verifymessage %s \"%s\" \"%s\"`" % (address, signature.decode('ascii'), message)


if is_ethereum:
  # create fake transaction and sign it (it that works, all is good)
  print bcolors.OKBLUE + "(on Ethereum, this may take a while)",bcolors.ENDC
  account = Account.new('somepassword', private_key, uuid4())
  account.unlock('somepassword')
  print bcolors.OKBLUE + "[!] created and unlocked a new Ethereum account.",bcolors.ENDC
  print bcolors.OKBLUE + "Account Address:\t%s" % binascii.hexlify(account.address),bcolors.ENDC
  tx = Transaction(1, 0, 10**6, account.address, 0, '')
  account.sign_tx(tx)
  print bcolors.OKBLUE + "Signed TX Sender:\t%s" % binascii.hexlify(tx.sender),bcolors.ENDC
  ver = False
  if binascii.hexlify(tx.sender) == binascii.hexlify(account.address) and binascii.hexlify(account.address) == addr:
    ver = True

  if ver == True:
      print bcolors.OKGREEN + "Verified:\t\t%s" % ver,bcolors.ENDC
  else:
      print bcolors.FAIL + "!!!!!! FAILURE! DO NOT USE THIS ETHEREUM ADDRESS, YOU WILL NOT BE ABLE TO ACCESS YOUR BTC! !!!!!!",bcolors.ENDC
      sys.exit(1)







