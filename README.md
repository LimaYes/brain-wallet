# Brain Wallet for Bitcoin and Ethereum

![In Action](https://github.com/OrdinaryDude/brain-wallet/raw/master/scrshot.png "In Action")

## Disclaimer

Please note that this script should be viewed as EXPERIMENTAL.
Your wallet, bitcoins or ETH may be lost, deleted, or corrupted due to bugs or glitches. Please take caution.

## What is it?

A brain wallet generator that takes in a "brain wallet string", generates a bitcoin private key from it, and then uses it to sign and verify a message (or in the case of Ethereum, to generate and sign a dummy transaction). This way, it can be ensured that the key is actually working.

## Prequisites

<i>Note: you must use Python 2.x here. If you have Python 3.x as your standard python interpreter, you must replace pip by pip2 and python by python2</i>

`pip install -r requirements.txt`

## Generate Brainwallet

For Bitcoin:
`python brain.py -b "This is a very long passphrase"`

For Ethereum:
`python brain.py -e "This is a very long passphrase"`


## Key Derivation

... is done using 100,000 iterations of pbkdf2_hmac using the sha256 hashing algorithm along with the plain passphase provided by the user and 'scriptkiddie' as the salt.
