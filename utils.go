package main

import (
	"crypto/sha256"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

type Memo struct {
	Protocol string `json:"p"`
	Operator string `json:"op"`
	Tick     string `json:"tick"`
	Amount   uint64 `json:"amt"`
}

func GetNativeSegWitAddress(publicKey *secp256k1.PublicKey) (addressP2WPKH *btcutil.AddressWitnessPubKeyHash, err error) {
	addressP2WPKH, err = btcutil.NewAddressWitnessPubKeyHash(btcutil.Hash160(publicKey.SerializeCompressed()), &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}

	return
}

func GetTaprootAddress(publicKey *secp256k1.PublicKey, script []byte) (addressP2TR *btcutil.AddressTaproot, err error) {
	addressP2TR, err = btcutil.NewAddressTaproot(schnorr.SerializePubKey(txscript.ComputeTaprootOutputKey(publicKey, script)), &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}

	return
}

func Sha256(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}
