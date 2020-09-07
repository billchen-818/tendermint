package types

import (
	cryptoenc "github.com/tendermint/tendermint/crypto/encoding"
	ed25519 "github.com/tendermint/tendermint/crypto/sm2"
)

const (
	PubKeyEd25519 = "sm2"
)

func Ed25519ValidatorUpdate(pk []byte, power int64) ValidatorUpdate {
	pke := ed25519.PubKey(pk)
	pkp, err := cryptoenc.PubKeyToProto(pke)
	if err != nil {
		panic(err)
	}

	return ValidatorUpdate{
		// Address:
		PubKey: pkp,
		Power:  power,
	}
}
