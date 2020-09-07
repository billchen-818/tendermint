package sm2

import (
	"bytes"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/tmhash"
	tmjson "github.com/tendermint/tendermint/libs/json"
)

const (
	PrivKeyName = "tendermint/PrivKeySM2"
	PubKeyName  = "tendermint/PubKeySM2"

	SM2PrivateKeyLength    = 32
	SM2PublicKeyLength     = 65
	SM2PublicKeyCompressed = 33

	pubkeyUncompressed byte = 0x4

	keyType = "sm2"
)

func init() {
	tmjson.RegisterType(PubKeySM2{}, PubKeyName)
	tmjson.RegisterType(PrivKeySM2{}, PrivKeyName)
}

type PrivKeySM2 []byte

var _ crypto.PrivKey = PrivKeySM2{}

func (privkey PrivKeySM2) Bytes() []byte {
	s := make([]byte, SM2PrivateKeyLength)
	copy(s, privkey[:])
	return s
}

func (privkey PrivKeySM2) Sign(msg []byte) ([]byte, error) {
	priv, _ := PrivKeyFromBytes(sm2.P256Sm2(), privkey[:])
	r, s, err := sm2.Sign(priv, crypto.Sm3Hash(msg))
	if err != nil {
		return nil, err
	}
	return Serialize(r, s), nil
}

func (privkey PrivKeySM2) PubKey() crypto.PubKey {
	_, pub := PrivKeyFromBytes(sm2.P256Sm2(), privkey[:])
	pubSM2 := make([]byte, SM2PublicKeyLength)
	copy(pubSM2[:], sm2.Compress(pub))
	return PubKeySM2(pubSM2)
}

func (privkey PrivKeySM2) Equals(key crypto.PrivKey) bool {
	if otherSecp, ok := key.(PrivKeySM2); ok {
		return bytes.Equal(privkey[:], otherSecp[:])
	}

	return false
}

func (privkey PrivKeySM2) Type() string {
	return keyType
}

func GenPrivKey() PrivKeySM2 {
	privKeyBytes := [SM2PrivateKeyLength]byte{}
	copy(privKeyBytes[:], crypto.CRandBytes(SM2PrivateKeyLength))

	return PrivKeySM2(privKeyBytes[:])
}

func GenPrivKeyFromSecret(secret []byte) PrivKeySM2 {
	seed := crypto.Sm3Hash(secret)
	privKeyBytes := [SM2PrivateKeyLength]byte{}
	copy(privKeyBytes[:], seed)

	return PrivKeySM2(privKeyBytes[:])
}

type PubKeySM2 []byte

var _ crypto.PubKey = PubKeySM2{}

func (pubkey PubKeySM2) Address() crypto.Address {
	if len(pubkey) != SM2PublicKeyLength {
		panic("pubkey is incorrect size")
	}
	return crypto.Address(tmhash.SumTruncated(pubkey[:]))
}

func (pubkey PubKeySM2) Bytes() []byte {
	return pubkey[:]
}

func (pubkey PubKeySM2) VerifySignature(msg []byte, sig []byte) bool {
	var pub *sm2.PublicKey
	if pubkey.isCompressed() {
		pub = sm2.Decompress(pubkey[0:SM2PublicKeyCompressed])
	} else {
		var err error
		pub, err = ParsePubKey(pubkey[:], sm2.P256Sm2())
		if err != nil {
			fmt.Printf("parse pubkey failed\n")
			return false
		}
	}

	r, s, err := Deserialize(sig)
	if err != nil {
		fmt.Printf("unmarshal sign failed")
		return false
	}

	return sm2.Verify(pub, crypto.Sm3Hash(msg), r, s)
}

func (pubKey PubKeySM2) isCompressed() bool {
	return pubKey[0] != pubkeyUncompressed
}

func (pubkey PubKeySM2) Equals(key crypto.PubKey) bool {
	if otherSecp, ok := key.(PubKeySM2); ok {
		return bytes.Equal(pubkey[:], otherSecp[:])
	}
	return false
}

func (pubkey PubKeySM2) Type() string {
	return keyType
}
