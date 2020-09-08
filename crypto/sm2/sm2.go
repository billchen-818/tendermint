package sm2

import (
	"bytes"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"

	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/tmhash"
	tmjson "github.com/tendermint/tendermint/libs/json"
)

var _ crypto.PrivKey = PrivKey{}

const (
	PrivKeyName = "tendermint/PrivKeySM2"
	PubKeyName  = "tendermint/PubKeySM2"

	PrivateKeySize       = 32
	PubKeySize           = 65
	PubKeySizeCompressed = 33

	pubkeyUncompressed byte = 0x4

	keyType = "sm2"
)

func init() {
	tmjson.RegisterType(PubKey{}, PubKeyName)
	tmjson.RegisterType(PrivKey{}, PrivKeyName)
}

type PrivKey []byte

func (privkey PrivKey) Bytes() []byte {
	return []byte(privkey)
}

func (privkey PrivKey) Sign(msg []byte) ([]byte, error) {
	priv, _ := PrivKeyFromBytes(sm2.P256Sm2(), privkey)
	r, s, err := sm2.Sign(priv, crypto.Sm3Hash(msg))
	if err != nil {
		return nil, err
	}
	return Serialize(r, s), nil
}

func (privkey PrivKey) PubKey() crypto.PubKey {
	_, pub := PrivKeyFromBytes(sm2.P256Sm2(), privkey)
	pubkey := make([]byte, PubKeySize)
	copy(pubkey, SerializeUncompressed(pub))
	return PubKey(pubkey)
}

func (privkey PrivKey) Equals(key crypto.PrivKey) bool {
	if otherSecp, ok := key.(PrivKey); ok {
		return bytes.Equal(privkey, otherSecp)
	}

	return false
}

func (privkey PrivKey) Type() string {
	return keyType
}

func GenPrivKey() PrivKey {
	privKeyBytes := make([]byte, PrivateKeySize)
	copy(privKeyBytes, crypto.CRandBytes(PrivateKeySize))

	return PrivKey(privKeyBytes)
}

func GenPrivKeyFromSecret(secret []byte) PrivKey {
	privKeyBytes := make([]byte, PrivateKeySize)
	seed := crypto.Sm3Hash(secret)
	copy(privKeyBytes, seed)

	return PrivKey(privKeyBytes)
}

type PubKey []byte

var _ crypto.PubKey = PubKey{}

func (pubkey PubKey) Address() crypto.Address {
	if len(pubkey) != PubKeySize {
		panic("pubkey is incorrect size")
	}
	return crypto.Address(tmhash.SumTruncated(pubkey))
}

func (pubkey PubKey) Bytes() []byte {
	return []byte(pubkey)
}

func (pubkey PubKey) VerifySignature(msg []byte, sig []byte) bool {
	var pub *sm2.PublicKey
	if pubkey.isCompressed() {
		pub = sm2.Decompress(pubkey[0:PubKeySizeCompressed])
	} else {
		var err error
		pub, err = ParsePubKey(pubkey, sm2.P256Sm2())
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

func (pubKey PubKey) isCompressed() bool {
	return pubKey[0] != pubkeyUncompressed
}

func (pubkey PubKey) Equals(key crypto.PubKey) bool {
	if otherSecp, ok := key.(PubKey); ok {
		return bytes.Equal(pubkey, otherSecp)
	}
	return false
}

func (pubkey PubKey) Type() string {
	return keyType
}
