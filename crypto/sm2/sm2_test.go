package sm2

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tendermint/tendermint/crypto"
	"testing"
)

func TestSM2(t *testing.T) {
	pri := GenPrivKey()
	pub := pri.PubKey()

	msg := crypto.CRandBytes(128)
	sig, err := pri.Sign(msg)
	require.Nil(t, err)

	assert.True(t, pub.VerifySignature(msg, sig))

	sig[7] ^= byte(0x01)

	assert.False(t, pub.VerifySignature(msg, sig))
}
