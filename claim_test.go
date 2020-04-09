package ontology_go_sdk

import (
	"testing"

	"fmt"
	"github.com/stretchr/testify/assert"
	"time"
)

func TestNewClaim(t *testing.T) {
	wallet := NewWallet("./wallet.dat")
	pwd := []byte("111111")
	acct, err := wallet.NewDefaultSettingIdentity(pwd)
	assert.Nil(t, err)
	clmMap := map[string]interface{}{
		"1111": "1111",
	}
	metadata := map[string]string{
		"2222": "2222",
	}
	clmRevMap := map[string]interface{}{
		"333": "333",
	}
	con,err := acct.controllers[0].GetController(pwd)
	assert.Nil(t, err)
	claim, err := NewClaim(con, "", clmMap, metadata, clmRevMap, "", time.Now().Unix()+20)
	assert.Nil(t, err)
	fmt.Println(claim.claimStr)
}
