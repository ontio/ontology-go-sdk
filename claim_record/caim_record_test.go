package claim_record

import (
	"testing"

	"github.com/ontio/ontology-go-sdk"
	"strings"
)

func TestClaimRecord_SendCommit(t *testing.T) {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress("127.0.0.1:20336")

	claimStr := "eyJraWQiOiJkaWQ6b250OkFTejlOZENCVUdEclpZVGhuY2hGZkp0ZVFWcnUyUDNtcXEja2V5cy0xIiwidHlwIjoiSldULVgiLCJhbGciOiJPTlQtRVMyNTYifQ==.eyJjbG0tcmV2Ijp7Iklzc3VlciI6ImRpZDpvbnQ6QVN6OU5kQ0JVR0RyWllUaG5jaEZmSnRlUVZydTJQM21xcSIsIlN1YmplY3QiOiJkaWQ6b250OkFhcnJNQnkxaUdKU1o1VG1VUUNvak55VlZUdWdpUExQaWsifSwic3ViIjoiZGlkOm9udDpBYXJyTUJ5MWlHSlNaNVRtVVFDb2pOeVZWVHVnaVBMUGlrIiwidmVyIjoidjEuMCIsImNsbSI6eyIkcmVmIjoiJC5jbG0tcmV2In0sImlzcyI6ImRpZDpvbnQ6QVN6OU5kQ0JVR0RyWllUaG5jaEZmSnRlUVZydTJQM21xcSIsImV4cCI6MTU4NjQ5OTEwNCwiaWF0IjoxNTg2NDk4MTA1LCJAY29udGV4dCI6ImNsYWltOmNvbnRleHQiLCJqdGkiOiI1MzlhMzlmNWYyY2E1NzRlNTdkMjY2NzRiMDBhZTc5ZTBkODdiYjExMTNmODBlZWNmZDFkZDhjNThhOTNiM2NjIn0=.AZ1jo4XYus7+ovFK5FKr3l5GxJihfDUPlsiOhY4vyiRf283L8AYG7fIguE2HLUEDLIE7rGxc6jnU8/ts77MLo6U="
	strings.Split(claimStr, ".")
	wallet := ontology_go_sdk.NewWallet("./wallet.dat")
	pwd := []byte("111111")
	issuerOntid,_ := wallet.NewDefaultSettingIdentity(pwd)
	subjectOntid,_ := wallet.NewDefaultSettingIdentity(pwd)
	payer, _ := wallet.NewDefaultSettingAccount(pwd)
	sdk.NeoVM.ClaimRecord.SendCommit(issuerOntid,pwd,subjectOntid.ID,"",payer,500,20000)
}
