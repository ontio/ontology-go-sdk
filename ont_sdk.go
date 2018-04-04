/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 * The ontology is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The ontology is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 */

 //Ontolog sdk in golang. Using for operation with ontology
package ontology_go_sdk

import (
	sdkcom "github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/rpc"
	"github.com/ontio/ontology-go-sdk/wallet"
	"fmt"
	"github.com/ontio/ontology/account"
	"github.com/ontio/ontology-go-sdk/utils"
)

//OntologySdk is the main struct for user
type OntologySdk struct {
	cryptScheme string
	//Rpc client used the rpc api of ontology
	Rpc         *rpc.RpcClient
}

//NewOntologySdk return OntologySdk.
func NewOntologySdk() *OntologySdk {
	scheme := sdkcom.CRYPTO_SCHEME_DEFAULT
	return &OntologySdk{
		cryptScheme: scheme,
		Rpc:         rpc.NewRpcClient(scheme),
	}
}

//GetCryptScheme return the currtn crypt scheme
func (this *OntologySdk) GetCryptScheme() string {
	return this.cryptScheme
}

//SetCryptScheme set a crypt scheme for sdk
func (this *OntologySdk) SetCryptScheme(scheme string) {
	this.cryptScheme = scheme
}

//OpenOrCreateWallet return a wllet instance.If the wallet is exist, just open it. if not, then create and open.
func (this *OntologySdk) OpenOrCreateWallet(walletFile, pwd string) (*wallet.OntWallet, error) {
	if utils.IsFileExist(walletFile) {
		return  this.OpenWallet(walletFile, pwd)
	} else {
		return  this.CreateWallet(walletFile, pwd)
	}
}

//CreateWallet return a new wallet
func (this *OntologySdk) CreateWallet(walletFile, pwd string)  (*wallet.OntWallet, error)  {
	walletClient := account.Create(walletFile, this.cryptScheme, []byte(pwd))
	if walletClient == nil {
		return nil, fmt.Errorf("CreateWallet:%s failed", walletFile)
	}
	return wallet.NewOntWallet(this.cryptScheme, walletClient), nil
}

//OpenWallet return a wallet instance
func (this *OntologySdk) OpenWallet(walletFile, pwd string)  (*wallet.OntWallet, error)  {
	walletClient := account.Open(walletFile, []byte(pwd))
	if walletClient == nil {
		return nil, fmt.Errorf("OpenWallet:%s failed", walletFile)
	}
	return wallet.NewOntWallet(this.cryptScheme, walletClient), nil
}