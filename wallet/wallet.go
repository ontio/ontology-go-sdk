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

 //Using for create account manage crypt key, and so on.
package wallet

import (
	"fmt"
	"github.com/ontio/ontology/account"
)

//OntWallet is main struct for wallet
type OntWallet struct {
	cryptScheme string
	wallet      *account.ClientImpl
}

//NewOntWallet return a OntWallet instance
func NewOntWallet(cryptScheme string, walletClient *account.ClientImpl) *OntWallet {
	return &OntWallet{
		cryptScheme: cryptScheme,
		wallet:walletClient,
	}
}

//SetCryptScheme set cryptScheme for crypt
func (this *OntWallet) SetCryptScheme(cryptScheme string) {
	this.cryptScheme = cryptScheme
}

//GetDefaultAccount return the default account
func (this *OntWallet)GetDefaultAccount()(*account.Account, error){
	return this.wallet.GetDefaultAccount()
}

//CreateAccount return a new account
func (this *OntWallet) CreateAccount() (*account.Account, error) {
	return this.wallet.CreateAccount(this.cryptScheme)
}

//ChangePassword change password of wallet
func (this *OntWallet)ChangePassword(old, new string)error{
	res := this.wallet.ChangePassword([]byte(old), []byte(new))
	if !res {
		return fmt.Errorf("ChangePassword failed")
	}
	return nil
}