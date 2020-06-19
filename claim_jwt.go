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

package ontology_go_sdk

type VerifiableCredentialJWT struct {
	Header    Header
	Payload   Payload
	Signature []byte
}

type Header struct {
	Alg string `json:"alg,omitempty"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

type Payload struct {
	Sub string      `json:"sub,omitempty"`
	Jti string      `json:"jti,omitempty"`
	Iss string      `json:"iss,omitempty"`
	Nbf string      `json:"nbf,omitempty"`
	Iat string      `json:"iat,omitempty"`
	Exp string      `json:"exp,omitempty"`
	VC  interface{} `json:"vc,omitempty"`
}
