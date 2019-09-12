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
package types

type FileMgrCrypto interface {
	Encrypt(req *EncryptFileReq) error
	Decrypt(req *DecryptFileReq) error
}

const (
	URL_ENCRYPT_FILE = "/api/v1/dsp/file/encrypt"
	URL_DECRYPT_FILE = "/api/v1/dsp/file/decrypt"
)

type EncryptFileReq struct {
	Path     string // should be absolute path at sync node(sync instance)
	Password string
}

type DecryptFileReq struct {
	EncryptFileReq
}
