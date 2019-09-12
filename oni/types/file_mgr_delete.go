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

type FileMgrDelete interface {
	DeleteFile(req *DeleteFileReq) (*DeleteFileResp, error)
	DeleteFiles(req *DeleteFilesReq) (*DeleteFilesResp, error)
}

const (
	URL_DELETE_FILE  = "/api/v1/dsp/file/delete"
	URL_DELETE_FILES = "/api/v1/dsp/files/delete"
)

// if uploaded file, delete it from saved node
// if download file, delete it from local
type DeleteFileReq struct {
	Hash string
}

type Node struct {
	HostAddr string
	Code     uint
	Error    string
}

type DeleteFileResp struct {
	Tx         string
	FileHash   string
	FileName   string
	Nodes      []*Node
	IsUploaded bool
}

type DeleteFilesReq struct {
	Hash []string
}

type DeleteFilesResp []DeleteFileResp
