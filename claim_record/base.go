package claim_record

import (
	"github.com/ontio/ontology/common"
	"io"
)

type ClaimTx struct {
	ClaimId      []byte
	IssuerOntId  []byte
	SubjectOntId []byte
	Status       []byte
}

func (this *ClaimTx) Deserialize(source *common.ZeroCopySource) error {
	_, eof := source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	_, _, irregular, eof := source.NextVarUint()
	if irregular {
		return common.ErrIrregularData
	}
	if eof {
		return io.ErrUnexpectedEOF
	}
	_, eof = source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	claimId, err := readVarBytes(source)
	if err != nil {
		return err
	}
	_, eof = source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	issuerOntId, err := readVarBytes(source)
	if err != nil {
		return err
	}
	_, eof = source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	subjectOntId, err := readVarBytes(source)
	if err != nil {
		return err
	}
	_, eof = source.NextByte()
	if eof {
		return io.ErrUnexpectedEOF
	}
	status, err := readVarBytes(source)
	if err != nil {
		return err
	}
	this.ClaimId = claimId
	this.IssuerOntId = issuerOntId
	this.SubjectOntId = subjectOntId
	this.Status = status
	return nil
}

func readVarBytes(source *common.ZeroCopySource) ([]byte, error) {
	bs, _, irregular, eof := source.NextVarBytes()
	if irregular {
		return nil, common.ErrIrregularData
	}
	if eof {
		return nil, io.ErrUnexpectedEOF
	}
	return bs, nil
}
