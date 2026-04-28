package json

import (
	"encoding/json"
	"io"

	"github.com/t3rmit3/assessor/internal/finding"
)

func Write(w io.Writer, r finding.Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
