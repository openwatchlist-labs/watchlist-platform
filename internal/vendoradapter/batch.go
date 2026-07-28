package vendoradapter

import "time"

func ConvertBatch(p Profile, inputs []BatchInput, now time.Time) (Batch, error) {
	b := Batch{SchemaVersion: BatchSchemaV1, AdapterID: p.AdapterID, ProfileSHA256: p.ProfileSHA256, Items: make([]BatchItem, 0, len(inputs))}
	for _, in := range inputs {
		item := BatchItem{SourceRef: in.SourceRef, SourceSHA256: SHA256Bytes(in.Bytes)}
		e, err := Convert(p, in.SourceRef, in.Bytes, now)
		if err != nil {
			item.Status = "rejected"
			item.ErrorCode = errorCode(err)
			item.Error = err.Error()
			b.RejectedCount++
		} else {
			item.Status = "accepted"
			item.Envelope = &e
			b.AcceptedCount++
		}
		b.Items = append(b.Items, item)
	}
	h, err := batchHash(b)
	if err != nil {
		return Batch{}, err
	}
	b.BatchSHA256 = h
	return b, nil
}
