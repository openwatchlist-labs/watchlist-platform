package iso20022coverage

func BuildBatch(documents []EvidenceEnvelope) BatchEnvelope {
	b := BatchEnvelope{SchemaVersion: "openwatchlist.iso20022-family-batch.v1", Documents: documents}
	b.BatchSHA256 = hashStruct(b, func(v *BatchEnvelope) { v.BatchSHA256 = "" })
	return b
}
