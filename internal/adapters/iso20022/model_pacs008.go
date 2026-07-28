package iso20022

import "encoding/xml"

type textValue struct {
	Value string
}

func (value *textValue) UnmarshalXML(decoder *xml.Decoder, start xml.StartElement) error {
	return decoder.DecodeElement(&value.Value, &start)
}

type pacs008Document struct {
	XMLName  xml.Name              `xml:"Document"`
	Transfer pacs008CreditTransfer `xml:"FIToFICstmrCdtTrf"`
}

type pacs008CreditTransfer struct {
	GroupHeader  pacs008GroupHeader   `xml:"GrpHdr"`
	Transactions []pacs008Transaction `xml:"CdtTrfTxInf"`
}

type pacs008GroupHeader struct {
	MessageID        *textValue `xml:"MsgId"`
	CreationDateTime *textValue `xml:"CreDtTm"`
	NumberOfTxs      *textValue `xml:"NbOfTxs"`
}

type pacs008Transaction struct {
	PaymentID               pacs008PaymentID            `xml:"PmtId"`
	InterbankSettlementAmt  *amountValue                `xml:"IntrBkSttlmAmt"`
	InterbankSettlementDate *textValue                  `xml:"IntrBkSttlmDt"`
	Debtor                  *partyIdentification        `xml:"Dbtr"`
	UltimateDebtor          *partyIdentification        `xml:"UltmtDbtr"`
	DebtorAccount           *cashAccount                `xml:"DbtrAcct"`
	DebtorAgent             *branchFinancialInstitution `xml:"DbtrAgt"`
	CreditorAgent           *branchFinancialInstitution `xml:"CdtrAgt"`
	Creditor                *partyIdentification        `xml:"Cdtr"`
	UltimateCreditor        *partyIdentification        `xml:"UltmtCdtr"`
	CreditorAccount         *cashAccount                `xml:"CdtrAcct"`
	Remittance              *remittanceInformation      `xml:"RmtInf"`
}

type pacs008PaymentID struct {
	InstructionID *textValue `xml:"InstrId"`
	EndToEndID    *textValue `xml:"EndToEndId"`
	TransactionID *textValue `xml:"TxId"`
	UETR          *textValue `xml:"UETR"`
}

type amountValue struct {
	Currency string `xml:"Ccy,attr"`
	Value    string `xml:",chardata"`
}

type partyIdentification struct {
	Name           *textValue     `xml:"Nm"`
	PostalAddress  *postalAddress `xml:"PstlAdr"`
	Identification *partyIDChoice `xml:"Id"`
}

type partyIDChoice struct {
	Organisation *organisationIdentification `xml:"OrgId"`
	Private      *personIdentification       `xml:"PrvtId"`
}

type organisationIdentification struct {
	LEI *textValue `xml:"LEI"`
}

type personIdentification struct {
	Birth *dateAndPlaceOfBirth `xml:"DtAndPlcOfBirth"`
}

type dateAndPlaceOfBirth struct {
	BirthDate *textValue `xml:"BirthDt"`
}

type postalAddress struct {
	TownName     *textValue `xml:"TwnNm"`
	Country      *textValue `xml:"Ctry"`
	AddressLines []string   `xml:"AdrLine"`
}

type cashAccount struct {
	Identification accountIDChoice `xml:"Id"`
}

type accountIDChoice struct {
	IBAN  *textValue        `xml:"IBAN"`
	Other *genericAccountID `xml:"Othr"`
}

type genericAccountID struct {
	ID *textValue `xml:"Id"`
}

type branchFinancialInstitution struct {
	Institution financialInstitutionIdentification `xml:"FinInstnId"`
}

type financialInstitutionIdentification struct {
	BICFI         *textValue     `xml:"BICFI"`
	LEI           *textValue     `xml:"LEI"`
	Name          *textValue     `xml:"Nm"`
	PostalAddress *postalAddress `xml:"PstlAdr"`
}

type remittanceInformation struct {
	Unstructured []string `xml:"Ustrd"`
}
