module github.com/forestrie/go-merklelog/massifs

go 1.24

require github.com/forestrie/go-merklelog/mmr v0.0.2

replace github.com/forestrie/go-merklelog/mmr => ../mmr

require (
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.11.1
	github.com/veraison/go-cose v1.1.0
)

require github.com/kr/text v0.2.0 // indirect

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fxamacker/cbor/v2 v2.7.0
	github.com/ldclabs/cose/go v0.0.0-20221214142927-d22c1cfc2154
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
