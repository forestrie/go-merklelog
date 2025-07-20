package storageschema

const (
	V1MMRPathSep                   = "/"
	V1MMRExtSep                    = "."
	V1MMRMassifExt                 = "log"
	V1MMRBlobNameFmt               = "%016d.log"
	V1MMRSignedTreeHeadBlobNameFmt = "%016d.sth"
	V1MMRSealSignedRootExt         = "sth" // Signed Tree Head
	// LogInstanceN refers to the approach for handling blob size and format changes discussed at
	// [Changing the massifheight for a log](https://github.com/datatrails/epic-8120-scalable-proof-mechanisms/blob/1cb966cc10af03ae041fea4bca44b10979fb1eda/mmr/forestrie-mmrblobs.md#changing-the-massifheight-for-a-log)

	LogInstanceN = 0
)