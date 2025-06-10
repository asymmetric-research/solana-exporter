package rpc

type (
	VoteAccountData struct {
		AuthorizedVoters     []authorizedVoter `json:"authorizedVoters"`
		AuthorizedWithdrawer string            `json:"authorizedWithdrawer"`
		Commission           int64             `json:"commission"`
		EpochCredits         []epochCredit     `json:"epochCredits"`
		LastTimestamp        lastTimestamp     `json:"lastTimestamp"`
		NodePubkey           string            `json:"nodePubkey"`
		PriorVoters          []string          `json:"priorVoters"`
		RootSlot             int64             `json:"rootSlot"`
		Votes                []vote            `json:"votes"`
	}

	authorizedVoter struct {
		AuthorizedVoter string `json:"authorizedVoter"`
		Epoch           int64  `json:"epoch"`
	}

	epochCredit struct {
		Credits         string `json:"credits"`
		Epoch           int64  `json:"epoch"`
		PreviousCredits string `json:"previousCredits"`
	}

	lastTimestamp struct {
		Slot      int64 `json:"slot"`
		Timestamp int64 `json:"timestamp"`
	}

	vote struct {
		ConfirmationCount int64 `json:"confirmationCount"`
		Slot              int64 `json:"slot"`
	}
)
