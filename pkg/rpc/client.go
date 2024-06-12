package rpc

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"k8s.io/klog/v2"
	"net/http"
)

type (
	Client struct {
		httpClient http.Client
		rpcAddr    string
	}

	rpcError struct {
		Message string `json:"message"`
		Code    int64  `json:"id"`
	}

	rpcError2 struct {
		Message string `json:"message"`
		Code    int64  `json:"code"`
	}

	rpcRequest struct {
		Version string        `json:"jsonrpc"`
		ID      int           `json:"id"`
		Method  string        `json:"method"`
		Params  []interface{} `json:"params"`
	}

	Commitment string
)

func (c Commitment) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"commitment": string(c)})
}

const (
	// CommitmentFinalized refers to the most recent block confirmed by cluster super-majority as having reached maximum lockout.
	CommitmentFinalized Commitment = "finalized"
	// CommitmentProcessed refers to the most recent processed block.
	CommitmentProcessed Commitment = "recent"
)

func NewRPCClient(rpcAddr string) *Client {
	c := &Client{
		httpClient: http.Client{},
		rpcAddr:    rpcAddr,
	}

	return c
}

func formatRPCRequest(method string, params []interface{}) io.Reader {
	r := &rpcRequest{
		Version: "2.0",
		ID:      1,
		Method:  method,
		Params:  params,
	}

	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}

	klog.V(2).Infof("jsonrpc request: %s", string(b))
	return bytes.NewBuffer(b)
}

func (c *Client) rpcRequest(ctx context.Context, data io.Reader) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.rpcAddr, data)
	if err != nil {
		panic(err)
	}
	req.Header.Set("content-type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	//goland:noinspection GoUnhandledErrorResult
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
