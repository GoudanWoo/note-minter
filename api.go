package main

import (
	"context"
	"encoding/hex"
	"github.com/gogf/gf/v2/encoding/gjson"
	"github.com/gogf/gf/v2/frame/g"
)

type UTXO struct {
	Address     string `json:"address"`
	TxId        string `json:"txId"`
	OutputIndex uint32 `json:"outputIndex"`
	Height      uint32 `json:"height"`
	Script      string `json:"script"`
	Satoshis    int64  `json:"satoshis"`
	Type        string `json:"type"`
	Time        int64  `json:"time"`
}

func (minter *Minter) getUTXOs(ctx context.Context, scriptHashes g.ArrayStr) []UTXO {
	var err error

	request, err := minter.client.Post(ctx, "/utxos", gjson.MustEncode(g.MapStrAny{
		"scriptHashs": scriptHashes,
	}))
	if err != nil {
		panic(err)
	}
	if request.StatusCode != 200 {
		panic(request.StatusCode)
	}

	var response []UTXO
	err = gjson.DecodeTo(request.ReadAll(), &response)
	if err != nil {
		panic(err)
	}

	return response
}

type Fee struct {
	Slow    int64 `json:"slowFee"`
	Average int64 `json:"avgFee"`
	Fast    int64 `json:"fastFee"`
}

func (minter *Minter) getFee(ctx context.Context) Fee {
	var err error

	request, err := minter.client.Get(ctx, "/fees")
	if err != nil {
		panic(err)
	}
	if request.StatusCode != 200 {
		panic(request.StatusCode)
	}

	var response Fee
	err = gjson.DecodeTo(request.ReadAll(), &response)
	if err != nil {
		panic(err)
	}

	return response
}

type BroadcastResult struct {
	Success bool `json:"success"`
	Error   struct {
		Code    int `json:"code"`
		Message struct {
			Total  string `json:"total"`
			Height uint32 `json:"height"`
			Note   struct {
				Protocol string `json:"p"`
				Operator string `json:"op"`
				Tick     string `json:"tick"`
				Amount   string `json:"amt"`
			} `json:"note"`
			Result string `json:"result"`
		} `json:"message"`
	} `json:"errror"`
}

func (minter *Minter) broadcast(ctx context.Context, raw []byte) BroadcastResult {
	var err error

	request, err := minter.client.Post(ctx, "/broadcast", gjson.MustEncode(g.MapStrAny{
		"rawHex": hex.EncodeToString(raw),
	}))
	if err != nil {
		panic(err)
	}
	if request.StatusCode != 200 {
		panic(request.StatusCode)
	}

	var response BroadcastResult
	err = gjson.DecodeTo(request.ReadAll(), &response)
	if err != nil {
		panic(err)
	}

	return response
}
