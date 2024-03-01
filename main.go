package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/gogf/gf/v2/container/gvar"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/gclient"
	"github.com/tyler-smith/go-bip39"
	"github.com/vmihailenco/msgpack/v5"
	"slices"
)

type Minter struct {
	client  *gclient.Client
	bitwork []byte

	privateKey *btcec.PrivateKey
	publicKey  *secp256k1.PublicKey

	tapLeafNote             txscript.TapLeaf
	tapLeafNoteHash         chainhash.Hash
	tapLeafNoteControlBlock []byte
	tapLeafP2pk             txscript.TapLeaf
	tapLeafP2pkHash         chainhash.Hash
	tapLeafP2pkControlBlock []byte
	tapTree                 *txscript.IndexedTapScriptTree
	tapTreeHash             chainhash.Hash

	tokenAddressScript   []byte
	tokenAddressHash     string
	fundingAddressScript []byte
	fundingAddressHash   string

	payload              []byte
	tokenUTXOSequence    uint32
	tokenUTXOValue       int64
	fundingUTXOSequences []uint32
	fundingUTXOValues    []int64
	inputs               []*wire.OutPoint
	outputs              []*wire.TxOut
}

func (minter *Minter) InitWallet(mnemonic string) {
	var err error

	minter.client = g.Client().
		SetPrefix("https://btc.urchain.com/api").
		SetHeader("Authorization", "Bearer 1234567890")
	minter.bitwork = []byte("20")

	seed := bip39.NewSeed(mnemonic, "")
	extendedKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		panic(err)
	}
	derivationPath, err := accounts.ParseDerivationPath("m/44'/0'/0'/0/0")
	for _, n := range derivationPath {
		extendedKey, err = extendedKey.Derive(n)
		if err != nil {
			panic(err)
		}
	}
	minter.privateKey, err = extendedKey.ECPrivKey()
	if err != nil {
		panic(err)
	}

	minter.publicKey = minter.privateKey.PubKey()

	scriptNote, err := txscript.NewScriptBuilder().AddData([]byte("NOTE")).AddOps([]byte{txscript.OP_2DROP, txscript.OP_2DROP, txscript.OP_2DROP}).AddData(schnorr.SerializePubKey(minter.publicKey)).AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		panic(err)
	}
	scriptP2pk, err := txscript.NewScriptBuilder().AddData(minter.publicKey.SerializeCompressed()).AddOp(txscript.OP_CHECKSIG).Script()
	if err != nil {
		panic(err)
	}
	minter.tapLeafNote = txscript.NewBaseTapLeaf(scriptNote)
	minter.tapLeafNoteHash = minter.tapLeafNote.TapHash()
	minter.tapLeafP2pk = txscript.NewBaseTapLeaf(scriptP2pk)
	minter.tapLeafP2pkHash = minter.tapLeafP2pk.TapHash()
	minter.tapTree = txscript.AssembleTaprootScriptTree(
		minter.tapLeafNote,
		minter.tapLeafP2pk,
	)
	minter.tapTreeHash = minter.tapTree.RootNode.TapHash()
	for i := range minter.tapTree.LeafMerkleProofs {
		switch minter.tapTree.LeafMerkleProofs[i].TapHash() {
		case minter.tapLeafNoteHash:
			tapLeafNoteControlBlock := minter.tapTree.LeafMerkleProofs[i].ToControlBlock(minter.publicKey)
			minter.tapLeafNoteControlBlock, err = tapLeafNoteControlBlock.ToBytes()
			if err != nil {
				panic(err)
			}
		case minter.tapLeafP2pkHash:
			tapLeafP2pkControlBlock := minter.tapTree.LeafMerkleProofs[i].ToControlBlock(minter.publicKey)
			minter.tapLeafP2pkControlBlock, err = tapLeafP2pkControlBlock.ToBytes()
			if err != nil {
				panic(err)
			}
		}
	}

	tokenAddress, err := GetTaprootAddress(minter.publicKey, minter.tapTreeHash[:])
	if err != nil {
		panic(err)
	}
	minter.tokenAddressScript, err = txscript.PayToAddrScript(tokenAddress)
	if err != nil {
		panic(err)
	}
	tokenAddressHash := Sha256(minter.tokenAddressScript)
	slices.Reverse(tokenAddressHash)
	minter.tokenAddressHash = hex.EncodeToString(tokenAddressHash)

	fundingAddress, err := GetNativeSegWitAddress(minter.publicKey)
	if err != nil {
		panic(err)
	}
	minter.fundingAddressScript, err = txscript.PayToAddrScript(fundingAddress)
	if err != nil {
		panic(err)
	}
	fundingAddressHash := Sha256(minter.fundingAddressScript)
	slices.Reverse(fundingAddressHash)
	minter.fundingAddressHash = hex.EncodeToString(fundingAddressHash)
}

func (minter *Minter) Mint(ctx context.Context, memo Memo) []byte {
	var err error

	payload := new(bytes.Buffer)
	msgpackEncoder := msgpack.NewEncoder(payload)
	msgpackEncoder.SetSortMapKeys(true)
	err = msgpackEncoder.Encode(gvar.New(memo).MapStrAny())
	if err != nil {
		panic(err)
	}
	minter.payload = payload.Bytes()

	// 输入

	inputValue := int64(0)

	tokenUTXOs := minter.getUTXOs(ctx, g.ArrayStr{minter.tokenAddressHash})
	if len(tokenUTXOs) == 0 {
		panic("未找到可用的代币伴生UTXO")
	}

	tokenUTXOId, err := chainhash.NewHashFromStr(tokenUTXOs[0].TxId)
	if err != nil {
		panic(err)
	}
	tokenUTXOPoint := wire.NewOutPoint(tokenUTXOId, tokenUTXOs[0].OutputIndex)
	minter.tokenUTXOValue = tokenUTXOs[0].Satoshis
	inputValue += minter.tokenUTXOValue
	minter.tokenUTXOSequence = wire.MaxTxInSequenceNum

	fundingUTXOs := minter.getUTXOs(ctx, g.ArrayStr{minter.fundingAddressHash})
	if len(fundingUTXOs) == 0 {
		panic("未找到可用的付款UTXO")
	}

	fundingUTXOPoints := make([]*wire.OutPoint, len(fundingUTXOs))
	minter.fundingUTXOValues = make([]int64, len(fundingUTXOs))
	minter.fundingUTXOSequences = make([]uint32, len(fundingUTXOs))
	for i := range fundingUTXOs {
		fundingUTXOId, err := chainhash.NewHashFromStr(fundingUTXOs[i].TxId)
		if err != nil {
			panic(err)
		}
		fundingUTXOPoints[i] = wire.NewOutPoint(fundingUTXOId, fundingUTXOs[i].OutputIndex)
		minter.fundingUTXOValues[i] = fundingUTXOs[i].Satoshis
		inputValue += minter.fundingUTXOValues[i]
		minter.fundingUTXOSequences[i] = wire.MaxTxInSequenceNum
	}

	minter.inputs = append([]*wire.OutPoint{
		tokenUTXOPoint,
	}, fundingUTXOPoints...)

	// 手续费

	fee := minter.getFee(ctx)
	size := 248. // todo 实时计算真实 vSize
	feeValue := int64(float64(fee.Average)/1000*size + 1)

	// 输出

	changeValue := inputValue - 546 - feeValue

	if changeValue < 0 {
		panic("余额不足")
	} else if changeValue < 546 {
		minter.outputs = []*wire.TxOut{
			wire.NewTxOut(546, minter.tokenAddressScript),
		}
	} else {
		minter.outputs = []*wire.TxOut{
			wire.NewTxOut(546, minter.tokenAddressScript),
			wire.NewTxOut(changeValue, minter.fundingAddressScript),
		}
	}

	for lockTime := uint32(0); lockTime < 0xffffffff; lockTime++ {
		raw := minter.structureTx(lockTime)
		hash := Sha256(Sha256(raw))
		if bytes.HasPrefix(hash, minter.bitwork) {
			g.Log().Infof(ctx, "raw transaction: %x", raw)
			return raw
		}
	}

	return nil
}

func (minter *Minter) structureTx(lockTime uint32) []byte {
	var err error

	// 构造交易

	psbtPacket, err := psbt.New(minter.inputs, minter.outputs, 2, lockTime, append([]uint32{minter.tokenUTXOSequence}, minter.fundingUTXOSequences...))
	if err != nil {
		panic(err)
	}

	psbtUpdater, err := psbt.NewUpdater(psbtPacket)
	if err != nil {
		panic(err)
	}

	if err = psbtUpdater.AddInWitnessUtxo(wire.NewTxOut(minter.tokenUTXOValue, minter.tokenAddressScript), 0); err != nil {
		panic(err)
	}
	for i := range minter.fundingUTXOValues {
		if err = psbtUpdater.AddInWitnessUtxo(wire.NewTxOut(minter.fundingUTXOValues[i], minter.fundingAddressScript), 1+i); err != nil {
			panic(err)
		}
	}

	// 签名

	if err = psbt.InputsReadyToSign(psbtPacket); err != nil {
		panic(err)
	}

	sigHashes := txscript.NewTxSigHashes(psbtPacket.UnsignedTx, wallet.PsbtPrevOutputFetcher(psbtPacket))

	signature, err := txscript.RawTxInTapscriptSignature(psbtPacket.UnsignedTx, sigHashes, 0, psbtPacket.Inputs[0].WitnessUtxo.Value, psbtPacket.Inputs[0].WitnessUtxo.PkScript, minter.tapLeafNote, txscript.SigHashDefault, minter.privateKey)
	if err != nil {
		panic(err)
	}
	psbtUpdater.Upsbt.Inputs[0].TaprootLeafScript = append(psbtUpdater.Upsbt.Inputs[0].TaprootLeafScript, &psbt.TaprootTapLeafScript{
		ControlBlock: minter.tapLeafNoteControlBlock,
		Script:       minter.tapLeafNote.Script,
		LeafVersion:  minter.tapLeafNote.LeafVersion,
	})
	finalScriptWitness := new(bytes.Buffer)
	err = psbt.WriteTxWitness(finalScriptWitness, [][]byte{
		signature,
		minter.payload,
		nil,
		nil,
		nil,
		nil,
		minter.tapLeafNote.Script,
		minter.tapLeafNoteControlBlock,
	})
	if err != nil {
		panic(err)
	}
	psbtUpdater.Upsbt.Inputs[0].FinalScriptWitness = finalScriptWitness.Bytes()

	for i := range minter.fundingUTXOValues {
		witness, err := txscript.WitnessSignature(psbtPacket.UnsignedTx, sigHashes, 1+i, psbtPacket.Inputs[1+i].WitnessUtxo.Value, psbtPacket.Inputs[1+i].WitnessUtxo.PkScript, txscript.SigHashAll, minter.privateKey, true)
		if err != nil {
			panic(err)
		}
		signResult, err := psbtUpdater.Sign(1+i, witness[0], minter.publicKey.SerializeCompressed(), nil, nil)
		if err != nil {
			panic(err)
		}
		if signResult != psbt.SignSuccesful {
			panic(signResult)
		}
		err = psbt.Finalize(psbtPacket, 1+i)
		if err != nil {
			panic(err)
		}
	}

	tx, err := psbt.Extract(psbtPacket)
	if err != nil {
		panic(err)
	}
	raw := new(bytes.Buffer)
	err = tx.Serialize(raw)
	if err != nil {
		panic(err)
	}

	return raw.Bytes()
}

func main() {
	ctx := context.Background()

	var minter Minter
	minter.InitWallet("助记词")

	memo := Memo{
		Protocol: "n20",
		Operator: "mint",
		Tick:     "NOTE",
		Amount:   39_0625_0000,
	}
	for {
		raw := minter.Mint(ctx, memo)
		if raw == nil {
			g.Log().Error(ctx, "无法找到符合条件的交易数据")
		}

		result := minter.broadcast(ctx, raw)

		if !result.Success {
			if result.Error.Code == 400 {
				if result.Error.Message.Result == "VerifyError: SCRIPT_ERR_EVAL_FALSE_IN_STACK, fails at OP_ENDIF\n" {
					g.Log().Warningf(ctx, "减产, 请调整 memo.Amount 为 %d", memo.Amount/2)
					break // 手动调整，便于确认调整后是否还有利润
				}
			} else if result.Error.Code == 0 {
				g.Log().Warning(ctx, "无法广播")
				break
			}
		}
		//time.Sleep(1 * time.Second)
	}
}
