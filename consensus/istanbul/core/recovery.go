package core

import (
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	// "github.com/jpmorganchase/quorum/swarm/log"

	// "github.com/ethereum/go-ethereum/crypto/ed25519"

	"crypto/sha256"

	// "github.com/ethereum/go-ethereum/crypto/ed25519"

	"github.com/ethereum/go-ethereum/common"
	crypto "github.com/ethereum/go-ethereum/crypto"
	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/onrik/gomerkle"

	// "github.com/ethereum/go-ethereum/consensus/istanbul"
	// "github.com/ethereum/go-ethereum/crypto/ed25519"
	ed25519 "github.com/ethereum/go-ethereum/filippo.io/edwards25519"
)

// SendReqMerklePath sends a request for the merkle path for a reconstruct message , if it had not received a valid message from leader.
func (c *core) SendReqMerklePath(seq uint64, addr common.Address) {

	index := c.getIndex(addr)

	req, err := Encode(&istanbul.ReqMerklePath{
		Seq: seq,
	})
	if err != nil {
		log.Error("Failed to encode reqMerklePathMessage message", "number", seq)
		return
	}
	c.sendToNode(addr, &message{
		Code: msgReqMerklePath,
		Msg:  req,
	})
	log.Info("Sent MerklePath Request message to", "node", index, "for number", seq)

}

// SendReqMultiSig sends a request for mulitisig on root
func (c *core) SendReqMultiSig(seq uint64, addr common.Address) {

	index := c.getIndex(addr)

	req, err := Encode(&istanbul.ReqMultiSig{
		Seq: seq,
	})
	if err != nil {
		log.Error("Failed to encode reqMultiSig message", "number", seq)
		return
	}
	c.sendToNode(addr, &message{
		Code: msgReqMultiSig,
		Msg:  req,
	})

	// if senderr != nil {
	// 	log.Error("Failed to send reqMultiSig message")
	// 	return
	// }

	log.Info("Sent MultiSig Request message to", "node", index, "for number", seq)
	return
}

// handleReqMerklePath sends Merkle Path
func (c *core) handleReqMerklePath(msg *message, src istanbul.Validator) error {

	index := c.getIndex(src.Address())
	log.Debug("Handling req for Merkle Path message from", "addr", src.Address(), "index", index)

	var rmsg *istanbul.ReqMerklePath
	err := msg.Decode(&rmsg)
	if err != nil {
		log.Error("ReqMerklePath decoding failed", "from", src.Address(), "index", "err", err)
		return errFailedDecodeReqMerklePath
	}

	rSeq := rmsg.Seq

	//@Vinith: Use Node Agg Data to get merkle root
	aData, ok := c.nodeAggData[rSeq]

	if !ok {
		log.Error("No agg data", "number", rSeq)
		return errAggDataNotFound
	}

	myindex := c.addrIDMap[c.Address()]

	encEval := aData.EncEvals[myindex] // aggregated encrypted data
	// recData := crypto.ReconstructData(encEval, c.edKey.Pkey, c.edKey.Skey)
	// irecData := istanbul.RecDataEncode(recData)

	// TODO(@vinith): Optimize to create the tree only once.
	_, tree := crypto.AggrMerkleRoot(aData.IndexSet, aData.Points, aData.EncEvals)
	leafindex := len(aData.IndexSet) + c.addrIDMap[c.Address()]

	proof := tree.GetProof(leafindex)
	iproof := istanbul.MerkleProofEncode(proof)

	// recData.Index = uint64(index)

	recovery, err := Encode(&istanbul.MerkleRecovery{
		Seq:      rSeq,
		EncProof: iproof,
		EncEval:  encEval.Bytes(),
		Root:     tree.Root(),
	})

	if err != nil {
		log.Error("Failed to encode recovery message", "number", rSeq)
		return errFailedEncodeMerklPath
	}

	// mpathData := istanbul.MerklePathEncode(rSeq, "This your requested merkle path:"+strconv.Itoa(index))
	// encPath, err := Encode(&mpathData)

	// if err != nil {
	// 	log.Error("Failed to encode MerklePath", "number", rSeq)
	// 	return errFailedEncodeMerklPath
	// }

	c.sendToNode(src.Address(), &message{
		Code: msgMerklePath,
		Msg:  recovery,
	})

	log.Info("Sent merkle path to ", "node", index, "for number:", rSeq)

	// check whether aggregate data is available or not
	// _, aok := c.nodeAggData[rSeq]
	// if !aok {
	// 	log.Error("PrePrepare message not received from leader")
	// 	c.SendReqMerklePath(rSeq,src.Address) // should i make this asynchronous?
	// 	return errAggDataNotFound
	// }

	// recon := istanbul.RecDataDecode(rmsg.RecData)
	// rIndex := recon.Index
	//@Vinith TODO: Uncomment the following lines
	// rPkey := c.pubKeys[src.Address()]
	// encShare := aData.EncEvals[rIndex]

	// if !crypto.ValidateReconstruct(*rPkey, encShare, recon.DecShare, recon.Proof) {
	// 	log.Error("Invalid reconstruct message", "from", src.Address(), "index", rIndex)
	// 	return errInvalidReconstruct
	// }
	// c.addReconstruct(rSeq, rIndex, recon.DecShare)
	return errHandleReqMerklePath
}

// handleReqMultiSig sends MultiSig
func (c *core) handleReqMultiSig(msg *message, src istanbul.Validator) error {
	log.Info("Inside handleReqMultiSig ")
	index := c.getIndex(src.Address())
	log.Debug("Handling req for Multisig message from", "addr", src.Address(), "index", index)

	var rmsg *istanbul.ReqMultiSig
	err := msg.Decode(&rmsg)
	if err != nil {
		log.Error("ReqMultiSig decoding failed", "from", src.Address(), "index", "err", err)
		return errFailedDecodeReqMultiSig
	}

	rSeq := rmsg.Seq

	c.nodeMu.RLock()
	//@Vinith: Use Node Agg Data to get merkle root
	if _, ok := c.nodeDecidedRoot[rSeq]; !ok {
		log.Error("No decided root")
	}
	log.Info("Decided Root", "value", c.nodeDecidedRoot[rSeq])

	if _, ok := c.nodeDecidedCommitCert[rSeq]; !ok {
		log.Error("No decided CommitCert")
	}

	log.Info("Decided Cert", "value", *c.nodeDecidedCommitCert[rSeq])

	msigData := istanbul.MultiSigEncode(rSeq, c.nodeDecidedRoot[rSeq], *c.nodeDecidedCommitCert[rSeq])
	msig, err := Encode(&msigData)

	if err != nil {
		log.Error("Failed to encode MultiSig", "error", err, "seq", rSeq, "root", c.nodeDecidedRoot[rSeq], "commitcert", c.nodeDecidedCommitCert[rSeq])
		// return errFailedEncodeMultiSig
	}
	c.nodeMu.RUnlock()

	c.sendToNode(src.Address(), &message{
		Code: msgMultiSig,
		Msg:  msig,
	})

	log.Info("Sent multsig to ", "node", index, "for number:", rSeq)

	// check whether aggregate data is available or not
	// _, aok := c.nodeAggData[rSeq]
	// if !aok {
	// 	log.Error("PrePrepare message not received from leader")
	// 	c.SendReqMerklePath(rSeq,src.Address) // should i make this asynchronous?
	// 	return errAggDataNotFound
	// }

	// recon := istanbul.RecDataDecode(rmsg.RecData)
	// rIndex := recon.Index
	//@Vinith TODO: Uncomment the following lines
	// rPkey := c.pubKeys[src.Address()]
	// encShare := aData.EncEvals[rIndex]

	// if !crypto.ValidateReconstruct(*rPkey, encShare, recon.DecShare, recon.Proof) {
	// 	log.Error("Invalid reconstruct message", "from", src.Address(), "index", rIndex)
	// 	return errInvalidReconstruct
	// }
	// c.addReconstruct(rSeq, rIndex, recon.DecShare)
	return errHandleReqMultiSig
}

// handleMerklePath handles Merkle Path message
func (c *core) handleMerklePath(msg *message, src istanbul.Validator) error {
	c.nodeMu.Lock()
	defer c.nodeMu.Unlock()

	// NOTE: Lock might be required in the future
	index := uint64(c.getIndex(src.Address()))

	log.Debug("Handling req for Merkle Path message from", "addr", src.Address(), "index", index)

	var rmsg *istanbul.MerkleRecovery
	err := msg.Decode(&rmsg)
	if err != nil {
		log.Error("MerklePath decoding failed", "from", src.Address(), "index", "err", err)
		return errFailedDecodeMerklePath
	}

	// _ = istanbul.RecDataDecode(rmsg.RecData)
	rSeq := rmsg.Seq
	rEncProof := istanbul.MerkleProofDecode(rmsg.EncProof)
	rEncEval := rmsg.EncEval
	rRoot := rmsg.Root

	// log.Info(" Received root,Decided Root:", "Received", common.BytesToHash(rRoot), "Decided", c.nodeDecidedRoot[rSeq])

	hash := sha256.New()
	hash.Write(rEncEval)
	leaf := hash.Sum(nil)

	newtree := gomerkle.NewTree(sha256.New())
	if !newtree.VerifyProof(rEncProof, rRoot, leaf) {
		log.Error(" Merkle proof verification failed")
		return errHandleMerkleProof
	}

	log.Info("Merkle Path verified!", rSeq)

	// Beacon output already available, no need to process further
	if _, rok := c.beacon[rSeq]; rok {
		return errHandleReconstruct // @Vinith:change this
	}

	share := c.nodeRecData[rSeq][index].DecShare
	c.addReconstruct(rSeq, index, share)

	// check whether aggregate data is available or not
	// _, aok := c.nodeAggData[rSeq]
	// if !aok {
	// 	log.Error("PrePrepare message not received from leader")
	// 	c.SendReqMerklePath(rSeq,src.Address) // should i make this asynchronous?
	// 	return errAggDataNotFound
	// }

	// recon := istanbul.RecDataDecode(rmsg.RecData)
	rIndex := c.nodeRecData[rSeq][index].Index
	//@Vinith TODO: Uncomment the following lines
	rPkey := c.pubKeys[src.Address()]
	// encShare := aData.EncEvals[rIndex]
	encEval, _ := ed25519.NewIdentityPoint().SetBytes(rEncEval)

	if !crypto.ValidateReconstruct(*rPkey, *encEval, share, c.nodeRecData[rSeq][index].Proof) {
		log.Error("Invalid reconstruct message after receiving Merkle Path", "from", src.Address(), "index", rIndex)
		// return errInvalidReconstruct
	}
	// c.addReconstruct(rSeq, rIndex, recon.DecShare)
	return errHandleMerklePath
}

// handleMultiSig handles MultiSig message
func (c *core) handleMultiSig(msg *message, src istanbul.Validator) error {
	c.nodeMu.Lock()
	defer c.nodeMu.Unlock()

	// NOTE: Lock might be required in the future
	index := uint64(c.getIndex(src.Address()))

	log.Debug("Handling Multi sig message from", "addr", src.Address(), "index", index)

	var rmsg *istanbul.MultiSig
	err := msg.Decode(&rmsg)
	if err != nil {
		log.Error("MultiSig decoding failed", "from", src.Address(), "index", "err", err)
		return errFailedDecodeMultiSig
	}

	rRoot := rmsg.Root
	rSeq := rmsg.Seq

	log.Info(" Received multisig:", "rootHash", rRoot, "Number", rSeq, "from", index)

	log.Debug("Root added and notified!", rSeq)
	c.nodeDecidedRoot[rSeq] = rRoot

	// musltig verification up ahead

	var pubkeys []*bn256.G2

	for _, value := range c.blspubKeys {
		pubkeys = append(pubkeys, value)
	}

	apk, _ := crypto.KeyAgg(pubkeys)
	aggkey := new(bn256.G2)
	_, err1 := aggkey.Unmarshal(rmsg.Sig.Aggpk)
	if err1 != nil {
		log.Error("aggpk not unmarshable")
	}
	aggsig := new(bn256.G1)
	_, err2 := aggsig.Unmarshal(rmsg.Sig.Aggsig)

	if err2 != nil {
		log.Error("aggsig not unmarshable")
	}
	var nodelist []int
	for _, value := range rmsg.Sig.Nodelist {
		nodelist = append(nodelist, int(value))
	}
	if !crypto.Verify(nodelist, apk, rRoot.Bytes(), aggkey, aggsig) {
		log.Error("Invalid Multisig")
		log.Info("the recieved values are as follows", "seq", rSeq, "nodelist", nodelist, "apk", apk, "roothash in bytes", rRoot.Bytes(), "aggkey", aggkey, "aggsig", aggsig)
		// return errInvalidMultiSig
	} else {
		log.Info("Valid multisig received")
	}

	// Beacon output already available, no need to process further
	if _, rok := c.beacon[rSeq]; rok {
		return errHandleReconstruct
	}

	//check whether aggregate data is available or not
	aData, aok := c.nodeAggData[rSeq]
	if !aok {
		log.Error("Multisig received but Private message not received from leader")
		c.SendReqMerklePath(rSeq, src.Address()) // should i make this asynchronous?
		return errAggDataNotFound
	}

	share := c.nodeRecData[rSeq][index].DecShare
	// if rRoot == c.nodeAggData[rSeq].Root {
	// 	c.addReconstruct(rSeq, index, share)
	// } else {
	// 	return errInconsistentMultiSig
	// }

	// go c.sendReconstruct(rSeq, rRoot)

	c.addReconstruct(rSeq, index, share)

	go c.sendReconstruct(rSeq, rRoot)

	// recon := istanbul.RecDataDecode(rmsg.RecData)
	rIndex := c.nodeRecData[rSeq][index].Index
	//@Vinith TODO: Uncomment the following lines
	rPkey := c.pubKeys[src.Address()]
	encShare := aData.EncEvals[rIndex]

	if !crypto.ValidateReconstruct(*rPkey, encShare, share, c.nodeRecData[rSeq][index].Proof) {
		log.Error("Invalid reconstruct message in MultiSig", "from", src.Address(), "index", rIndex)
		// return errInvalidReconstruct
	}
	// c.addReconstruct(rSeq, rIndex, recon.DecShare)
	return errHandleMultiSig
}