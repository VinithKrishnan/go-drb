// Copyright 2017 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"bytes"
	"math"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/istanbul"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ed25519"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/log"
	metrics "github.com/ethereum/go-ethereum/metrics"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

// New creates an Istanbul consensus core
func New(backend istanbul.Backend, config *istanbul.Config) Engine {
	r := metrics.NewRegistry()
	c := &core{
		config:             config,
		address:            backend.Address(),
		state:              StateAcceptRequest,
		handlerWg:          new(sync.WaitGroup),
		logger:             log.New("address", backend.Address()),
		backend:            backend,
		backlogs:           make(map[common.Address]*prque.Prque),
		backlogsMu:         new(sync.Mutex),
		pendingRequests:    prque.New(),
		pendingRequestsMu:  new(sync.Mutex),
		consensusTimestamp: time.Time{},
		roundMeter:         metrics.NewMeter(),
		sequenceMeter:      metrics.NewMeter(),
		consensusTimer:     metrics.NewTimer(),
		startSeq:           config.StartSeq,
		index:              config.NodeIndex,
		local:              config.Local,
		commitmentCh:       make(chan *istanbul.View),
		privDataCh:         make(chan *istanbul.View),
		pubKeys:            make(map[common.Address]ed25519.Point),
		addrIDMap:          make(map[common.Address]int),
		idAddrMap:          make(map[int]common.Address),
		indexSets:          make(map[uint64][]common.Address),
		leaderData:         make(map[uint64]map[common.Address]crypto.NodeData),
		leaderAggData:      make(map[uint64]crypto.NodeData),
		nodeAggData:        make(map[uint64]crypto.NodeData),
		nodePrivData:       make(map[uint64]crypto.RoundData),
		nodeRecData:        make(map[uint64]map[uint64]ed25519.Point),
		beacon:             make(map[uint64]ed25519.Point),
	}

	r.Register("consensus/istanbul/core/round", c.roundMeter)
	r.Register("consensus/istanbul/core/sequence", c.sequenceMeter)
	r.Register("consensus/istanbul/core/consensus", c.consensusTimer)

	c.validateFn = c.checkValidatorSignature
	return c
}

// ----------------------------------------------------------------------------

type core struct {
	config  *istanbul.Config
	address common.Address
	state   State
	logger  log.Logger

	// drb misc
	index int
	local bool

	// drb
	numNodes     int
	threshold    int
	startSeq     uint64
	commitmentCh chan *istanbul.View // channel to indicate enough commitment
	privDataCh   chan *istanbul.View // channel to indicate that aggregate data has been received

	// drb data
	edKey     types.Key // secret key of the node
	pubKeys   map[common.Address]ed25519.Point
	addrIDMap map[common.Address]int
	idAddrMap map[int]common.Address

	// For leader of a round
	leaderMu      sync.RWMutex
	indexSets     map[uint64][]common.Address                   // stores aggregated index
	leaderData    map[uint64]map[common.Address]crypto.NodeData // height:{addr:NodeData}
	leaderAggData map[uint64]crypto.NodeData                    // to store the aggregated value at a leader

	// for other nodes
	nodeMu       sync.RWMutex
	nodeAggData  map[uint64]crypto.NodeData          // height: [agg. poly. commit; agg. enc]
	nodePrivData map[uint64]crypto.RoundData         // height: node's private data for aggregated commitment
	nodeRecData  map[uint64]map[uint64]ed25519.Point // height: {index:share}
	beacon       map[uint64]ed25519.Point            // height: beacon-output

	backend               istanbul.Backend
	events                *event.TypeMuxSubscription
	finalCommittedSub     *event.TypeMuxSubscription
	timeoutSub            *event.TypeMuxSubscription
	futurePreprepareTimer *time.Timer

	valSet                istanbul.ValidatorSet
	waitingForRoundChange bool
	validateFn            func([]byte, []byte) (common.Address, error)

	backlogs   map[common.Address]*prque.Prque
	backlogsMu *sync.Mutex

	current   *roundState
	handlerWg *sync.WaitGroup

	roundChangeSet   *roundChangeSet
	roundChangeTimer *time.Timer

	pendingRequests   *prque.Prque
	pendingRequestsMu *sync.Mutex

	consensusTimestamp time.Time
	// the meter to record the round change rate
	roundMeter metrics.Meter
	// the meter to record the sequence update rate
	sequenceMeter metrics.Meter
	// the timer to record consensus duration (from accepting a preprepare to final committed stage)
	consensusTimer metrics.Timer
}

func (c *core) InitKeys(vals []common.Address) error {
	// Initializing the public keys
	pkPath := "pubkey.json"
	keyPath := "edkeys/k" + strconv.Itoa(c.index) + ".json"

	// initializing number of nodes an threshold
	c.setNumNodesTh(len(vals))

	// Load the nodes from the config file.
	var nodelist []string
	if err := common.LoadJSON(pkPath, &nodelist); err != nil {
		log.Error("Can't load node file", "path", pkPath, "error", err)
		return err
	}
	for i, val := range vals {
		c.addrIDMap[val] = i
		c.idAddrMap[i] = val
		c.pubKeys[val] = types.StringToPoint(nodelist[i])
		log.Trace("Initializing pkeys", "addr", val, "idx", i, "pkey", nodelist[i])
	}

	// loads the key into the key of the user
	var strKey types.StringKey
	if err := common.LoadJSON(keyPath, &strKey); err != nil {
		log.Error("Can't load node file", "path", keyPath, "error", err)
		return err
	}
	c.edKey = types.StringToKey(strKey)
	log.Debug("Initializing local key", "addr", c.address, "pkey", strKey.Pkey)
	return nil
}

// getIndex returns the index of the user
func (c *core) getIndex(addr common.Address) int {
	if idx, ok := c.addrIDMap[addr]; ok {
		return idx
	}
	return -1
}

// setNumNodesTh sets the total and threshold
func (c *core) setNumNodesTh(total int) {
	c.numNodes = total
	c.threshold = (total-1)/3 + 1
}

func (c *core) finalizeMessage(msg *message) ([]byte, error) {
	var err error
	// Add sender address
	msg.Address = c.Address()

	// Add proof of consensus
	msg.CommittedSeal = []byte{}
	// Assign the CommittedSeal if it's a COMMIT message and proposal is not nil
	if msg.Code == msgCommit && c.current.Proposal() != nil {
		seal := PrepareCommittedSeal(c.current.Proposal().Hash())
		msg.CommittedSeal, err = c.backend.Sign(seal)
		if err != nil {
			return nil, err
		}
	}

	// Sign message
	data, err := msg.PayloadNoSig()
	if err != nil {
		return nil, err
	}
	msg.Signature, err = c.backend.Sign(data)
	if err != nil {
		return nil, err
	}

	// Convert to payload
	payload, err := msg.Payload()
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func (c *core) broadcast(msg *message) {
	logger := c.logger.New("state", c.state)

	payload, err := c.finalizeMessage(msg)
	if err != nil {
		logger.Error("Failed to finalize message", "msg", msg, "err", err)
		return
	}

	// Broadcast payload
	if err = c.backend.Broadcast(c.valSet, payload); err != nil {
		logger.Error("Failed to broadcast message", "msg", msg, "err", err)
		return
	}
}

// sendToNode sends a given message to the intended receipient
func (c *core) sendToNode(addr common.Address, msg *message) {
	logger := c.logger.New("state", c.state)

	payload, err := c.finalizeMessage(msg)
	if err != nil {
		logger.Error("Failed to finalize message", "msg", msg, "err", err)
		return
	}
	// Send payload
	if err = c.backend.SendToNode(addr, payload); err != nil {
		logger.Error("Failed to send message", "rcv", addr, "msg", msg, "err", err)
		return
	}
}

func (c *core) currentView() *istanbul.View {
	return &istanbul.View{
		Sequence: new(big.Int).Set(c.current.Sequence()),
		Round:    new(big.Int).Set(c.current.Round()),
	}
}

func (c *core) IsProposer() bool {
	v := c.valSet
	if v == nil {
		return false
	}
	return v.IsProposer(c.backend.Address())
}

func (c *core) IsCurrentProposal(blockHash common.Hash) bool {
	return c.current != nil && c.current.pendingRequest != nil && c.current.pendingRequest.Proposal.Hash() == blockHash
}

func (c *core) commit(view *istanbul.View) {
	c.setState(StateCommitted)

	proposal := c.current.Proposal()
	if proposal != nil {
		committedSeals := make([][]byte, c.current.Commits.Size())
		for i, v := range c.current.Commits.Values() {
			committedSeals[i] = make([]byte, types.IstanbulExtraSeal)
			copy(committedSeals[i][:], v.CommittedSeal[:])
		}
		if err := c.backend.Commit(proposal, committedSeals); err != nil {
			c.current.UnlockHash() //Unlock block when insertion fails
			c.sendNextRoundChange()
			return
		}
		if view.Sequence.Uint64() > c.startSeq {
			go c.sendReconstruct(view)
		}
	}
}

// startNewRound starts a new round. if round equals to 0, it means to starts a new sequence
func (c *core) startNewRound(round *big.Int) {
	var logger log.Logger
	if c.current == nil {
		logger = c.logger.New("old_round", -1, "old_seq", 0)
	} else {
		logger = c.logger.New("old_round", c.current.Round(), "old_seq", c.current.Sequence())
	}

	roundChange := false
	// Try to get last proposal
	lastProposal, lastProposer := c.backend.LastProposal()
	if c.current == nil {
		logger.Trace("Start to the initial round")
	} else if lastProposal.Number().Cmp(c.current.Sequence()) >= 0 {
		diff := new(big.Int).Sub(lastProposal.Number(), c.current.Sequence())
		c.sequenceMeter.Mark(new(big.Int).Add(diff, common.Big1).Int64())

		if !c.consensusTimestamp.IsZero() {
			c.consensusTimer.UpdateSince(c.consensusTimestamp)
			c.consensusTimestamp = time.Time{}
		}
		logger.Trace("Catch up latest proposal", "number", lastProposal.Number().Uint64(), "hash", lastProposal.Hash())
	} else if lastProposal.Number().Cmp(big.NewInt(c.current.Sequence().Int64()-1)) == 0 {
		if round.Cmp(common.Big0) == 0 {
			// same seq and round, don't need to start new round
			return
		} else if round.Cmp(c.current.Round()) < 0 {
			logger.Warn("New round should not be smaller than current round", "seq", lastProposal.Number().Int64(), "new_round", round, "old_round", c.current.Round())
			return
		}
		roundChange = true
	} else {
		logger.Warn("New sequence should be larger than current sequence", "new_seq", lastProposal.Number().Int64())
		return
	}

	var newView *istanbul.View
	if roundChange {
		newView = &istanbul.View{
			Sequence: new(big.Int).Set(c.current.Sequence()),
			Round:    new(big.Int).Set(round),
		}
	} else {
		newView = &istanbul.View{
			Sequence: new(big.Int).Add(lastProposal.Number(), common.Big1),
			Round:    new(big.Int),
		}
		c.valSet = c.backend.Validators(lastProposal)
	}

	// Update logger
	logger = logger.New("old_proposer", c.valSet.GetProposer())
	// Clear invalid ROUND CHANGE messages
	c.roundChangeSet = newRoundChangeSet(c.valSet)
	// New snapshot for new round
	c.updateRoundState(newView, c.valSet, roundChange)
	// Calculate new proposer
	c.valSet.CalcProposer(lastProposer, newView.Round.Uint64())
	c.waitingForRoundChange = false
	c.setState(StateAcceptRequest)
	// if roundChange && c.IsProposer() && c.current != nil {
	if roundChange && c.current != nil {
		// If it is locked, propose the old proposal
		// If we have pending request, propose pending request
		if c.current.IsHashLocked() {
			r := &istanbul.Request{
				Proposal: c.current.Proposal(), //c.current.Proposal would be the locked proposal by previous proposer, see updateRoundState
			}
			go c.sendPreprepare(r)
		} else if c.current.pendingRequest != nil {
			go c.sendPreprepare(c.current.pendingRequest)
		}
	}
	c.newRoundChangeTimer()

	logger.Debug("New round", "new_round", newView.Round, "new_seq", newView.Sequence, "new_proposer", c.valSet.GetProposer(), "valSet", c.valSet.List(), "size", c.valSet.Size(), "IsProposer", c.IsProposer())
}

// getPubKeys returns publicKyes in the form of a array
func (c *core) getPubKeys() crypto.Points {
	var (
		pubKeys = make(crypto.Points, c.numNodes)
		index   int
	)
	for addr, key := range c.pubKeys {
		index = c.addrIDMap[addr]
		pubKeys[index] = key
	}
	return pubKeys
}

func (c *core) catchUpRound(view *istanbul.View) {
	logger := c.logger.New("old_round", c.current.Round(), "old_seq", c.current.Sequence(), "old_proposer", c.valSet.GetProposer())

	if view.Round.Cmp(c.current.Round()) > 0 {
		c.roundMeter.Mark(new(big.Int).Sub(view.Round, c.current.Round()).Int64())
	}
	c.waitingForRoundChange = true

	// Need to keep block locked for round catching up
	c.updateRoundState(view, c.valSet, true)
	c.roundChangeSet.Clear(view.Round)
	c.newRoundChangeTimer()

	logger.Trace("Catch up round", "new_round", view.Round, "new_seq", view.Sequence, "new_proposer", c.valSet)
}

// updateRoundState updates round state by checking if locking block is necessary
func (c *core) updateRoundState(view *istanbul.View, validatorSet istanbul.ValidatorSet, roundChange bool) {
	// Lock only if both roundChange is true and it is locked
	if roundChange && c.current != nil {
		if c.current.IsHashLocked() {
			c.current = newRoundState(view, validatorSet, c.current.GetLockedHash(), c.current.Preprepare, c.current.pendingRequest, c.backend.HasBadProposal)
		} else {
			c.current = newRoundState(view, validatorSet, common.Hash{}, nil, c.current.pendingRequest, c.backend.HasBadProposal)
		}
	} else {
		c.current = newRoundState(view, validatorSet, common.Hash{}, nil, nil, c.backend.HasBadProposal)
	}
}

func (c *core) setState(state State) {
	if c.state != state {
		c.state = state
	}
	if state == StateAcceptRequest {
		c.processPendingRequests()
	}
	c.processBacklog()
}

func (c *core) Address() common.Address {
	return c.address
}

func (c *core) stopFuturePreprepareTimer() {
	if c.futurePreprepareTimer != nil {
		c.futurePreprepareTimer.Stop()
	}
}

func (c *core) stopTimer() {
	c.stopFuturePreprepareTimer()
	if c.roundChangeTimer != nil {
		c.roundChangeTimer.Stop()
	}
}

func (c *core) newRoundChangeTimer() {
	c.stopTimer()

	// set timeout based on the round number
	timeout := time.Duration(c.config.RequestTimeout) * time.Millisecond
	round := c.current.Round().Uint64()
	if round > 0 {
		timeout += time.Duration(math.Pow(2, float64(round))) * time.Second
	}
	c.roundChangeTimer = time.AfterFunc(timeout, func() {
		c.sendEvent(timeoutEvent{})
	})
}

func (c *core) checkValidatorSignature(data []byte, sig []byte) (common.Address, error) {
	return istanbul.CheckValidatorSignature(c.valSet, data, sig)
}

func (c *core) QuorumSize() int {
	if c.config.Ceil2Nby3Block == nil || (c.current != nil && c.current.sequence.Cmp(c.config.Ceil2Nby3Block) < 0) {
		c.logger.Trace("Confirmation Formula used 2F+ 1")
		return (2 * c.valSet.F()) + 1
	}
	c.logger.Trace("Confirmation Formula used ceil(2N/3)")
	return int(math.Ceil(float64(2*c.valSet.Size()) / 3))
}

// PrepareCommittedSeal returns a committed seal for the given hash
func PrepareCommittedSeal(hash common.Hash) []byte {
	var buf bytes.Buffer
	buf.Write(hash.Bytes())
	buf.Write([]byte{byte(msgCommit)})
	return buf.Bytes()
}
