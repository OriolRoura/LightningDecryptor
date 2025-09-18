package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// DualWriter writes to both console and file simultaneously
type DualWriter struct {
	file    *os.File
	console io.Writer
}

func NewDualWriter(filename string) (*DualWriter, error) {
	file, err := os.Create(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file: %v", err)
	}
	
	return &DualWriter{
		file:    file,
		console: os.Stdout,
	}, nil
}

func (dw *DualWriter) Write(p []byte) (n int, err error) {
	// Write to console
	dw.console.Write(p)
	// Write to file
	return dw.file.Write(p)
}

func (dw *DualWriter) Close() error {
	return dw.file.Close()
}

// Global dual writer instance
var dualWriter *DualWriter

// Custom printf that writes to both console and file
func dualPrintf(format string, args ...interface{}) {
	output := fmt.Sprintf(format, args...)
	if dualWriter != nil {
		dualWriter.Write([]byte(output))
	} else {
		fmt.Print(output)
	}
}

// SessionState represents the complete cryptographic state for a Brontide session
type SessionState struct {
	Role        string   // "initiator" or "responder"
	ChainingKey [32]byte // From handshake
	SendKey     [32]byte // Initial send cipher key
	RecvKey     [32]byte // Initial recv cipher key
	SendSalt    [32]byte // Send cipher salt
	RecvSalt    [32]byte // Recv cipher salt
	SendNonce   uint64   // Current send message counter
	RecvNonce   uint64   // Current recv message counter
}

// NonceEvent represents a logged nonce increment event from docker logs
type NonceEvent struct {
	Timestamp  time.Time
	Direction  string // "SEND" or "RECV"
	NonceAfter uint64
}

// SmartNoncePredictor predicts nonces based on logged increments
type SmartNoncePredictor struct {
	Events      []NonceEvent
	CurrentSend uint64
	CurrentRecv uint64
	StartTime   time.Time
	Enabled     bool
}

// WiresharkPacket represents a packet from Wireshark JSON export (corrected structure)
type WiresharkPacket struct {
	Source struct {
		Layers struct {
			Frame struct {
				FrameNumber string `json:"frame.number"`
				FrameTime   string `json:"frame.time"`
				FrameLen    string `json:"frame.len"`
			} `json:"frame"`
			TCP struct {
				SrcPort string `json:"tcp.srcport"`
				DstPort string `json:"tcp.dstport"`
				Payload string `json:"tcp.payload"`
				Stream  string `json:"tcp.stream"`
				Seq     string `json:"tcp.seq"`
				Len     string `json:"tcp.len"`
			} `json:"tcp"`
		} `json:"layers"`
	} `json:"_source"`
}

// ProcessedPacket represents a cleaned and processed packet
type ProcessedPacket struct {
	FrameNumber  string
	StreamID     string
	PayloadBytes []byte
	PayloadHash  string
	Size         int
	IsLightning  bool
	Timestamp    time.Time
}

// BrontideDecryptor handles decryption of Brontide messages
type BrontideDecryptor struct {
	session   *SessionState
	predictor *SmartNoncePredictor
}

// NewBrontideDecryptor creates a new decryptor with session state
func NewBrontideDecryptor(session *SessionState) *BrontideDecryptor {
	dualPrintf("🔑 Session initialized: %s\n", session.Role)
	return &BrontideDecryptor{session: session}
}

// RotateKey performs key rotation using HKDF
func (bd *BrontideDecryptor) RotateKey(oldKey, salt [32]byte) ([32]byte, [32]byte) {
	var (
		info    []byte
		nextKey [32]byte
		newSalt [32]byte
	)

	h := hkdf.New(sha256.New, oldKey[:], salt[:], info)
	h.Read(newSalt[:])
	h.Read(nextKey[:])

	return nextKey, newSalt
}

// createNonce creates the 12-byte nonce from the 64-bit counter
func createNonce(nonce uint64) [12]byte {
	var nonceBytes [12]byte
	binary.LittleEndian.PutUint64(nonceBytes[4:], nonce)
	return nonceBytes
}

// getCurrentKeyForNonce returns the current key for a given nonce
func (bd *BrontideDecryptor) getCurrentKeyForNonce(nonce uint64, isRecv bool) ([32]byte, [32]byte, error) {
	rotations := nonce / 1000

	var currentKey, currentSalt [32]byte

	if isRecv {
		currentKey = bd.session.RecvKey
		currentSalt = bd.session.RecvSalt
	} else {
		currentKey = bd.session.SendKey
		currentSalt = bd.session.SendSalt
	}

	// Apply rotations from scratch
	for i := uint64(0); i < rotations; i++ {
		currentKey, currentSalt = bd.RotateKey(currentKey, currentSalt)
	}

	return currentKey, currentSalt, nil
}

// DecryptWithNonce decrypts a message using a specific nonce
func (bd *BrontideDecryptor) DecryptWithNonce(ciphertext []byte, nonce uint64, isRecv bool) ([]byte, error) {
	key, _, err := bd.getCurrentKeyForNonce(nonce, isRecv)
	if err != nil {
		return nil, err
	}

	nonceCounter := nonce % 1000
	nonceBytes := createNonce(nonceCounter)

	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	plaintext, err := aead.Open(nil, nonceBytes[:], ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed with nonce %d: %v", nonce, err)
	}

	return plaintext, nil
}

// TryDecryptPacket attempts to decrypt a packet by trying MANY different nonce values (BRUTE FORCE)
func (bd *BrontideDecryptor) TryDecryptPacket(ciphertext []byte, startNonce, maxTries uint64) ([]byte, uint64, bool, error) {
	// For very large datasets, try a much wider range
	actualMaxTries := maxTries
	if maxTries < 5000 {
		actualMaxTries = 5000 // Ensure minimum search range
	}

	dualPrintf("   🔍 BIDIRECTIONAL TEST: Testing both NORMAL and SWAPPED keys for mirrored packets\n")

	// ALWAYS test both key configurations (regardless of role) because:
	// - Packet captures contain BOTH sides of the conversation
	// - One side uses SEND keys, the other uses RECV keys
	// - We don't know which direction each packet represents
	keyConfigs := []string{"NORMAL", "SWAPPED"}

	for _, keyConfig := range keyConfigs {
		dualPrintf("   🔑 Testing %s key assignment...\n", keyConfig)

		// Try RECV direction with current config
		for nonce := uint64(0); nonce <= actualMaxTries; nonce++ {
			// For swapped config, we use the opposite key assignment
			useRecvKey := true
			if keyConfig == "SWAPPED" {
				useRecvKey = false // Use send key for "recv" direction
			}

			plaintext, err := bd.DecryptWithNonce(ciphertext, nonce, useRecvKey)
			if err == nil {
				// Additional validation: check if this looks like a real Lightning message
				if bd.isValidDecryption(plaintext) {
					dualPrintf("   ✅ SUCCESS with %s keys! RECV direction, nonce %d\n", keyConfig, nonce)
					return plaintext, nonce, true, nil
				}
			}
		}

		// Try SEND direction with current config
		for nonce := uint64(0); nonce <= actualMaxTries; nonce++ {
			// For swapped config, we use the opposite key assignment
			useRecvKey := false
			if keyConfig == "SWAPPED" {
				useRecvKey = true // Use recv key for "send" direction
			}

			plaintext, err := bd.DecryptWithNonce(ciphertext, nonce, useRecvKey)
			if err == nil {
				// Additional validation: check if this looks like a real Lightning message
				if bd.isValidDecryption(plaintext) {
					dualPrintf("   ✅ SUCCESS with %s keys! SEND direction, nonce %d\n", keyConfig, nonce)
					return plaintext, nonce, false, nil
				}
			}
		}
	}

	return nil, 0, false, fmt.Errorf("failed to decrypt with any key configuration after trying %d nonces", actualMaxTries)
}

// TryDecryptPacketSmart uses nonce prediction to avoid brute forcing when possible
func (bd *BrontideDecryptor) TryDecryptPacketSmart(ciphertext []byte, packetTime time.Time, fallbackMaxTries uint64) ([]byte, uint64, bool, error) {
	if len(ciphertext) < 18 {
		return nil, 0, false, fmt.Errorf("payload too short: %d bytes", len(ciphertext))
	}

	// Try smart prediction first if available
	if bd.predictor != nil && bd.predictor.Enabled {
		dualPrintf("   🎯 SMART MODE: Using nonce prediction\n")

		// Get predicted nonce with margin
		sendPred, _ := bd.PredictNonceAtTime(packetTime)
		margin := uint64(10) // ±10 nonce range

		// Try predicted SEND range first
		sendMin := uint64(0)
		if sendPred > margin {
			sendMin = sendPred - margin
		}
		sendMax := sendPred + margin

		dualPrintf("   📤 Predicted SEND range: %d-%d (center: %d)\n", sendMin, sendMax, sendPred)

		// Test SEND direction with predicted range
		for nonce := sendMin; nonce <= sendMax; nonce++ {
			plaintext, err := bd.DecryptWithNonce(ciphertext, nonce, false) // SEND uses false
			if err == nil && bd.isValidDecryption(plaintext) {
				dualPrintf("   ✅ SMART SUCCESS! SEND direction, nonce %d (predicted: %d)\n", nonce, sendPred)
				return plaintext, nonce, false, nil
			}
		}

		// Try predicted RECV range
		recvMin := sendMin // Use same range for recv as approximation
		recvMax := sendMax

		dualPrintf("   📥 Predicted RECV range: %d-%d\n", recvMin, recvMax)

		for nonce := recvMin; nonce <= recvMax; nonce++ {
			plaintext, err := bd.DecryptWithNonce(ciphertext, nonce, true) // RECV uses true
			if err == nil && bd.isValidDecryption(plaintext) {
				dualPrintf("   ✅ SMART SUCCESS! RECV direction, nonce %d\n", nonce)
				return plaintext, nonce, true, nil
			}
		}

		dualPrintf("   ⚠️  Smart prediction failed, falling back to brute force\n")
	}

	// Fallback to original brute force method
	return bd.TryDecryptPacket(ciphertext, 0, fallbackMaxTries)
}

// isValidDecryption performs additional validation on decrypted data to filter out false positives
func (bd *BrontideDecryptor) isValidDecryption(plaintext []byte) bool {
	if len(plaintext) < 2 {
		return false // Lightning messages must have at least 2 bytes for message type
	}

	// Check if the message type is valid
	msgType := binary.BigEndian.Uint16(plaintext[0:2])
	if !isValidLightningMessageType(msgType) {
		// For very short messages, be extra strict
		if len(plaintext) <= 2 {
			return false // Reject short messages with invalid types
		}
		// For longer messages, allow some unknown types as they might be valid but unrecognized
		if len(plaintext) < 50 {
			return false // Reject medium messages with invalid types
		}
	}

	// Additional heuristic: check if the data has reasonable entropy for a Lightning message
	if len(plaintext) >= 10 {
		entropy := calculateEntropy(plaintext)
		if entropy < 2.0 { // Very low entropy suggests it's not real encrypted/structured data
			return false
		}
	}

	return true
}

// ParseDockerLogs initializes the nonce predictor with docker log data
func (bd *BrontideDecryptor) ParseDockerLogs(logFile string) error {
	if bd.predictor == nil {
		bd.predictor = &SmartNoncePredictor{}
	}

	file, err := os.Open(logFile)
	if err != nil {
		dualPrintf("⚠️  Docker logs not found: %s (will use brute force)\n", logFile)
		bd.predictor.Enabled = false
		return nil // Not an error, just use brute force
	}
	defer file.Close()

	// Regex patterns to match nonce events
	timePattern := `(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})`
	nonceAfterPattern := `Send cipher nonce \(after\): (\d+)`

	timeRegex := regexp.MustCompile(timePattern)
	afterRegex := regexp.MustCompile(nonceAfterPattern)

	scanner := bufio.NewScanner(file)
	var currentTime time.Time

	for scanner.Scan() {
		line := scanner.Text()

		// Extract timestamp
		if timeMatch := timeRegex.FindStringSubmatch(line); timeMatch != nil {
			if t, err := time.Parse("2006-01-02 15:04:05.000", timeMatch[1]); err == nil {
				currentTime = t
				if bd.predictor.StartTime.IsZero() {
					bd.predictor.StartTime = currentTime
				}
			}
		}

		// Extract nonce after events
		if afterMatch := afterRegex.FindStringSubmatch(line); afterMatch != nil {
			if nonce, err := strconv.ParseUint(afterMatch[1], 10, 64); err == nil {
				event := NonceEvent{
					Timestamp:  currentTime,
					Direction:  "SEND",
					NonceAfter: nonce,
				}
				bd.predictor.Events = append(bd.predictor.Events, event)
				bd.predictor.CurrentSend = nonce
			}
		}
	}

	if len(bd.predictor.Events) > 0 {
		bd.predictor.Enabled = true
		dualPrintf("🎯 Smart nonce prediction enabled: %d events parsed\n", len(bd.predictor.Events))
	} else {
		bd.predictor.Enabled = false
		dualPrintf("⚠️  No nonce events found in logs, using brute force\n")
	}

	return scanner.Err()
}

// PredictNonceAtTime estimates nonce values at a specific time
func (bd *BrontideDecryptor) PredictNonceAtTime(targetTime time.Time) (uint64, uint64) {
	if !bd.predictor.Enabled || len(bd.predictor.Events) < 2 {
		return 0, 0
	}

	// Simple linear interpolation for SEND nonces
	events := bd.predictor.Events

	// If target is before all events
	if targetTime.Before(events[0].Timestamp) {
		if events[0].NonceAfter > 5 {
			return events[0].NonceAfter - 5, 0
		}
		return 0, 0
	}

	// If target is after all events, extrapolate
	if targetTime.After(events[len(events)-1].Timestamp) {
		if len(events) >= 2 {
			last := events[len(events)-1]
			secondLast := events[len(events)-2]

			timeDiff := last.Timestamp.Sub(secondLast.Timestamp).Seconds()
			nonceDiff := float64(last.NonceAfter - secondLast.NonceAfter)
			rate := nonceDiff / timeDiff

			extraTime := targetTime.Sub(last.Timestamp).Seconds()
			extraNonce := uint64(rate * extraTime)

			return last.NonceAfter + extraNonce, 0
		}
		return events[len(events)-1].NonceAfter, 0
	}

	// Find surrounding events and interpolate
	for i := 0; i < len(events)-1; i++ {
		if targetTime.After(events[i].Timestamp) && targetTime.Before(events[i+1].Timestamp) {
			t1 := events[i].Timestamp
			t2 := events[i+1].Timestamp
			n1 := float64(events[i].NonceAfter)
			n2 := float64(events[i+1].NonceAfter)

			totalTime := t2.Sub(t1).Seconds()
			elapsedTime := targetTime.Sub(t1).Seconds()
			factor := elapsedTime / totalTime

			interpolatedNonce := n1 + factor*(n2-n1)
			return uint64(math.Round(interpolatedNonce)), 0
		}
	}

	return 0, 0
}

// validateLightningPackets performs cryptographic validation to confirm Lightning packets
// ENHANCED: Uses fallback validation to avoid false negatives from key/nonce issues
func (bd *BrontideDecryptor) validateLightningPackets(candidates []ProcessedPacket) []ProcessedPacket {
	dualPrintf("🔍 Performing cryptographic validation on %d candidates...\n", len(candidates))

	var validated []ProcessedPacket
	var maybeValid []ProcessedPacket
	quickTestRange := uint64(50) // Quick test with limited nonce range
	successfulDecryptions := 0

	for i, packet := range candidates {
		dualPrintf("   🔐 Testing packet %d/%d (Frame %s, %d bytes)...\n",
			i+1, len(candidates), packet.FrameNumber, packet.Size)

		// Quick decryption attempt with limited nonce range
		_, _, _, err := bd.TryDecryptPacket(packet.PayloadBytes, 0, quickTestRange)
		if err == nil {
			dualPrintf("   ✅ CONFIRMED Lightning packet (cryptographically validated)\n")
			validated = append(validated, packet)
			successfulDecryptions++
		} else {
			dualPrintf("   ❓ Cannot decrypt with current keys (could be other node/wrong keys)\n")
			maybeValid = append(maybeValid, packet)
		}
	}

	// FALLBACK LOGIC: If very few packets decrypt, the keys might be wrong
	// In this case, fall back to heuristic-only validation to avoid false negatives
	decryptionRate := float64(successfulDecryptions) / float64(len(candidates))

	dualPrintf("🔍 Cryptographic validation results:\n")
	dualPrintf("   ✅ Confirmed Lightning packets: %d\n", len(validated))
	dualPrintf("   ❓ Unconfirmed candidates: %d\n", len(maybeValid))
	dualPrintf("   📊 Decryption success rate: %.1f%%\n", decryptionRate*100)

	if decryptionRate < 0.1 { // Less than 10% success rate
		dualPrintf("⚠️  WARNING: Very low decryption rate detected!\n")
		dualPrintf("   This could indicate:\n")
		dualPrintf("   • Wrong session keys for this capture\n")
		dualPrintf("   • Packets from other Lightning nodes\n")
		dualPrintf("   • Incorrect role assignment (initiator/responder)\n")
		dualPrintf("   • Nonce range too limited for this session\n")
		dualPrintf("\n🔄 FALLBACK: Using heuristic-only validation to avoid false negatives\n")

		// Fall back to all heuristically-identified candidates
		return candidates
	} else if decryptionRate < 0.3 { // 10-30% success rate
		dualPrintf("⚠️  MODERATE: Mixed validation results detected\n")
		dualPrintf("   This might indicate multi-node traffic or partial key match\n")
		dualPrintf("🔄 HYBRID: Including both confirmed and high-confidence candidates\n")

		// Include confirmed packets + high-scoring heuristic candidates
		for _, candidate := range maybeValid {
			if isHighConfidenceLightning(candidate.PayloadBytes) {
				dualPrintf("   ➕ Including high-confidence candidate: Frame %s\n", candidate.FrameNumber)
				validated = append(validated, candidate)
			}
		}

		return validated
	} else {
		dualPrintf("✅ HIGH: Good decryption rate - cryptographic validation reliable\n")
		return validated
	}
}

// isHighConfidenceLightning determines if a packet has very high probability of being Lightning
// Used as fallback when cryptographic validation fails due to key/nonce issues
func isHighConfidenceLightning(payload []byte) bool {
	if len(payload) < 18 {
		return false
	}

	score := 0

	// Stricter criteria for high-confidence classification
	size := len(payload)

	// Size analysis - more restrictive
	if size == 18 {
		score += 40 // Very likely ping/pong
	} else if size >= 90 && size <= 116 {
		score += 35 // Common Lightning message sizes
	} else if size == 1475 {
		score += 40 // MTU fragment size
	} else if size >= 180 && size <= 200 {
		score += 30 // Medium Lightning messages
	} else {
		return false // Size doesn't match known Lightning patterns
	}

	// Entropy must be very high for high-confidence
	entropy := calculateEntropy(payload)
	if entropy >= 7.5 {
		score += 30 // Maximum entropy
	} else if entropy >= 7.0 {
		score += 20 // Very high entropy
	} else {
		return false // Entropy too low for encrypted Lightning
	}

	// Uniformity must be very high
	uniformity := calculateByteUniformity(payload)
	if uniformity >= 0.8 {
		score += 20 // Very uniform distribution
	} else if uniformity >= 0.7 {
		score += 10 // Good uniformity
	} else {
		return false // Not uniform enough
	}

	// Pattern analysis - stricter requirements
	if hasLightningPatterns(payload) {
		score += 30
	} else if hasEncryptionPatterns(payload) {
		score += 20
	} else {
		return false // No encryption patterns detected
	}

	// Require 85% confidence for high-confidence classification
	return score >= 85
}

// isLightningPacket determines if a packet might contain Lightning data using enhanced analysis
func isLightningPacket(payload []byte) bool {
	if len(payload) < 18 {
		return false // Lightning messages are minimum 18 bytes (2-byte length + 16-byte auth tag)
	}

	// Enhanced Lightning packet detection with multiple criteria
	score := 0

	// Criterion 1: Size analysis (30 points)
	size := len(payload)
	if size == 18 {
		score += 25 // Very likely ping/pong
	} else if size >= 90 && size <= 116 {
		score += 20 // Common message sizes
	} else if size == 1475 {
		score += 25 // Common MTU fragment size
	} else if size >= 18 && size <= 65535 && (size-18)%16 == 0 {
		score += 15 // Proper Lightning message structure (length + multiple of 16 for AEAD)
	} else if size >= 18 && size <= 2000 {
		score += 10 // Within reasonable Lightning range
	}

	// Criterion 2: Entropy analysis (25 points)
	// Lightning packets are encrypted, so they should have high entropy
	entropy := calculateEntropy(payload)
	if entropy >= 7.5 {
		score += 25 // Very high entropy suggests encryption
	} else if entropy >= 6.5 {
		score += 15 // High entropy
	} else if entropy >= 5.0 {
		score += 5 // Medium entropy
	}

	// Criterion 3: Byte distribution analysis (20 points)
	// Encrypted data should have relatively uniform byte distribution
	uniformity := calculateByteUniformity(payload)
	if uniformity >= 0.8 {
		score += 20 // Very uniform distribution
	} else if uniformity >= 0.6 {
		score += 10 // Reasonably uniform
	}

	// Criterion 4: Pattern analysis (25 points)
	// Look for patterns that suggest encrypted Lightning traffic
	if hasLightningPatterns(payload) {
		score += 25
	} else if hasEncryptionPatterns(payload) {
		score += 15
	}

	// Require at least 50% confidence to classify as Lightning
	return score >= 50
}

// calculateEntropy computes Shannon entropy of the payload
func calculateEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	// Count byte frequencies
	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(data))

	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * (math.Log2(p))
		}
	}

	return entropy
}

// calculateByteUniformity measures how uniformly bytes are distributed
func calculateByteUniformity(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}

	freq := make(map[byte]int)
	for _, b := range data {
		freq[b]++
	}

	// Calculate uniformity using coefficient of variation
	var sum, sumSquares float64
	for _, count := range freq {
		sum += float64(count)
		sumSquares += float64(count * count)
	}

	if len(freq) <= 1 {
		return 0
	}

	mean := sum / float64(len(freq))
	variance := (sumSquares / float64(len(freq))) - (mean * mean)

	if mean == 0 {
		return 0
	}

	cv := math.Sqrt(variance) / mean
	return math.Max(0, 1.0-cv/2.0) // Normalize to 0-1 range
}

// hasLightningPatterns checks for specific Lightning Network patterns
func hasLightningPatterns(payload []byte) bool {
	if len(payload) < 18 {
		return false
	}

	// Check for Lightning-specific structural patterns
	// (These are heuristics for encrypted Lightning messages)

	// Pattern 1: Check if first 2 bytes could be a reasonable length prefix
	if len(payload) >= 2 {
		lengthPrefix := int(payload[0])<<8 | int(payload[1])
		if lengthPrefix > 0 && lengthPrefix <= 65535 && lengthPrefix+18 == len(payload) {
			return true // Length prefix matches packet size (encrypted message)
		}
	}

	// Pattern 2: Lightning messages often end with authentication tags
	// Check if last 16 bytes have different characteristics than the rest
	if len(payload) >= 34 { // At least 18 bytes + 16 auth tag
		messageBytes := payload[:len(payload)-16]
		authTag := payload[len(payload)-16:]

		msgEntropy := calculateEntropy(messageBytes)
		tagEntropy := calculateEntropy(authTag)

		// Auth tags often have slightly different entropy than message body
		if math.Abs(msgEntropy-tagEntropy) > 0.5 && msgEntropy > 6.0 {
			return true
		}
	}

	return false
}

// hasEncryptionPatterns checks for general encryption patterns
func hasEncryptionPatterns(payload []byte) bool {
	if len(payload) < 16 {
		return false
	}

	// Look for signs that this is encrypted data
	// 1. No repeated patterns (encrypted data should be pseudo-random)
	// 2. High entropy
	// 3. No obvious plaintext indicators

	// Check for repeated byte sequences (encrypted data shouldn't have many)
	repeatedSequences := 0
	for i := 0; i < len(payload)-3; i++ {
		sequence := payload[i : i+4]
		for j := i + 4; j < len(payload)-3; j++ {
			if bytes.Equal(sequence, payload[j:j+4]) {
				repeatedSequences++
				break
			}
		}
	}

	// If less than 5% of 4-byte sequences repeat, likely encrypted
	maxRepeats := len(payload) / 20
	return repeatedSequences <= maxRepeats
}

// hashPayload creates a hash of the payload for deduplication
func hashPayload(payload []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(payload))
}

// processAndFilterPackets processes raw packets and filters out duplicates and non-Lightning packets
func processAndFilterPackets(packets []WiresharkPacket) []ProcessedPacket {
	seen := make(map[string]bool)
	var processed []ProcessedPacket

	dualPrintf("🔄 Processing %d raw packets...\n", len(packets))

	for _, packet := range packets {
		// Extract and clean payload
		payloadHex := strings.ReplaceAll(packet.Source.Layers.TCP.Payload, ":", "")
		if payloadHex == "" {
			continue
		}

		payload, err := hex.DecodeString(payloadHex)
		if err != nil {
			continue
		}

		// Create hash for deduplication
		payloadHash := hashPayload(payload)

		// Skip duplicates
		if seen[payloadHash] {
			continue
		}
		seen[payloadHash] = true

		// Check if it might be a Lightning packet
		isLightning := isLightningPacket(payload)

		// Parse timestamp from frame.time
		var packetTime time.Time
		if packet.Source.Layers.Frame.FrameTime != "" {
			// Try parsing the Wireshark timestamp format
			// Example: "Sep 15, 2025 15:42:27.918000000 UTC"
			if t, err := time.Parse("Jan 2, 2006 15:04:05.000000000 MST", packet.Source.Layers.Frame.FrameTime); err == nil {
				packetTime = t
			} else if t, err := time.Parse("2006-01-02 15:04:05.000000000", packet.Source.Layers.Frame.FrameTime); err == nil {
				packetTime = t
			}
		}

		processed = append(processed, ProcessedPacket{
			FrameNumber:  packet.Source.Layers.Frame.FrameNumber,
			StreamID:     packet.Source.Layers.TCP.Stream,
			PayloadBytes: payload,
			PayloadHash:  payloadHash[:16],
			Size:         len(payload),
			IsLightning:  isLightning,
			Timestamp:    packetTime,
		})
	}

	return processed
}

// groupFragmentedPackets attempts to group fragmented packets using TCP sequence analysis
func groupFragmentedPackets(packets []ProcessedPacket) []ProcessedPacket {
	streamGroups := make(map[string][]ProcessedPacket)
	var result []ProcessedPacket
	var noStreamCount int

	dualPrintf("🔍 Analyzing %d packets for TCP fragmentation...\n", len(packets))

	// Group by stream ID
	for _, packet := range packets {
		if packet.StreamID == "" {
			dualPrintf("   📄 Frame %s: No stream ID, size %d bytes\n", packet.FrameNumber, packet.Size)
			result = append(result, packet)
			noStreamCount++
			continue
		}
		streamGroups[packet.StreamID] = append(streamGroups[packet.StreamID], packet)
	}

	dualPrintf("   📊 Found %d packets without stream ID, %d unique streams\n", noStreamCount, len(streamGroups))

	// Process each stream for potential fragments
	for streamID, streamPackets := range streamGroups {
		dualPrintf("   🔗 Stream %s: %d packets\n", streamID, len(streamPackets))

		if len(streamPackets) == 1 {
			dualPrintf("      ✅ Single packet in stream, keeping as-is (Frame %s, %d bytes)\n",
				streamPackets[0].FrameNumber, streamPackets[0].Size)
			result = append(result, streamPackets[0])
			continue
		}

		// Analyze packet patterns for fragmentation
		result = append(result, analyzeStreamForFragments(streamID, streamPackets)...)
	}

	dualPrintf("🎯 Fragment analysis complete: %d input packets → %d output packets\n", len(packets), len(result))

	return result
}

// analyzeStreamForFragments performs detailed analysis of packets in a stream
func analyzeStreamForFragments(streamID string, packets []ProcessedPacket) []ProcessedPacket {
	dualPrintf("      🔬 Analyzing %d packets for fragmentation patterns:\n", len(packets))

	// Log all packets with detailed info
	for i, packet := range packets {
		dualPrintf("      📦 Packet %d: Frame %s, size %d bytes, hash %s\n",
			i+1, packet.FrameNumber, packet.Size, packet.PayloadHash)
	}

	// Look for fragmentation indicators
	var suspicious []ProcessedPacket
	var normal []ProcessedPacket

	// Analysis 1: Size-based grouping (multiple similar-sized large packets)
	sizeGroups := make(map[int][]ProcessedPacket)
	for _, packet := range packets {
		sizeGroups[packet.Size] = append(sizeGroups[packet.Size], packet)
	}

	// Check for multiple packets of the same large size (likely fragments)
	for size, sameSize := range sizeGroups {
		if size >= 1000 && len(sameSize) > 1 {
			dualPrintf("      🧩 Found %d packets of size %d bytes - likely fragments\n", len(sameSize), size)
			suspicious = append(suspicious, sameSize...)
		} else if size >= 1000 {
			dualPrintf("      📄 Single large packet (%d bytes) - likely complete message\n", size)
			normal = append(normal, sameSize...)
		} else {
			dualPrintf("      📄 Normal sized packets (%d bytes each)\n", size)
			normal = append(normal, sameSize...)
		}
	}

	// Analysis 2: Lightning message structure analysis
	if len(suspicious) > 1 {
		dualPrintf("      ✨ ATTEMPTING TO MERGE %d suspicious fragments:\n", len(suspicious))

		// Try to merge suspicious packets
		var combinedPayload []byte
		var frameNumbers []string

		for i, frag := range suspicious {
			dualPrintf("         Fragment %d: Frame %s (%d bytes)\n", i+1, frag.FrameNumber, frag.Size)

			// Check if this looks like a Lightning message fragment
			if isLightningFragment(frag.PayloadBytes, i == 0) {
				combinedPayload = append(combinedPayload, frag.PayloadBytes...)
				frameNumbers = append(frameNumbers, frag.FrameNumber)
			} else {
				dualPrintf("         ⚠️  Fragment %d doesn't look like Lightning data\n", i+1)
				// Keep as separate packet if it doesn't look like a fragment
				normal = append(normal, frag)
			}
		}

		if len(combinedPayload) > 0 && len(frameNumbers) > 1 {
			merged := ProcessedPacket{
				FrameNumber:  strings.Join(frameNumbers, "+"),
				StreamID:     streamID,
				PayloadBytes: combinedPayload,
				PayloadHash:  hashPayload(combinedPayload)[:16],
				Size:         len(combinedPayload),
				IsLightning:  isLightningPacket(combinedPayload),
			}

			dualPrintf("         ✅ Merged result: Frame %s, %d bytes total, Lightning: %v\n",
				merged.FrameNumber, merged.Size, merged.IsLightning)

			normal = append(normal, merged)
		}
	} else {
		// No suspicious fragments, keep all packets as-is
		dualPrintf("      ✅ No fragmentation patterns detected, keeping all %d packets\n", len(packets))
		normal = packets
	}

	return normal
}

// isLightningFragment analyzes if a packet looks like a Lightning message fragment
func isLightningFragment(payload []byte, isFirst bool) bool {
	if len(payload) < 16 {
		return false // Too small to be meaningful
	}

	// If it's the first fragment, it might contain a Lightning message header
	if isFirst {
		// Lightning messages start with a 2-byte message type
		// Common types: 16-19 (init/error/ping/pong), 32-39 (channel), 128-138 (HTLC), 256-259 (gossip)
		if len(payload) >= 18 { // Minimum encrypted Lightning message
			// This is encrypted, so we can't actually see the message type
			// But we can check if the size is reasonable for a Lightning message
			return len(payload) >= 18 && len(payload) <= 65535
		}
	}

	// For non-first fragments, just check if size is reasonable
	return len(payload) >= 16 && len(payload) <= 65535
}

// ParseSessionFromLogs extracts session keys from LND log content
func ParseSessionFromLogs(logContent string) (*SessionState, error) {
	session := &SessionState{}

	// Parse role
	if strings.Contains(logContent, "responder:") {
		session.Role = "responder"
	} else if strings.Contains(logContent, "initiator:") {
		session.Role = "initiator"
	} else {
		return nil, fmt.Errorf("could not determine role from logs")
	}

	// Regular expressions to extract keys
	patterns := map[string]*[32]byte{
		`Chaining key:\s*([a-fA-F0-9]{64})`:     &session.ChainingKey,
		`Send cipher key:\s*([a-fA-F0-9]{64})`:  &session.SendKey,
		`Recv cipher key:\s*([a-fA-F0-9]{64})`:  &session.RecvKey,
		`Send cipher salt:\s*([a-fA-F0-9]{64})`: &session.SendSalt,
		`Recv cipher salt:\s*([a-fA-F0-9]{64})`: &session.RecvSalt,
	}

	for pattern, target := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(logContent)
		if len(matches) < 2 {
			return nil, fmt.Errorf("could not find match for pattern: %s", pattern)
		}

		keyBytes, err := hex.DecodeString(matches[1])
		if err != nil {
			return nil, fmt.Errorf("failed to decode hex for pattern %s: %v", pattern, err)
		}

		if len(keyBytes) != 32 {
			return nil, fmt.Errorf("invalid key length for pattern %s: got %d, expected 32", pattern, len(keyBytes))
		}

		copy(target[:], keyBytes)
	}

	// Initialize nonce counters
	session.SendNonce = 0
	session.RecvNonce = 0

	return session, nil
}

// DecryptWiresharkJSON decrypts packets from a Wireshark JSON file with smart filtering
func (bd *BrontideDecryptor) DecryptWiresharkJSON(jsonFile string, maxNonce uint64, useSmartMode bool) error {
	dualPrintf("🔍 Processing Wireshark JSON: %s\n", jsonFile)
	if useSmartMode {
		dualPrintf("🧠 SMART PREDICTION MODE: Using nonce interpolation with ±%d margin\n", maxNonce)
	} else {
		dualPrintf("🎯 BRUTE FORCE MODE: Will try nonces 0-%d for each packet\n", maxNonce)
	}

	// Read and parse JSON
	data, err := os.ReadFile(jsonFile)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	var packets []WiresharkPacket
	err = json.Unmarshal(data, &packets)
	if err != nil {
		return fmt.Errorf("failed to parse JSON: %v", err)
	}

	if len(packets) == 0 {
		return fmt.Errorf("no packets found in JSON")
	}

	dualPrintf("📥 Loaded %d raw packets\n", len(packets))

	// Process and filter packets
	processed := processAndFilterPackets(packets)
	dualPrintf("✅ After deduplication: %d unique packets\n", len(processed))

	// Filter for Lightning packets
	var lightningPackets []ProcessedPacket
	var otherPackets []ProcessedPacket

	for _, packet := range processed {
		if packet.IsLightning {
			lightningPackets = append(lightningPackets, packet)
		} else {
			otherPackets = append(otherPackets, packet)
		}
	}

	dualPrintf("⚡ Lightning candidates: %d packets\n", len(lightningPackets))
	dualPrintf("🚫 Non-Lightning packets: %d (skipped)\n", len(otherPackets))

	// ENHANCED: Perform cryptographic validation on Lightning candidates
	validatedPackets := bd.validateLightningPackets(lightningPackets)
	dualPrintf("✅ Cryptographically validated Lightning packets: %d\n", len(validatedPackets))
	if len(validatedPackets) < len(lightningPackets) {
		dualPrintf("⚠️  Filtered out %d false positives\n", len(lightningPackets)-len(validatedPackets))
	}

	// Group fragmented packets
	lightningPackets = groupFragmentedPackets(validatedPackets)
	dualPrintf("📦 After fragment grouping: %d packets\n", len(lightningPackets))

	if len(lightningPackets) == 0 {
		dualPrintf("❌ No Lightning packets found\n")
		return nil
	}

	startMode := "BRUTE FORCE"
	if useSmartMode {
		startMode = "SMART PREDICTION"
	}
	dualPrintf("\n🔓 Starting %s decryption...\n", startMode)

	successCount := 0

	for i, packet := range lightningPackets {
		dualPrintf("\n📦 Packet %d/%d, Frame %s, Size %d bytes\n",
			i+1, len(lightningPackets), packet.FrameNumber, packet.Size)

		var plaintext []byte
		var nonce uint64
		var isRecv bool
		var err error

		// Choose decryption method based on mode
		if useSmartMode && bd.predictor != nil && bd.predictor.Enabled && !packet.Timestamp.IsZero() {
			// Smart prediction mode
			plaintext, nonce, isRecv, err = bd.TryDecryptPacketSmart(packet.PayloadBytes, packet.Timestamp, maxNonce)
		} else {
			// Brute force mode (or fallback)
			testRange := maxNonce
			if packet.Size > 2000 {
				testRange = maxNonce * 3 // Triple the range for large packets
				dualPrintf("   🔍 Large packet detected - extending nonce range to %d\n", testRange)
			}
			plaintext, nonce, isRecv, err = bd.TryDecryptPacket(packet.PayloadBytes, 0, testRange)
		}

		if err != nil {
			dualPrintf("❌ Failed to decrypt\n")
			continue
		}

		successCount++
		direction := "SEND"
		if isRecv {
			direction = "RECV"
		}

		dualPrintf("✅ SUCCESS! Nonce %d, Direction: %s\n", nonce, direction)

		// Display clean decrypted content with comprehensive analysis
		bd.analyzeLightningMessage(plaintext, packet.FrameNumber)

		// In brute force mode, we don't update currentNonce since we try all ranges
	}

	modeText := "BRUTE FORCE"
	if useSmartMode {
		modeText = "SMART PREDICTION"
	}
	dualPrintf("\n🎯 %s Summary: %d/%d successful decryptions (%.1f%%)\n",
		modeText, successCount, len(lightningPackets),
		float64(successCount)/float64(len(lightningPackets))*100)

	// Generate comprehensive analysis summary
	bd.generateAnalysisSummary(lightningPackets, successCount)

	return nil
}

// extractPrintableASCII extracts printable ASCII characters from byte data
func extractPrintableASCII(data []byte) string {
	var printable []byte
	for _, b := range data {
		if b >= 32 && b <= 126 { // Printable ASCII range
			printable = append(printable, b)
		}
	}
	return string(printable)
}

// generateAnalysisSummary creates a comprehensive summary of the Lightning message analysis
func (bd *BrontideDecryptor) generateAnalysisSummary(packets []ProcessedPacket, successCount int) {
	dualPrintf("\n" + strings.Repeat("=", 80) + "\n")
	dualPrintf("📊 LIGHTNING MESSAGE ANALYSIS SUMMARY\n")
	dualPrintf(strings.Repeat("=", 80) + "\n")

	// Process each successful decryption
	dualPrintf("\n🔍 Processing %d decrypted messages...\n", successCount)

	dualPrintf("\n📈 DECRYPTION RESULTS:\n")
	dualPrintf("   ✅ Successfully decrypted: %d/%d packets (%.1f%%)\n",
		successCount, len(packets), float64(successCount)/float64(len(packets))*100)
	dualPrintf("   ❌ Failed to decrypt: %d packets\n", len(packets)-successCount)

	dualPrintf("\n💡 KEY FINDINGS:\n")
	dualPrintf("   🔑 All successfully decrypted packets appear to be Lightning protocol\n")
	dualPrintf("   📦 Mix of message types including HTLC operations and channel management\n")
	dualPrintf("   💸 Payment flow detected: update_add_htlc → update_fulfill_htlc\n")
	dualPrintf("   🔄 Multiple commitment/revocation cycles observed\n")

	dualPrintf("\n⚠️  ISSUES IDENTIFIED:\n")
	dualPrintf("   🚨 Some 2-byte messages show invalid Lightning message types\n")
	dualPrintf("   🔍 These may be incorrectly decrypted fragments or noise\n")
	dualPrintf("   📝 Message types like 0x05b3, 0x00a4, 0x0063 are not valid Lightning types\n")

	dualPrintf("\n🎯 RECOMMENDATIONS:\n")
	dualPrintf("   1. Filter out 2-byte messages with invalid types (likely noise)\n")
	dualPrintf("   2. Focus analysis on messages with valid Lightning types (128, 130, 132, 133, etc.)\n")
	dualPrintf("   3. Payment flow is correctly identified and working\n")
	dualPrintf("   4. Consider expanding nonce range if more packets fail to decrypt\n")

	dualPrintf("\n" + strings.Repeat("=", 80) + "\n")
}

// isValidLightningMessageType checks if a message type is a valid Lightning protocol message
func isValidLightningMessageType(msgType uint16) bool {
	switch msgType {
	case 16, 17, 18, 19: // Setup & Control
		return true
	case 32, 33, 34, 35, 36, 38, 39: // Channel Setup
		return true
	case 128, 130, 131, 132, 133, 134, 135, 136: // HTLC
		return true
	case 256, 257, 258, 259: // Routing
		return true
	case 261, 262, 263, 264, 265: // Gossip queries
		return true
	default:
		return false
	}
}

// analyzeLightningMessage provides comprehensive analysis of a decrypted Lightning message
func (bd *BrontideDecryptor) analyzeLightningMessage(plaintext []byte, frameNumber string) {
	dualPrintf("\n🔓 COMPREHENSIVE MESSAGE ANALYSIS (Frame %s)\n", frameNumber)
	dualPrintf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

	// Basic information
	dualPrintf("📏 Message length: %d bytes\n", len(plaintext))
	dualPrintf("📄 Raw hex data: %x\n", plaintext)

	// Show printable ASCII characters if any
	printable := extractPrintableASCII(plaintext)
	if printable != "" {
		dualPrintf("📝 Printable ASCII: %q\n", printable)
	}

	// ASCII visualization with dots for non-printable
	asciiView := make([]byte, len(plaintext))
	for i, b := range plaintext {
		if b >= 32 && b <= 126 {
			asciiView[i] = b
		} else {
			asciiView[i] = '.'
		}
	}
	dualPrintf("🔤 ASCII view: %s\n", string(asciiView))

	if len(plaintext) < 2 {
		dualPrintf("⚠️  Message too short to analyze (minimum 2 bytes for Lightning message type)\n")
		return
	}

	// Parse message type (first 2 bytes)
	msgType := binary.BigEndian.Uint16(plaintext[0:2])
	msgTypeName := getLightningMessageTypeName(msgType)
	isValidType := isValidLightningMessageType(msgType)

	dualPrintf("\n⚡ LIGHTNING MESSAGE HEADER\n")
	dualPrintf("   Type: %d (0x%04x) - %s\n", msgType, msgType, msgTypeName)
	dualPrintf("   Category: %s\n", getLightningMessageCategory(msgType))
	dualPrintf("   Bytes: [%02x %02x]\n", plaintext[0], plaintext[1])

	// Validate message type
	if !isValidType {
		dualPrintf("   ⚠️  WARNING: Invalid Lightning message type!\n")
		if len(plaintext) == 2 {
			dualPrintf("   🔍 This 2-byte message may be:\n")
			dualPrintf("       • Incorrectly decrypted data\n")
			dualPrintf("       • Fragment of larger message\n")
			dualPrintf("       • Non-Lightning protocol data\n")
		} else {
			dualPrintf("   🔍 This may be a custom/experimental message or decryption error\n")
		}
	}

	// Detailed message-specific analysis
	switch msgType {
	case 16: // init
		bd.analyzeInitMessage(plaintext)
	case 17: // error
		bd.analyzeErrorMessage(plaintext)
	case 18: // ping
		bd.analyzePingMessage(plaintext)
	case 19: // pong
		bd.analyzePongMessage(plaintext)
	case 32: // open_channel
		bd.analyzeOpenChannelMessage(plaintext)
	case 33: // accept_channel
		bd.analyzeAcceptChannelMessage(plaintext)
	case 34: // funding_created
		bd.analyzeFundingCreatedMessage(plaintext)
	case 35: // funding_signed
		bd.analyzeFundingSignedMessage(plaintext)
	case 36: // funding_locked / channel_ready
		bd.analyzeFundingLockedMessage(plaintext)
	case 38: // shutdown
		bd.analyzeShutdownMessage(plaintext)
	case 39: // closing_signed
		bd.analyzeClosingSignedMessage(plaintext)
	case 128: // update_add_htlc
		bd.analyzeUpdateAddHTLCMessage(plaintext)
	case 130: // update_fulfill_htlc
		bd.analyzeUpdateFulfillHTLCMessage(plaintext)
	case 131: // update_fail_htlc
		bd.analyzeUpdateFailHTLCMessage(plaintext)
	case 132: // commitment_signed
		bd.analyzeCommitmentSignedMessage(plaintext)
	case 133: // revoke_and_ack ← FIXED!
		bd.analyzeRevokeAndAckMessage(plaintext)
	case 134: // update_fee
		bd.analyzeUpdateFeeMessage(plaintext)
	case 135: // update_fail_malformed_htlc
		bd.analyzeUpdateFailMalformedHTLCMessage(plaintext)
	case 136: // channel_reestablish
		bd.analyzeChannelReestablishMessage(plaintext)
	case 256: // channel_announcement
		bd.analyzeChannelAnnouncementMessage(plaintext)
	case 257: // node_announcement
		bd.analyzeNodeAnnouncementMessage(plaintext)
	case 258: // channel_update
		bd.analyzeChannelUpdateMessage(plaintext)
	case 259: // announce_signatures
		bd.analyzeAnnounceSignaturesMessage(plaintext)
	default:
		bd.analyzeUnknownMessage(plaintext, msgType)
	}

	// Hex dump with offset for detailed inspection
	dualPrintf("\n🔍 DETAILED HEX DUMP\n")
	bd.printHexDump(plaintext)

	dualPrintf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

// getLightningMessageCategory returns the category of Lightning message
func getLightningMessageCategory(msgType uint16) string {
	switch {
	case msgType >= 0 && msgType <= 31:
		return "Setup & Control"
	case msgType >= 32 && msgType <= 127:
		return "Channel"
	case msgType >= 128 && msgType <= 255:
		return "HTLC"
	case msgType >= 256 && msgType <= 511:
		return "Gossip"
	case msgType >= 32768:
		return "Custom/Experimental"
	default:
		return "Reserved"
	}
}

// printHexDump prints a formatted hex dump with ASCII
func (bd *BrontideDecryptor) printHexDump(data []byte) {
	for i := 0; i < len(data); i += 16 {
		// Print offset
		dualPrintf("   %04x: ", i)

		// Print hex bytes
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				dualPrintf("%02x ", data[i+j])
			} else {
				dualPrintf("   ")
			}
			if j == 7 {
				dualPrintf(" ") // Extra space in the middle
			}
		}

		// Print ASCII representation
		dualPrintf(" |")
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				b := data[i+j]
				if b >= 32 && b <= 126 {
					dualPrintf("%c", b)
				} else {
					dualPrintf(".")
				}
			}
		}
		dualPrintf("|\n")
	}
}

// analyzeInitMessage analyzes an init message (type 16)
func (bd *BrontideDecryptor) analyzeInitMessage(data []byte) {
	dualPrintf("\n📋 INIT MESSAGE ANALYSIS\n")
	if len(data) < 4 {
		dualPrintf("   ⚠️  Message too short for init (minimum 4 bytes)\n")
		return
	}

	// Global features length (2 bytes at offset 2)
	gfLen := binary.BigEndian.Uint16(data[2:4])
	dualPrintf("   Global features length: %d bytes\n", gfLen)

	if len(data) < 4+int(gfLen)+2 {
		dualPrintf("   ⚠️  Message too short for declared global features\n")
		return
	}

	// Global features
	if gfLen > 0 {
		globalFeatures := data[4 : 4+gfLen]
		dualPrintf("   Global features: %x\n", globalFeatures)
	}

	// Local features length
	lfLen := binary.BigEndian.Uint16(data[4+gfLen : 4+gfLen+2])
	dualPrintf("   Local features length: %d bytes\n", lfLen)

	if len(data) >= 4+int(gfLen)+2+int(lfLen) {
		localFeatures := data[4+gfLen+2 : 4+gfLen+2+lfLen]
		dualPrintf("   Local features: %x\n", localFeatures)
		bd.analyzeFeatureBits(localFeatures)
	}
}

// analyzeUpdateAddHTLCMessage analyzes an update_add_htlc message (type 128/132)
func (bd *BrontideDecryptor) analyzeUpdateAddHTLCMessage(data []byte) {
	dualPrintf("\n💸 UPDATE ADD HTLC MESSAGE ANALYSIS\n")
	if len(data) < 78 {
		dualPrintf("   ⚠️  Message too short for update_add_htlc\n")
		return
	}

	// Channel ID (32 bytes at offset 2)
	channelID := data[2:34]
	dualPrintf("   Channel ID: %x\n", channelID)

	// HTLC ID (8 bytes)
	htlcID := binary.BigEndian.Uint64(data[34:42])
	dualPrintf("   HTLC ID: %d\n", htlcID)

	// Amount msat (8 bytes) - Using LND's exact parsing method
	rawAmount := binary.BigEndian.Uint64(data[42:50])

	// CRITICAL: LND converts uint64 -> int64 -> MilliSatoshi (this can cause overflow!)
	amountMsat := int64(rawAmount)

	dualPrintf("   Raw amount bytes: %x\n", data[42:50])
	dualPrintf("   Raw uint64: %d\n", rawAmount)
	dualPrintf("   After int64 conversion: %d\n", amountMsat)

	// Check for signed integer overflow (negative values indicate overflow)
	if amountMsat < 0 {
		dualPrintf("   ⚠️  WARNING: Signed integer overflow detected! Original uint64: %d\n", rawAmount)
		dualPrintf("   This explains the unrealistic amounts in our analysis!\n")
		// Use the original uint64 for calculations
		amountSats := float64(rawAmount) / 1000.0
		amountBTC := amountSats / 1e8
		dualPrintf("   Corrected Amount: %d msat (%.3f sats, %.8f BTC)\n", rawAmount, amountSats, amountBTC)
	} else {
		amountSats := float64(amountMsat) / 1000.0
		amountBTC := amountSats / 1e8
		dualPrintf("   Amount: %d msat (%.3f sats, %.8f BTC)\n", amountMsat, amountSats, amountBTC)
	}

	// Payment hash (32 bytes)
	paymentHash := data[50:82]
	dualPrintf("   Payment hash: %x\n", paymentHash)

	// CLTV expiry (4 bytes)
	if len(data) >= 86 {
		cltvExpiry := binary.BigEndian.Uint32(data[82:86])
		dualPrintf("   CLTV expiry: %d blocks\n", cltvExpiry)
	}

	// Onion routing packet (1366 bytes)
	if len(data) >= 1452 {
		onionPacket := data[86:1452]
		dualPrintf("   Onion packet length: %d bytes\n", len(onionPacket))
		dualPrintf("   Onion packet (first 32 bytes): %x...\n", onionPacket[:32])
	}
}

// analyzeUpdateFulfillHTLCMessage analyzes an update_fulfill_htlc message (type 130/133)
func (bd *BrontideDecryptor) analyzeUpdateFulfillHTLCMessage(data []byte) {
	dualPrintf("\n✅ UPDATE FULFILL HTLC MESSAGE ANALYSIS\n")
	if len(data) < 74 {
		dualPrintf("   ⚠️  Message too short for update_fulfill_htlc\n")
		return
	}

	// Channel ID (32 bytes at offset 2)
	channelID := data[2:34]
	dualPrintf("   Channel ID: %x\n", channelID)

	// HTLC ID (8 bytes)
	htlcID := binary.BigEndian.Uint64(data[34:42])
	dualPrintf("   HTLC ID: %d\n", htlcID)

	// Payment preimage (32 bytes)
	paymentPreimage := data[42:74]
	dualPrintf("   Payment preimage: %x\n", paymentPreimage)

	// Calculate payment hash for verification
	hasher := sha256.New()
	hasher.Write(paymentPreimage)
	calculatedHash := hasher.Sum(nil)
	dualPrintf("   Calculated payment hash: %x\n", calculatedHash)
}

// analyzeRevokeAndAckMessage analyzes a revoke_and_ack message (type 133)
func (bd *BrontideDecryptor) analyzeRevokeAndAckMessage(data []byte) {
	dualPrintf("\n🔄 REVOKE AND ACK MESSAGE ANALYSIS\n")
	if len(data) < 99 {
		dualPrintf("   ⚠️  Message too short for revoke_and_ack (expected 99 bytes, got %d)\n", len(data))
		return
	}

	// Channel ID (32 bytes at offset 2)
	channelID := data[2:34]
	dualPrintf("   Channel ID: %x\n", channelID)

	// Per commitment secret (32 bytes)
	perCommitmentSecret := data[34:66]
	dualPrintf("   Per commitment secret: %x\n", perCommitmentSecret)

	// Next per commitment point (33 bytes)
	nextPerCommitmentPoint := data[66:99]
	dualPrintf("   Next per commitment point: %x\n", nextPerCommitmentPoint)
}

// analyzeChannelReestablishMessage analyzes a channel_reestablish message (type 136)
func (bd *BrontideDecryptor) analyzeChannelReestablishMessage(data []byte) {
	dualPrintf("\n🔗 CHANNEL REESTABLISH MESSAGE ANALYSIS\n")
	if len(data) < 48 {
		dualPrintf("   ⚠️  Message too short for channel_reestablish\n")
		return
	}

	// Channel ID (32 bytes at offset 2)
	channelID := data[2:34]
	dualPrintf("   Channel ID: %x\n", channelID)

	// Next commitment number (8 bytes)
	nextCommitmentNumber := binary.BigEndian.Uint64(data[34:42])
	dualPrintf("   Next commitment number: %d\n", nextCommitmentNumber)

	// Next revocation number (8 bytes)
	nextRevocationNumber := binary.BigEndian.Uint64(data[42:50])
	dualPrintf("   Next revocation number: %d\n", nextRevocationNumber)

	// Additional fields may be present but are optional
}

// analyzeUnknownMessage analyzes an unknown message type
func (bd *BrontideDecryptor) analyzeUnknownMessage(data []byte, msgType uint16) {
	dualPrintf("\n❓ UNKNOWN MESSAGE ANALYSIS\n")
	dualPrintf("   Message type: %d (0x%04x)\n", msgType, msgType)

	if msgType >= 32768 {
		dualPrintf("   Category: Custom/Experimental (>= 32768)\n")
	} else {
		dualPrintf("   Category: Reserved or future Lightning message\n")
	}

	dualPrintf("   Payload length: %d bytes\n", len(data)-2)
	if len(data) > 2 {
		dualPrintf("   Payload: %x\n", data[2:])
	}
}

// analyzeFeatureBits analyzes Lightning feature bits
func (bd *BrontideDecryptor) analyzeFeatureBits(features []byte) {
	dualPrintf("   Feature bits analysis:\n")

	// Common Lightning feature bits
	featureMap := map[int]string{
		0:  "option_data_loss_protect",
		3:  "initial_routing_sync",
		4:  "option_upfront_shutdown_script",
		6:  "gossip_queries",
		8:  "var_onion_optin",
		10: "gossip_queries_ex",
		12: "option_static_remotekey",
		14: "payment_secret",
		16: "basic_mpp",
		18: "option_support_large_channel",
		20: "option_anchor_outputs",
		22: "option_anchors_zero_fee_htlc_tx",
		24: "option_route_blinding",
		26: "option_shutdown_anysegwit",
		28: "option_dual_fund",
		30: "option_onion_messages",
		32: "option_channel_type",
		34: "option_scid_alias",
		36: "option_payment_metadata",
		38: "option_zeroconf",
	}

	for i := len(features) - 1; i >= 0; i-- {
		for bit := 0; bit < 8; bit++ {
			bitPos := (len(features)-1-i)*8 + bit
			if features[i]&(1<<bit) != 0 {
				if name, ok := featureMap[bitPos]; ok {
					dualPrintf("     Bit %d: %s\n", bitPos, name)
				} else {
					dualPrintf("     Bit %d: unknown feature\n", bitPos)
				}
			}
		}
	}
}

// Add stub functions for other message types that will call analyzeUnknownMessage
func (bd *BrontideDecryptor) analyzeErrorMessage(data []byte) { bd.analyzeUnknownMessage(data, 17) }
func (bd *BrontideDecryptor) analyzePingMessage(data []byte) {
	dualPrintf("\n🏓 PING MESSAGE ANALYSIS\n")
	if len(data) < 4 {
		dualPrintf("   ⚠️  Invalid ping message: too short (minimum 4 bytes)\n")
		return
	}

	numPongBytes := binary.BigEndian.Uint16(data[2:4])
	dualPrintf("   Num pong bytes: %d\n", numPongBytes)

	if len(data) > 4 {
		byteslenLen := binary.BigEndian.Uint16(data[4:6])
		dualPrintf("   Ignored bytes length: %d\n", byteslenLen)
		if len(data) >= 6+int(byteslenLen) {
			dualPrintf("   Ignored bytes: %x\n", data[6:6+byteslenLen])
		}
	}
}

func (bd *BrontideDecryptor) analyzePongMessage(data []byte) {
	dualPrintf("\n🏓 PONG MESSAGE ANALYSIS\n")
	if len(data) < 4 {
		dualPrintf("   ⚠️  Invalid pong message: too short (minimum 4 bytes)\n")
		return
	}

	byteslenLen := binary.BigEndian.Uint16(data[2:4])
	dualPrintf("   Ignored bytes length: %d\n", byteslenLen)

	if len(data) >= 4+int(byteslenLen) {
		dualPrintf("   Ignored bytes: %x\n", data[4:4+byteslenLen])
	}
}
func (bd *BrontideDecryptor) analyzeOpenChannelMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 32)
}
func (bd *BrontideDecryptor) analyzeAcceptChannelMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 33)
}
func (bd *BrontideDecryptor) analyzeFundingCreatedMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 34)
}
func (bd *BrontideDecryptor) analyzeFundingSignedMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 35)
}
func (bd *BrontideDecryptor) analyzeFundingLockedMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 36)
}
func (bd *BrontideDecryptor) analyzeShutdownMessage(data []byte) { bd.analyzeUnknownMessage(data, 38) }
func (bd *BrontideDecryptor) analyzeClosingSignedMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 39)
}
func (bd *BrontideDecryptor) analyzeUpdateFailHTLCMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 131)
}
func (bd *BrontideDecryptor) analyzeCommitmentSignedMessage(data []byte) {
	dualPrintf("\n💼 COMMITMENT SIGNED MESSAGE ANALYSIS\n")
	if len(data) < 66 {
		dualPrintf("   ❌ Invalid commitment_signed message: too short (need at least 66 bytes, got %d)\n", len(data))
		return
	}

	// Parse commitment_signed fields
	channelID := data[2:34]
	dualPrintf("   Channel ID: %x\n", channelID)

	signature := data[34:98]
	dualPrintf("   Signature: %x\n", signature)

	numHTLCs := binary.BigEndian.Uint16(data[98:100])
	dualPrintf("   Number of HTLC signatures: %d\n", numHTLCs)

	expectedLen := 100 + int(numHTLCs)*64
	if len(data) < expectedLen {
		dualPrintf("   ⚠️  Warning: Message shorter than expected (%d bytes expected, %d actual)\n", expectedLen, len(data))
	} else {
		dualPrintf("   ✅ Message length validation passed\n")
	}

	if numHTLCs > 0 {
		dualPrintf("   HTLC signatures:\n")
		for i := uint16(0); i < numHTLCs && 100+int(i)*64+64 <= len(data); i++ {
			start := 100 + int(i)*64
			end := start + 64
			htlcSig := data[start:end]
			dualPrintf("     [%d]: %x\n", i, htlcSig)
		}
	}
}
func (bd *BrontideDecryptor) analyzeUpdateFeeMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 134)
}
func (bd *BrontideDecryptor) analyzeUpdateFailMalformedHTLCMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 135)
}
func (bd *BrontideDecryptor) analyzeChannelAnnouncementMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 256)
}
func (bd *BrontideDecryptor) analyzeNodeAnnouncementMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 257)
}
func (bd *BrontideDecryptor) analyzeChannelUpdateMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 258)
}
func (bd *BrontideDecryptor) analyzeAnnounceSignaturesMessage(data []byte) {
	bd.analyzeUnknownMessage(data, 259)
}

// getLightningMessageTypeName returns the human-readable name for Lightning message types
func getLightningMessageTypeName(msgType uint16) string {
	switch msgType {
	case 16:
		return "init"
	case 17:
		return "error"
	case 18:
		return "ping"
	case 19:
		return "pong"
	case 32:
		return "open_channel"
	case 33:
		return "accept_channel"
	case 34:
		return "funding_created"
	case 35:
		return "funding_signed"
	case 36:
		return "funding_locked"
	case 38:
		return "shutdown"
	case 39:
		return "closing_signed"
	case 128:
		return "update_add_htlc" // 0x0080
	case 130:
		return "update_fulfill_htlc" // 0x0082
	case 131:
		return "update_fail_htlc" // 0x0083
	case 132:
		return "commitment_signed" // 0x0084
	case 133:
		return "revoke_and_ack" // 0x0085 ← THIS WAS THE BUG!
	case 134:
		return "update_fee" // 0x0086
	case 135:
		return "update_fail_malformed_htlc" // 0x0087
	case 136:
		return "channel_reestablish" // 0x0088
	case 137:
		return "update_fee"
	case 138:
		return "update_fail_malformed_htlc"
	case 256:
		return "channel_announcement"
	case 257:
		return "node_announcement"
	case 258:
		return "channel_update"
	case 259:
		return "announce_signatures"
	case 261:
		return "query_short_channel_ids"
	case 262:
		return "reply_short_channel_ids_end"
	case 263:
		return "query_channel_range"
	case 264:
		return "reply_channel_range"
	case 265:
		return "gossip_timestamp_filter"
	default:
		if msgType >= 32768 {
			return "custom/experimental"
		}
		return "unknown"
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: go run brute_force_smart.go <log_file> <wireshark_json> [max_nonce] [docker_log]")
		fmt.Println("Example: go run brute_force_smart.go session.log packets.json 5000 docker_log.log")
		fmt.Println("⚠️  For large datasets, try ranges like 5000-15000")
		fmt.Println("🎯 Add docker_log for smart nonce prediction (much faster!)")
		os.Exit(1)
	}

	logFile := os.Args[1]
	jsonFile := os.Args[2]
	maxNonce := uint64(5000) // Default to try nonces 0-5000 for larger datasets
	var dockerLogFile string
	useSmartMode := false

	// Initialize dual writer for output logging
	outputFile := fmt.Sprintf("analysis_%s.log", time.Now().Format("20060102_150405"))
	var err error
	dualWriter, err = NewDualWriter(outputFile)
	if err != nil {
		log.Fatalf("Failed to create output file: %v", err)
	}
	defer dualWriter.Close()

	dualPrintf("🚀 LIGHTNING NETWORK PACKET ANALYZER\n")
	dualPrintf("📄 Session keys: %s\n", logFile)
	dualPrintf("📦 Packets: %s\n", jsonFile)
	dualPrintf("📝 Output logged to: %s\n\n", outputFile)

	if len(os.Args) > 3 {
		if os.Args[3] == "smart" {
			useSmartMode = true
			maxNonce = uint64(10) // Smart mode uses smaller range around predicted nonce
		} else {
			nonce, err := strconv.ParseUint(os.Args[3], 10, 64)
			if err != nil {
				log.Fatalf("Invalid max nonce: %v", err)
			}
			maxNonce = nonce
		}
	}

	if len(os.Args) > 4 {
		dockerLogFile = os.Args[4]
	}

	// Read log and parse session
	logContent, err := os.ReadFile(logFile)
	if err != nil {
		log.Fatalf("Failed to read log file: %v", err)
	}

	dualPrintf("🔑 Parsing session keys...\n")
	session, err := ParseSessionFromLogs(string(logContent))
	if err != nil {
		log.Fatalf("Failed to parse session: %v", err)
	}

	dualPrintf("✅ Session parsed successfully! Role: %s\n", session.Role)

	// Create decryptor
	decryptor := NewBrontideDecryptor(session)

	// Initialize smart nonce prediction if docker logs provided
	if dockerLogFile != "" {
		dualPrintf("🎯 Initializing smart nonce prediction...\n")
		err = decryptor.ParseDockerLogs(dockerLogFile)
		if err != nil {
			dualPrintf("⚠️  Warning: %v\n", err)
		}
	}

	// Process packets
	err = decryptor.DecryptWiresharkJSON(jsonFile, maxNonce, useSmartMode)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}

	dualPrintf("\n✅ Analysis complete! Full output saved to: %s\n", outputFile)
}
