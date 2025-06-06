package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"fmt"

	"github.com/aniagut/msc-bbs/keygen"
	"github.com/aniagut/msc-bbs/open"
	"github.com/aniagut/msc-bbs/sign"
	"github.com/aniagut/msc-bbs/verify"
	"github.com/aniagut/msc-bbs/models"
	"github.com/aniagut/msc-bbs/utils"

	"github.com/aniagut/msc-bbs-anonymous-credentials/setup"
    "github.com/aniagut/msc-bbs-anonymous-credentials/issue"
    "github.com/aniagut/msc-bbs-anonymous-credentials/presentation"
    credVerify "github.com/aniagut/msc-bbs-anonymous-credentials/verify"
	credModels "github.com/aniagut/msc-bbs-anonymous-credentials/models"

	e "github.com/cloudflare/circl/ecc/bls12381"
)

var (
	pubKey    models.PublicKey
	users     []models.User
	managerSK models.SecretManagerKey
	lock      sync.Mutex

	managerPassword = "supersecret"

	userPasswords = map[int]string{
        1: "alicepwd",
        2: "bobpwd",
        3: "carolpwd",
        4: "davepwd",
        5: "evepwd",
    }
)

// SigResponse wraps a BBS signature’s fields as base64 strings
type SigResponse struct {
	T1      string `json:"T1"`
	T2      string `json:"T2"`
	T3      string `json:"T3"`
	C       string `json:"C"`
	SAlpha  string `json:"SAlpha"`
	SBeta   string `json:"SBeta"`
	SX      string `json:"SX"`
	SDelta1 string `json:"SDelta1"`
	SDelta2 string `json:"SDelta2"`
}

type SigRequest struct {
    T1      string `json:"T1"`
    T2      string `json:"T2"`
    T3      string `json:"T3"`
    C       string `json:"C"`
    SAlpha  string `json:"SAlpha"`
    SBeta   string `json:"SBeta"`
    SX      string `json:"SX"`
    SDelta1 string `json:"SDelta1"`
    SDelta2 string `json:"SDelta2"`
}


type CredParamsResponse struct {
    G1  string   `json:"G1"`
    G2  string   `json:"G2"`
    H1  []string `json:"H1"`
}

type CredSigResponse struct {
    A     string `json:"A"`
    E     string `json:"E"`
}

type CredProofResponse struct {
	APrim string   `json:"aPrim"`
	Bprim string   `json:"bPrim"`
	Ch  string   `json:"ch"`
	Zr string   `json:"zr"`
	Zi []string `json:"zi"`
	Ze string `json:"ze"`
}


func main() {
	rootFS := http.FileServer(http.Dir("static"))
	http.Handle("/", rootFS)

    // ─── 1) Serve “/group/” from ./static/group ─────────────────────────────
    groupFS := http.FileServer(http.Dir("static/group"))
    // any request under /group/ → look in static/group/
    http.Handle("/group/", http.StripPrefix("/group/", groupFS))

    // ─── 2) Serve “/cred/” from ./static/cred ──────────────────────────────
    credFS := http.FileServer(http.Dir("static/cred"))
    http.Handle("/cred/", http.StripPrefix("/cred/", credFS))

    // ─── 3) Register AJAX endpoints (these stay at top‐level URLs) ─────────
    http.HandleFunc("/group/keygen", handleKeyGen)
    http.HandleFunc("/group/sign", handleSign)
    http.HandleFunc("/group/verify", handleVerify)
    http.HandleFunc("/group/open", handleOpen)

    http.HandleFunc("/cred/setup", handleCredSetup)
    http.HandleFunc("/cred/issue", handleCredIssue)
    http.HandleFunc("/cred/present", handleCredPresent)
    http.HandleFunc("/cred/verify", handleCredVerify)

    fmt.Println("Starting demo on http://localhost:8080 …")
    http.ListenAndServe(":8080", nil);
}

func checkManagerAuth(r *http.Request) bool {
    pwd := r.URL.Query().Get("mgrpwd")
    return pwd == managerPassword
}

func checkUserAuth(r *http.Request, signerIdx int) bool {
	supplied := r.URL.Query().Get("upwd")
	expected, exists := userPasswords[signerIdx]
	return exists && (supplied == expected)
}

func handleKeyGen(w http.ResponseWriter, r *http.Request) {
	if !checkManagerAuth(r) {
        http.Error(w, "Unauthorized: invalid manager password", http.StatusUnauthorized)
        return
    }

	size := r.URL.Query().Get("size")
	n, _ := strconv.Atoi(size)

	lock.Lock()
	defer lock.Unlock()

	result, err := keygen.KeyGen(n)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pubKey = result.PublicKey
	users = result.Users
	managerSK = result.SecretManagerKey

	w.Write([]byte("Generated group with " + strconv.Itoa(n) + " users.\n"))
}

func handleSign(w http.ResponseWriter, r *http.Request) {
	signerStr := r.URL.Query().Get("signer")
	idx64, err := strconv.ParseInt(signerStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid `signer` parameter", http.StatusBadRequest)
		return
	}
	idx := int(idx64)

	// 2) Check user+password
	if !checkUserAuth(r, idx) {
		http.Error(w, "Unauthorized: invalid user index or password", http.StatusUnauthorized)
		return
	}

	msg := r.URL.Query().Get("msg")
	if msg == "" {
		http.Error(w, "Missing `msg` parameter", http.StatusBadRequest)
		return
	}

	lock.Lock()
	defer lock.Unlock()

	if len(users) == 0 {
		http.Error(w, "Group not initialized", http.StatusBadRequest)
		return
	}
	if idx < 1 || idx > len(users) {
		http.Error(w, "Invalid `signer` index", http.StatusBadRequest)
		return
	}

	fmt.Printf("Signing message '%s' with user #%d\n", msg, idx)


	bbsSig, err := sign.Sign(pubKey, users[idx-1], msg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Marshal each element as bytes, then Base64‐encode
	// (assumes T1, T2, T3 are *e.G1 and C is *e.G1, etc. – adjust types if different)
	t1Bytes := utils.SerializeG1(bbsSig.T1)
	t2Bytes := utils.SerializeG1(bbsSig.T2)
	t3Bytes := utils.SerializeG1(bbsSig.T3)
	cBytes, _ := bbsSig.C.MarshalBinary()
	saBytes, _ := bbsSig.SAlpha.MarshalBinary()
	sbBytes, _ := bbsSig.SBeta.MarshalBinary()
	sxBytes, _ := bbsSig.SX.MarshalBinary()
	sd1Bytes, _ := bbsSig.SDelta1.MarshalBinary()
	sd2Bytes, _ := bbsSig.SDelta2.MarshalBinary()

	resp := SigResponse{
		T1:      base64.StdEncoding.EncodeToString(t1Bytes),
		T2:      base64.StdEncoding.EncodeToString(t2Bytes),
		T3:      base64.StdEncoding.EncodeToString(t3Bytes),
		C:       base64.StdEncoding.EncodeToString(cBytes),
		SAlpha:  base64.StdEncoding.EncodeToString(saBytes),
		SBeta:   base64.StdEncoding.EncodeToString(sbBytes),
		SX:      base64.StdEncoding.EncodeToString(sxBytes),
		SDelta1: base64.StdEncoding.EncodeToString(sd1Bytes),
		SDelta2: base64.StdEncoding.EncodeToString(sd2Bytes),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")

	// 1) Decode JSON into SigRequest
	var req SigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// 2) Base64‐decode each field
	t1Bytes, err := base64.StdEncoding.DecodeString(req.T1)
	if err != nil {
		http.Error(w, "Invalid Base64 for T1", http.StatusBadRequest)
		return
	}
	t2Bytes, _ := base64.StdEncoding.DecodeString(req.T2)
	t3Bytes, _ := base64.StdEncoding.DecodeString(req.T3)
	cBytes, _  := base64.StdEncoding.DecodeString(req.C)
	saBytes, _ := base64.StdEncoding.DecodeString(req.SAlpha)
	sbBytes, _ := base64.StdEncoding.DecodeString(req.SBeta)
	sxBytes, _ := base64.StdEncoding.DecodeString(req.SX)
	sd1Bytes, _ := base64.StdEncoding.DecodeString(req.SDelta1)
	sd2Bytes, _ := base64.StdEncoding.DecodeString(req.SDelta2)

	// 3) Unmarshal bytes into G1 group elements (using your pairing library’s UnmarshalBinary)
	var t1, t2, t3 e.G1
	var cPt, sAlpha, sBeta, sX, sD1, sD2 e.Scalar
	if err := t1.SetBytes(t1Bytes); err != nil {
		http.Error(w, "Failed to unmarshal T1", http.StatusBadRequest)
		return
	}
	if err := t2.SetBytes(t2Bytes); err != nil {
		http.Error(w, "Failed to unmarshal T2", http.StatusBadRequest)
		return
	}
	if err := t3.SetBytes(t3Bytes); err != nil {
		http.Error(w, "Failed to unmarshal T3", http.StatusBadRequest)
		return
	}
	cPt.SetBytes(cBytes);

	// 4) Convert Base64‐decoded scalars into *big.Int
	sAlpha.SetBytes(saBytes)
	sBeta.SetBytes(sbBytes)
	sX.SetBytes(sxBytes)
	sD1.SetBytes(sd1Bytes)
	sD2.SetBytes(sd2Bytes)

	// 5) Reconstruct a models.Signature instance
	var sig models.Signature
	// If models.Signature stores pointers to G1 (not G1Affine), adjust accordingly:
	sig.T1 = &t1
	sig.T2 = &t2
	sig.T3 = &t3
	sig.C  = cPt

	sig.SAlpha  = &sAlpha
	sig.SBeta   = &sBeta
	sig.SX      = &sX
	sig.SDelta1 = &sD1
	sig.SDelta2 = &sD2

	// 6) Perform the actual Verify call
	lock.Lock()
	defer lock.Unlock()

	ok, err := verify.Verify(pubKey, msg, sig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Verified? %v", ok)
}

func handleOpen(w http.ResponseWriter, r *http.Request) {
	if !checkManagerAuth(r) {
		http.Error(w, "Unauthorized: invalid manager password", http.StatusUnauthorized)
		return
	}

	msg := r.URL.Query().Get("msg")
	if msg == "" {
		http.Error(w, "Missing `msg` parameter", http.StatusBadRequest)
		return
	}

	// Decode JSON into SigRequest
	var req SigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	// Base64‐decode each field
	t1Bytes, err := base64.StdEncoding.DecodeString(req.T1)
	if err != nil {
		http.Error(w, "Invalid Base64 for T1", http.StatusBadRequest)
		return
	}
	t2Bytes, _ := base64.StdEncoding.DecodeString(req.T2)
	t3Bytes, _ := base64.StdEncoding.DecodeString(req.T3)
	cBytes, _  := base64.StdEncoding.DecodeString(req.C)
	saBytes, _ := base64.StdEncoding.DecodeString(req.SAlpha)
	sbBytes, _ := base64.StdEncoding.DecodeString(req.SBeta)
	sxBytes, _ := base64.StdEncoding.DecodeString(req.SX)
	sd1Bytes, _ := base64.StdEncoding.DecodeString(req.SDelta1)
	sd2Bytes, _ := base64.StdEncoding.DecodeString(req.SDelta2)

	// Unmarshal bytes into G1 group elements
	var t1, t2, t3 e.G1
	var cPt e.Scalar
	if err := t1.SetBytes(t1Bytes); err != nil {
		http.Error(w, "Failed to unmarshal T1", http.StatusBadRequest)
		return
	}
	if err := t2.SetBytes(t2Bytes); err != nil {
		http.Error(w, "Failed to unmarshal T2", http.StatusBadRequest)
		return
	}
	if err := t3.SetBytes(t3Bytes); err != nil {
		http.Error(w, "Failed to unmarshal T3", http.StatusBadRequest)
		return
	}
	cPt.SetBytes(cBytes)

	// Unmarshal scalars
	var sAlpha, sBeta, sX, sD1, sD2 e.Scalar
	sAlpha.SetBytes(saBytes)
	sBeta.SetBytes(sbBytes)
	sX.SetBytes(sxBytes)
	sD1.SetBytes(sd1Bytes)
	sD2.SetBytes(sd2Bytes)

	// Reconstruct models.Signature
	var sig models.Signature
	sig.T1 = &t1
	sig.T2 = &t2
	sig.T3 = &t3
	sig.C  = cPt
	sig.SAlpha  = &sAlpha
	sig.SBeta   = &sBeta
	sig.SX      = &sX
	sig.SDelta1 = &sD1
	sig.SDelta2 = &sD2

	// Call open.Open
	lock.Lock()
	defer lock.Unlock()

	if len(users) == 0 {
		http.Error(w, "Group not initialized", http.StatusBadRequest)
		return
	}
	ownerIdx, err := open.Open(pubKey, managerSK, msg, sig, users)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(fmt.Sprintf("Signer is user #%d", ownerIdx+1)))
}

// Global state for the credential demo:
var (
    credParams    credModels.SetupResult       // holds PublicParameters + SecretKey after Setup()
    credSignature  credModels.Signature    // holds the issued credential signature
)

// handlerCredSetup drives setup.Setup(l) and returns the resulting public parameters as JSON.
func handleCredSetup(w http.ResponseWriter, r *http.Request) {
    // Expect: /cred/setup?l=5
    lStr := r.URL.Query().Get("l")
    l, err := strconv.Atoi(lStr)
    if err != nil || l <= 0 {
        http.Error(w, "Invalid or missing `l` parameter", http.StatusBadRequest)
        return
    }

    // Call setup.Setup(l)
    result, err := setup.Setup(l)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    // Store globally so we can issue later
    credParams = result

	// Convert points to base64 strings for JSON
	g1Bytes := credParams.PublicParameters.G1.Bytes();
	g2Bytes := credParams.PublicParameters.G2.Bytes();
	h1Bytes := make([][]byte, len(credParams.PublicParameters.H1))
	for i, h1 := range credParams.PublicParameters.H1 {
		h1Bytes[i] = h1.Bytes()
	}

	g1B64 := base64.StdEncoding.EncodeToString(g1Bytes)
	g2B64 := base64.StdEncoding.EncodeToString(g2Bytes)
	h1B64 := make([]string, len(h1Bytes))
	for i, h1 := range h1Bytes {
		h1B64[i] = base64.StdEncoding.EncodeToString(h1)
	}
	
	// Prepare response
	resp := CredParamsResponse{
        G1: g1B64,
        G2: g2B64,
        H1: h1B64,
    }

    // Return the public parameters as JSON (hide secret key)
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(resp)
}

// handlerCredIssue drives issue.Issue(attributes, PublicParameters, SecretKey),
// stores the resulting signature in credSignature, and returns it as JSON.
func handleCredIssue(w http.ResponseWriter, r *http.Request) {
    // Expect a JSON body like: {"attributes":["attr1","attr2","attr3"]}
    var req struct {
        Attributes []string `json:"attributes"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON body", http.StatusBadRequest)
        return
    }
    if len(credParams.PublicParameters.H1) == 0 {
        http.Error(w, "Public parameters not initialized. Call /cred/setup first", http.StatusBadRequest)
        return
    }

    sig, err := issue.Issue(req.Attributes, credParams.PublicParameters, credParams.SecretKey)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    credSignature = sig

	// Convert signature fields to base64 strings for JSON
	aBytes := sig.A.Bytes()
	eBytes, _ := sig.E.MarshalBinary()
	aB64 := base64.StdEncoding.EncodeToString(aBytes)
	eB64 := base64.StdEncoding.EncodeToString(eBytes)
	// Prepare response
	resp := CredSigResponse{
		A: aB64,
		E: eB64,
	}
	// Return the signature as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handlerCredPresent drives presentation.Presentation(attributes, signature, revealed, PublicParameters, nonce)
func handleCredPresent(w http.ResponseWriter, r *http.Request) {
    // Expect JSON body:
    // {
    //   "attributes": ["attr1","attr2","attr3","attr4","attr5"],
    //   "revealedIndices": [0,4],
    //   "nonce": "random_nonce_base64"
    // }
    var req struct {
        Attributes      []string `json:"attributes"`
        RevealedIndices []int    `json:"revealedIndices"`
        Nonce           string   `json:"nonce"` // base64-encoded or raw string
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON body", http.StatusBadRequest)
        return
    }
    if len(credParams.PublicParameters.H1) == 0 {
        http.Error(w, "Public parameters not initialized. Call /cred/setup first", http.StatusBadRequest)
        return
    }
    if credSignature.A == nil  {
        http.Error(w, "Credential not issued. Call /cred/issue first", http.StatusBadRequest)
        return
    }

    // Convert nonce string to []byte (if you Base64‐encoded it on the client, decode here)
    nonceBytes := []byte(req.Nonce)

    proof, err := presentation.Presentation(
        req.Attributes,
        credSignature,
        req.RevealedIndices,
        credParams.PublicParameters,
        nonceBytes,
    )
	//Print proof for debugging
	fmt.Printf("Proof: %+v\n", proof)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }

	// Convert proof fields to base64 strings for JSON
	aPrimB64 := base64.StdEncoding.EncodeToString(proof.APrim.Bytes())
	bPrimB64 := base64.StdEncoding.EncodeToString(proof.BPrim.Bytes())
	// Convert ch to base64 string
	chBytes, _ := proof.Ch.MarshalBinary()
	chB64 := base64.StdEncoding.EncodeToString(chBytes)
	// Convert zr to base64 string
	zRBytes, _ := proof.Zr.MarshalBinary()
	zrB64 := base64.StdEncoding.EncodeToString(zRBytes)
	// Convert zi to base64 strings
	ziBytes := make([][]byte, len(proof.Zi))
	for i, zi := range proof.Zi {
		ziBytes[i], _ = zi.MarshalBinary()
	}
	// Convert each zi to base64 string
	ziB64 := make([]string, len(proof.Zi))
	for i, _ := range proof.Zi {
		ziB64[i] = base64.StdEncoding.EncodeToString(ziBytes[i])
	}
	// Convert ze to base64 string
	zeBytes, _ := proof.Ze.MarshalBinary()
	zeB64 := base64.StdEncoding.EncodeToString(zeBytes)
	// Prepare response
	proofResp := CredProofResponse{
		APrim: aPrimB64,
		Bprim: bPrimB64,
		Ch:    chB64,
		Zr:    zrB64,
		Zi:    ziB64,
		Ze:    zeB64,
	}


    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(proofResp)
}

// handlerCredVerify drives verify.Verify(proof, nonce, revealedAttributes, revealedIndices, PublicParameters, PublicKey)
func handleCredVerify(w http.ResponseWriter, r *http.Request) {
    // Expect JSON body:
    // {
    //   "proof": { … presentation proof fields … },
    //   "nonce": "random_nonce_base64",
    //   "revealedAttributes": ["attr1","attr5"],
    //   "revealedIndices": [0,4]
    // }
    var req struct {
        Proof              CredProofResponse `json:"proof"`
        Nonce              string             `json:"nonce"`
        RevealedAttributes []string           `json:"revealedAttributes"`
        RevealedIndices    []int              `json:"revealedIndices"`
    }
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        http.Error(w, "Invalid JSON body", http.StatusBadRequest)
        return
    }
    if len(credParams.PublicParameters.H1) == 0 {
        http.Error(w, "Public parameters not initialized. Call /cred/setup first", http.StatusBadRequest)
        return
    }
	// Decode the proof fields from base64
	aPrimBytes, _ := base64.StdEncoding.DecodeString(req.Proof.APrim)
	bPrimBytes, _ := base64.StdEncoding.DecodeString(req.Proof.Bprim)
	chBytes, _ := base64.StdEncoding.DecodeString(req.Proof.Ch)
	zrBytes, _ := base64.StdEncoding.DecodeString(req.Proof.Zr)
	ziBytes := make([][]byte, len(req.Proof.Zi))
	for i, zi := range req.Proof.Zi {
		ziBytes[i], _ = base64.StdEncoding.DecodeString(zi)
	}
	zeBytes, _ := base64.StdEncoding.DecodeString(req.Proof.Ze)

	// Convert the proof fields to the appropriate types
	var aPrim, bPrim e.G1
	var ch, zr, ze e.Scalar
	zi := make([]e.Scalar, len(ziBytes))
	aPrim.SetBytes(aPrimBytes)
	bPrim.SetBytes(bPrimBytes)
	ch.SetBytes(chBytes)
	zr.SetBytes(zrBytes)
	for i, ziByte := range ziBytes {
		zi[i].SetBytes(ziByte)
	}
	ze.SetBytes(zeBytes)

	// Reconstruct the proof
	proof := credModels.SignatureProof{
		APrim: &aPrim,
		BPrim: &bPrim,
		Ch:    &ch,
		Zr:    &zr,
		Zi:    zi,
		Ze:    &ze,
	}

	// Print proof for debugging
	fmt.Printf("Proof: %+v\n", proof)


    nonceBytes := []byte(req.Nonce)
    isValid, err := credVerify.Verify(
        proof,
        nonceBytes,
        req.RevealedAttributes,
        req.RevealedIndices,
        credParams.PublicParameters,
        credParams.PublicKey,
    )
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    w.Write([]byte(fmt.Sprintf("Valid? %v", isValid)))
}

