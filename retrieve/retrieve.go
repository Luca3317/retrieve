package retrieve

// TODO
// turn this into module
// Below might be fixed

// Get public identity key to work correctly
// The deserialized pub key always adds a byte equal to 5 in front and loses the last byte
// Also, both have 33 bytes each, from ECPublicKey doc:
// "KeySize is the size of EC keys (32) with the EC type byte prepended to it."
// 5 is the type of djb keys

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"log"
	"os"

	"github.com/Luca3317/libsignalcopy/ecc"
	"github.com/Luca3317/libsignalcopy/keys/identity"
	"github.com/Luca3317/libsignalcopy/serialize"
	"github.com/Luca3317/libsignalcopy/state/record"
	"github.com/Luca3317/libsignalcopy/util/keyhelper"
	"golang.org/x/crypto/curve25519"
)

const idspath = "ids.bin"
const prekeypath = "prekey.bin"
const sigprekeypath = "sigprekey.bin"

const idkeypairpath = "idkeypair.bin"
const idkeypubpath = "idkeypub.bin"
const idkeyprivpath = "idkeypriv.bin"

type IDs struct {
	RegID uint32
	DevID uint32
}

func writefile(content []byte, path string) {

	permissions := 0644
	err := ioutil.WriteFile(path, content, fs.FileMode(permissions))

	if err != nil {
		log.Fatalf("FAILED TO WRITE TO FILE %v", path)
		os.Remove(path)
	} else {
		fmt.Printf("\nSUCCESS WRITING TO %v:\n%v\n", path, content)
	}
}

func readfile(content *[]byte, path string) {

	var err error
	*content, err = ioutil.ReadFile(path)

	if err != nil {
		log.Fatalf("FAILED TO READ FROM FILE %v", path)
		*content = nil
	} else {
		fmt.Printf("\nSUCCESS READING FROM FILE %v:\n%v\n", path, *content)
	}
}

func IDsToGOB(id IDs) []byte {
	b := bytes.Buffer{}
	e := gob.NewEncoder(&b)
	err := e.Encode(id)
	if err != nil {
		log.Fatal("failed gob encode ids")
	}

	return b.Bytes()
}

func IDsFromGOB(by []byte) IDs {
	i := IDs{}
	b := bytes.Buffer{}
	b.Write(by)
	d := gob.NewDecoder(&b)
	err := d.Decode(&i)
	if err != nil {
		fmt.Println("failed gob decode ids")
	}

	return i
}

func CreateIdentityKeyPairBase() ([32]byte, [32]byte) {
	random := rand.Reader

	var priv, pub [32]byte

	// generate random data
	_, err := io.ReadFull(random, priv[:])
	if err != nil {
		log.Fatal("failed to generate random data for priv key")
	}

	// Documented at: http://cr.yp.to/ecdh.html
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	curve25519.ScalarBaseMult(&pub, &priv)

	return pub, priv
}

// Recreating identity keypair from serialized values
// mix of generatekeypair (assignments after raw value generation)
// and generate identitykeypair (further assignments to restore structure)
func CreateIdentityKeyPair(pub, priv [32]byte) *identity.KeyPair {

	djbECPub := ecc.NewDjbECPublicKey(pub)
	djbECPriv := ecc.NewDjbECPrivateKey(priv)
	keypair := ecc.NewECKeyPair(djbECPub, djbECPriv)

	publicKey := identity.NewKey(keypair.PublicKey())
	return identity.NewKeyPair(publicKey, keypair.PrivateKey())
}

func InitGOB() {
	gob.Register(IDs{})
}

// change name
type Retrievable struct {
	ids             IDs
	preKey          *record.PreKey
	signedPreKey    *record.SignedPreKey
	identityKeyPair *identity.KeyPair
}

func GenerateRetrievable() *Retrievable {

	rk := &Retrievable{}

	// Write / read ids (works fully)
	if _, err := os.Stat(idspath); errors.Is(err, os.ErrNotExist) {
		rk.ids = IDs{
			RegID: keyhelper.GenerateRegistrationID(),
			DevID: 12,
		}

		writefile(IDsToGOB(rk.ids), idspath)

	} else if err == nil {
		var content []byte
		readfile(&content, idspath)
		rk.ids = IDsFromGOB(content)

	} else {
		log.Fatal("some other error occured when checking for ", idspath)
	}

	// Write / read prekey (works fully)
	if _, err := os.Stat(prekeypath); errors.Is(err, os.ErrNotExist) {
		prekeys, err := keyhelper.GeneratePreKeys(0, 10, serialize.NewJSONSerializer().PreKeyRecord)
		if err != nil {
			log.Fatal("failed to generate prekeys")
		}

		rk.preKey = prekeys[0]
		writefile(rk.preKey.Serialize(), prekeypath)

	} else if err == nil {
		var content []byte
		readfile(&content, prekeypath)
		rk.preKey, err = record.NewPreKeyFromBytes(content, serialize.NewJSONSerializer().PreKeyRecord)
		if err != nil {
			log.Fatal("failed to generate prekey")
		}

	} else {
		log.Fatalf("some other error occured when checking for %v", prekeypath)
	}

	// Write / read id keys (appears to work, but needs testing)
	if _, err := os.Stat(idkeypubpath); errors.Is(err, os.ErrNotExist) {

		var pub, priv [32]byte
		pub, priv = CreateIdentityKeyPairBase()

		writefile(pub[:], idkeypubpath)
		writefile(priv[:], idkeyprivpath)

		rk.identityKeyPair = CreateIdentityKeyPair(pub, priv)
		/*
			identityKeyPair, err = keyhelper.GenerateIdentityKeyPair()
			if err != nil {
				log.Fatal("failed to generate identity keypair")
			}

			idkeypairpub := identityKeyPair.PublicKey().Serialize()
			idkeypairpriv := identityKeyPair.PrivateKey().Serialize()

			writefile(idkeypairpub, idkeypubpath)
			writefile(idkeypairpriv[:], idkeyprivpath)
		*/

	} else if err == nil {
		var pubkey []byte
		readfile(&pubkey, idkeypubpath)

		var privkey []byte
		readfile(&privkey, idkeyprivpath)

		var fixpub, fixpriv [32]byte
		copy(fixpub[:], pubkey)
		copy(fixpriv[:], privkey)

		//		rk.identityKeyPair = CreateIdentityKeyPair(*(*[32]byte)(pubkey), *(*[32]byte)(privkey))

		rk.identityKeyPair = CreateIdentityKeyPair(fixpub, fixpriv)

	} else {
		log.Fatal("some other error occured when checking for ", idkeypubpath)
	}

	// Write / read signed pre key
	if _, err := os.Stat(sigprekeypath); errors.Is(err, os.ErrNotExist) {
		rk.signedPreKey, err = keyhelper.GenerateSignedPreKey(rk.identityKeyPair, 0, serialize.NewJSONSerializer().SignedPreKeyRecord)
		if err != nil {
			log.Fatal("failed to generate pre keys")
		}

		writefile(rk.signedPreKey.Serialize(), sigprekeypath)

	} else if err == nil {
		var content []byte
		readfile(&content, sigprekeypath)
		rk.signedPreKey, err = record.NewSignedPreKeyFromBytes(content, serialize.NewJSONSerializer().SignedPreKeyRecord)
		if err != nil {
			log.Fatal("failed to generate signed pre key from bytes")
		}

	} else {
		log.Fatal("some other error occured when checking for ", sigprekeypath)
	}

	// Print all created keys and ids
	fmt.Printf("\n\n\n")
	fmt.Print("Reg ID: ", rk.ids.RegID, "\n")
	fmt.Print("Dev ID: ", rk.ids.DevID, "\n\n")

	fmt.Print("PreKey: ", rk.preKey.Serialize(), "\n\n")

	fmt.Print("IDKey Public: ", rk.identityKeyPair.PublicKey().Serialize(), "\n")
	fmt.Print("IDKey Private: ", rk.identityKeyPair.PrivateKey().Serialize(), "\n\n")

	fmt.Print("Signed PreKey: ", rk.signedPreKey.Serialize(), "\n")

	return rk
}
