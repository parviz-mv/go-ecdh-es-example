package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
)

const (
	P256   string = "P-256"
	P384   string = "P-384"
	P521   string = "P-521"
	X25519 string = "X25519"
)

var curve ecdh.Curve

type EcdhKeyPair struct {
	Curve      string `json:"curve"`
	PublicKey  []byte `json:"publicKey"`
	PrivateKey []byte `json:"privateKey"`
}

//---Request types-----
type Request interface {
	string | EcdhKeyPair | []byte
}
type requestMessage[T Request] struct {
	Payload T `json:"payload"`
}

//---Response types-----
type Response interface {
	*EcdhKeyPair | string | []byte
}

type responseMessage[T Response] struct {
	Payload T      `json:"payload"`
	Error   string `json:"error"`
}

func (s *responseMessage[T]) Marshall() []byte {
	b, _ := json.Marshal(s)
	return b
}
func parseRequest[T Request](data []byte) (*requestMessage[T], error) {
	var request requestMessage[T]
	if len(data) == 0 {
		return nil, errors.New(fmt.Sprintln("Data is empty!"))
	}
	if err := json.Unmarshal(data, &request); err != nil {
		return nil, err
	}
	return &request, nil
}
func (s EcdhKeyPair) Marshall() []byte {
	b, _ := json.Marshal(s)
	return b
}
func main() {
	runExample()
}

// P256  public 65 (64), private 32, shared 32, encrypted cek 40
// P384  public 97 (96), private 48, shared 48, encrypted cek not working
// P521  public 133 (132), private 66, shared 66 , encrypted cek not working
// X25519  public 32 , private 32, shared 32, encrypted cek 40

func GenerateKeyPair(data []byte) []byte {
	keyPair, err := func() (keyPair *EcdhKeyPair, err error) {
		var changedPablic []byte
		parse, err := parseRequest[string](data)
		if err != nil {
			return nil, err
		}
		curve, err := checkCurve(parse.Payload)
		if err != nil {
			return nil, err
		}
		privateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		publicKey, err := curve.NewPublicKey(privateKey.PublicKey().Bytes())
		if err != nil {
			return nil, err
		}

		if parse.Payload != X25519 {
			changedPablic = publicKey.Bytes()[1:len(publicKey.Bytes())]
		} else {
			changedPablic = publicKey.Bytes()
		}

		return &EcdhKeyPair{
			Curve:      parse.Payload,
			PublicKey:  changedPablic,
			PrivateKey: privateKey.Bytes(),
		}, nil
	}()

	if err != nil {
		response := responseMessage[string]{Payload: "", Error: err.Error()}
		return response.Marshall()
	}
	response := responseMessage[*EcdhKeyPair]{Payload: keyPair, Error: ""}
	return response.Marshall()
}
func GetSharedKey(data []byte) []byte {
	sk, err := func() (sh []byte, err error) {
		var changedPablic []byte
		dataParse, err := parseRequest[EcdhKeyPair](data)
		if err != nil {
			return nil, err
		}
		curve, err := checkCurve(dataParse.Payload.Curve)
		if err != nil {
			return nil, err
		}
		if dataParse.Payload.Curve != X25519 {
			changedPablic = append([]byte{4}, dataParse.Payload.PublicKey...)
		} else {
			changedPablic = dataParse.Payload.PublicKey
		}
		newPrivateKey, err := curve.NewPrivateKey(dataParse.Payload.PrivateKey)
		if err != nil {
			return nil, err
		}
		newPublicKey, err := curve.NewPublicKey(changedPablic)
		if err != nil {
			return nil, err
		}
		sk, err := newPrivateKey.ECDH(newPublicKey)
		if err != nil {
			return nil, err
		}
		return sk, nil
	}()
	if err != nil {
		response := responseMessage[string]{Payload: "", Error: err.Error()}
		return response.Marshall()
	}
	response := responseMessage[[]byte]{Payload: sk, Error: ""}
	return response.Marshall()
}
func checkCurve(curvName string) (ecdh.Curve, error) {
	if curvName == "" {
		return nil, errors.New(fmt.Sprintln("Curv name is empty!"))
	}
	switch curvName {
	case P256:
		curve = ecdh.P256()
	case P384:
		curve = ecdh.P384()
	case P521:
		curve = ecdh.P521()
	case X25519:
		curve = ecdh.X25519()
	default:
		str := fmt.Sprintf("Unsupported curv name: %s", curvName)
		return nil, errors.New(str)
	}
	return curve, nil
}
func runExample() {
	fmt.Println("===================Generate KeyPair=======================")
	curve := flag.String("curve", "X25519", "curve for generate keyPair and getSharedKey") //P384 P521 X25519 P256
	flag.Parse()
	curveName:= *curve
	req := responseMessage[string]{Payload: curveName, Error: ""}
	aliceKeyPairByte := GenerateKeyPair(req.Marshall())
	aliceKeyPairParse, err := parseRequest[EcdhKeyPair](aliceKeyPairByte)
	if err != nil {
		panic(err)
	}
	fmt.Println("Curve for generate key pair is:", aliceKeyPairParse.Payload.Curve)
	fmt.Println("----------------------------------------------------------")

	apub:=fmt.Sprint("Alice public key : ", aliceKeyPairParse.Payload.PublicKey, ", key length : ",len(aliceKeyPairParse.Payload.PublicKey))
	fmt.Println(apub)
	fmt.Println("----------------------------------------------------------")

	apriv:=fmt.Sprint("Alice private key : ", aliceKeyPairParse.Payload.PrivateKey, ", key length : ",len(aliceKeyPairParse.Payload.PrivateKey))
	fmt.Println(apriv)
    
	bobKeyPairByte := GenerateKeyPair(req.Marshall())
	bobKeyPairParse, err := parseRequest[EcdhKeyPair](bobKeyPairByte)
	if err != nil {
		panic(err)
	}
	fmt.Println("----------------------------------------------------------")


	bpub:=fmt.Sprint("Bob public key : ", bobKeyPairParse.Payload.PublicKey, ", key length : ",len(bobKeyPairParse.Payload.PublicKey))
	fmt.Println(bpub)
	fmt.Println("----------------------------------------------------------")

	bpriv:=fmt.Sprint("Bob private key : ", bobKeyPairParse.Payload.PrivateKey, ", key length : ",len(bobKeyPairParse.Payload.PrivateKey))
	fmt.Println(bpriv)
	
	dataForAliceSK := &EcdhKeyPair{
		Curve:      curveName,
		PublicKey:  bobKeyPairParse.Payload.PublicKey,
		PrivateKey: aliceKeyPairParse.Payload.PrivateKey,
	}
	res := responseMessage[*EcdhKeyPair]{Payload: dataForAliceSK, Error: ""}
	aliceShKeyResult := GetSharedKey(res.Marshall())

	var aliceShKeyParse responseMessage[[]byte]
	err = json.Unmarshal(aliceShKeyResult, &aliceShKeyParse)
	if err != nil {
		panic(err)
	}
	fmt.Println("----------------------------------------------------------")

	ask:=fmt.Sprint("Alice shared key : ", aliceShKeyParse.Payload, ", key length : ",len(aliceShKeyParse.Payload))
	fmt.Println(ask)

	dataForBobSK := &EcdhKeyPair{
		Curve:      curveName,
		PublicKey:  aliceKeyPairParse.Payload.PublicKey,
		PrivateKey: bobKeyPairParse.Payload.PrivateKey,
	}
	res2 := responseMessage[*EcdhKeyPair]{Payload: dataForBobSK, Error: ""}
	bobShKeyResult := GetSharedKey(res2.Marshall())

	var bobShKeyParse responseMessage[[]byte]
	err = json.Unmarshal(bobShKeyResult, &bobShKeyParse)
	if err != nil {
		panic(err)
	}
	fmt.Println("----------------------------------------------------------")

	bsk:=fmt.Sprint("Bob shared key : ", bobShKeyParse.Payload, ", key length : ",len(bobShKeyParse.Payload))
	fmt.Println(bsk)
	fmt.Println("----------------------------------------------------------")
}
