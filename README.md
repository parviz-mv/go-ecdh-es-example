# Go crypto ECDH-ES example of generate key pair and get shared key
Demo example of using go `ECDH-ES` with EC key types:  `P-256, P-384 and P-521` and OKP key type : `X25519` for generate key pair and get shared key.

## Installation

Before start you need to clone this repository:
```shell
git clone git@github.com:parviz-mv/go-ecdh-es-example.git
```
## Usage

For run example in root directory of the cloned repository in terminal run this command :

```go 
go run .
```
Also, you can run with special curve :

```go 
go run . -curve P-256  // variants: P-256, P-384 , P-521 and X25519
```
