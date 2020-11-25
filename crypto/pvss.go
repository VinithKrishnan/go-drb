package crypto

import (
	"fmt"
	// "math"
	"math/big"
	"errors"
	"strconv"
	"bytes"
	"unsafe"
	"crypto/sha512"
	"reflect"
	"ed25519"
)

func hello() (ed25519.Point) {
	return ed25519.Point_one()
}

