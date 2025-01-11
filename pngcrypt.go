package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"image"
	"image/color"
	"image/png"
	"io"
	"math"
	"os"
)

const (
	saltSize   = 32
	keySize    = 32
	nonceSize  = 12
	iterations = 100000
)

type ImageData struct {
	Raw    []byte
	Width  int
	Height int
}

func imageToBytes(img image.Image) (*ImageData, error) {
	var buf bytes.Buffer
	err := png.Encode(&buf, img)
	if err != nil {
		return nil, err
	}
	bounds := img.Bounds()
	return &ImageData{
		Raw:    buf.Bytes(),
		Width:  bounds.Max.X,
		Height: bounds.Max.Y,
	}, nil
}

func bytesToImage(data []byte) (image.Image, error) {
	return png.Decode(bytes.NewReader(data))
}

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
}

func encryptImage(img image.Image, password string) (image.Image, error) {
	imgData, err := imageToBytes(img)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aead.Seal(nil, nonce, imgData.Raw, nil)

	// Store length + salt + nonce + ciphertext
	dataLen := uint32(len(ciphertext) + saltSize + nonceSize)
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, dataLen)
	combined := append(lenBytes, append(append(salt, nonce...), ciphertext...)...)

	size := int(math.Ceil(math.Sqrt(float64(len(combined)) / 3)))
	noiseImg := image.NewRGBA(image.Rect(0, 0, size, size))

	for i := 0; i < len(combined); i += 3 {
		x := (i / 3) % size
		y := (i / 3) / size
		r := combined[i]
		g := byte(0)
		b := byte(0)
		if i+1 < len(combined) {
			g = combined[i+1]
		}
		if i+2 < len(combined) {
			b = combined[i+2]
		}
		noiseImg.Set(x, y, color.RGBA{r, g, b, 255})
	}

	return noiseImg, nil
}

func decryptImage(noiseImg image.Image, password string) (image.Image, error) {
	bounds := noiseImg.Bounds()
	size := bounds.Max.X
	rawData := make([]byte, size*size*3)

	idx := 0
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			r, g, b, _ := noiseImg.At(x, y).RGBA()
			rawData[idx] = uint8(r >> 8)
			rawData[idx+1] = uint8(g >> 8)
			rawData[idx+2] = uint8(b >> 8)
			idx += 3
		}
	}

	dataLen := binary.BigEndian.Uint32(rawData[:4])
	data := rawData[4:dataLen+4]

	salt := data[:saltSize]
	nonce := data[saltSize : saltSize+nonceSize]
	ciphertext := data[saltSize+nonceSize:]

	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return bytesToImage(plaintext)
}

func main() {
    decrypt := flag.Bool("d", false, "Decrypt mode")
    password := flag.String("p", "", "Password for encryption/decryption")
    flag.Parse()

    if *password == "" {
        fmt.Println("Please provide password with -p")
        flag.PrintDefaults()
        return
    }

    if *decrypt {
        noiseImg, err := png.Decode(os.Stdin)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error decoding encrypted image: %v\n", err)
            return
        }

        decryptedImg, err := decryptImage(noiseImg, *password)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Decryption failed: %v\n", err)
            return
        }

        if err := png.Encode(os.Stdout, decryptedImg); err != nil {
            fmt.Fprintf(os.Stderr, "Error encoding PNG: %v\n", err)
            return
        }
    } else {
        img, err := png.Decode(os.Stdin)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error decoding PNG: %v\n", err)
            return
        }

        encryptedImg, err := encryptImage(img, *password)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Encryption failed: %v\n", err)
            return
        }

        if err := png.Encode(os.Stdout, encryptedImg); err != nil {
            fmt.Fprintf(os.Stderr, "Error encoding encrypted PNG: %v\n", err)
            return
        }
    }
}
