package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// Struct to hold metadata for each file
type FileMetadata struct {
	OriginalName string `json:"original_name"`
	Timestamp    string `json:"timestamp"`
	Hash         string `json:"hash"`
}

const metadataSeparator = "--METADATA_END--"

// DeriveKey generates a secure encryption key from password and salt using Argon2
func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32) // 1 iteration, 64MB memory, 4 threads, 32-byte key
}

// Computes SHA-256 hash for a large file in chunks
func calculateFileHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	buffer := make([]byte, 64*1024) // 64 KB buffer

	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return "", err
		}
		if n == 0 {
			break
		}
		if _, err := hasher.Write(buffer[:n]); err != nil {
			return "", err
		}
	}

	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}




// EncryptFile encrypts the contents of a file with metadata and saves it
func encryptFile(filePath string, key []byte) error {
	fmt.Printf("Encrypting %s \n", filepath.Base(filePath))

	originalHash, err := calculateFileHash(filePath)
	if err != nil {
		return err
	}

	fmt.Println("Original Hash - "+originalHash)

	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	outputFile, err := os.Create(filePath+".enc")
	if err != nil {
		return err
	}
	defer outputFile.Close()


	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	//fmt.Println(nonce)
	//fmt.Println(len(nonce))

	// Write nonce to the file
	if _, err := outputFile.Write(nonce); err != nil {
		return err
	}

	// Metadata including the original filename and timestamp
	metadata := FileMetadata{
		OriginalName: filepath.Base(filePath),
		Timestamp:    time.Now().Format(time.RFC3339),
		Hash:         originalHash, //fmt.Sprintf("%x", originalHash),
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	// Combine metadata and file content
	combinedData := append(metadataJSON, []byte(metadataSeparator)...)

	//fmt.Println("com length ", len(combinedData))

	//fmt.Println("com ", combinedData)

	meta := make([]byte, 1024)
	copy(meta[:], combinedData)

	//fmt.Println("meta 1 length ", len(meta))

	//fmt.Println("data", meta)

	metaEncrypted := gcm.Seal(nil, nonce, meta, nil)

	//fmt.Println("encrypt len ",len(metaEncrypted))

	//fmt.Println("encrypt data ", metaEncrypted)

	if _, err := outputFile.Write(metaEncrypted); err != nil {
		return err
	}

	// Encrypt and write the file in chunks, updating HMAC as we go
	buffer := make([]byte, 64*1024) // 64 KB chunks
	for {
		n, err := file.Read(buffer)
		//fmt.Println("n",n)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}

		// Generate a unique nonce for each chunk
		nonce := make([]byte, gcm.NonceSize())
		if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
			return err
		}
		//fmt.Println("buffer", buffer[:n])
		chunk := gcm.Seal(nil, nonce, buffer[:n], nil)
		//fmt.Println("chunk", chunk)
		
		if _, err := outputFile.Write(nonce); err != nil {
			return err
		}
		
		if _, err := outputFile.Write(chunk); err != nil {
			return err
		}
	}

		//fmt.Println("HMAC - ", mac.Sum(nil))
		err = os.Remove(filePath)
		if err != nil {
			fmt.Println("Error while removing source file:", err)
					return err
		}

	// ciphertext := gcm.Seal(nonce, nonce, combinedData, nil)

	// err = os.WriteFile(filePath+".enc", ciphertext, 0644)
		
	return nil
}

// DecryptFile decrypts an encrypted file, checks integrity, and restores content
func decryptFile(filePath string, key []byte) error {
	fmt.Printf("Decrypting %s \n", filepath.Base(filePath))

	// Open the encrypted file for reading
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Get file size to isolate the HMAC (last 32 bytes)
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	fileSize := fileInfo.Size()
	if fileSize < 48 { // Minimum size for encrypted metadata, separator, and HMAC
		return errors.New("file too small to be valid")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	
	nonceSize := gcm.NonceSize()
	metadataAndNonceSize := nonceSize + 1040 // Adjust 512 based on expected metadata size

	//fmt.Println(metadataAndNonceSize)

	// Read nonce and encrypted metadata
	header := make([]byte, metadataAndNonceSize)
	if _, err := file.Read(header); err != nil {
		return err
	}
	// fmt.Println(header)

	nonce := header[:nonceSize]
	encryptedMetadata := header[nonceSize:]

	//fmt.Println("nonce", nonce)
	//fmt.Println(len(encryptedMetadata))
	//fmt.Println("encrypt data ", encryptedMetadata)
	

	// Decrypt metadata
	metadataDecrypted, err := gcm.Open(nil, nonce, encryptedMetadata, nil)
	if err != nil {
		fmt.Println(err.Error())
		return errors.New("failed to decrypt metadata")
	}

	//fmt.Println("data", metadataDecrypted)

	//fmt.Println("sep", []byte(metadataSeparator))

	// Locate separator to extract metadata JSON
	sepIndex := findSeparatorIndex(metadataDecrypted, []byte(metadataSeparator))
	if sepIndex == -1 {
		return errors.New("invalid metadata format")
	}
	var metadata FileMetadata
	if err := json.Unmarshal(metadataDecrypted[:sepIndex], &metadata); err != nil {
		return errors.New("failed to parse metadata")
	}

	//fmt.Println("Metadata - ", metadata)

	// Create output file for decrypted content
	outputFilePath := filepath.Dir(filePath) + "/" + metadata.OriginalName
	outputFile, err := os.Create(outputFilePath)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	// Prepare HMAC validation
	contentOffset := int64(nonceSize+1040)
	file.Seek(contentOffset, io.SeekStart)

	// Decrypt the file in chunks and verify HMAC
	buffer := make([]byte, 64*1024 + gcm.Overhead()) // 64 KB buffer
	for {
		
		nonce := make([]byte, gcm.NonceSize())
		if _, err := file.Read(nonce); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		n, err := file.Read(buffer)
		//fmt.Println("n = ", n)
		//fmt.Println("buf", buffer[:n])

		if n > 0 {
			//fmt.Println("buf", buffer[:n])
			// Decrypt each chunk
			decryptedChunk, err := gcm.Open(nil, nonce, buffer[:n], nil)
			if err != nil {
				fmt.Println(err)
				return errors.New("decryption failed")
			}
			//fmt.Println("decryptedChunk", decryptedChunk)

			// Write decrypted data to output file and update HMAC
			if _, err = outputFile.Write(decryptedChunk); err != nil {
				fmt.Println(err)
				return err
			}
		}
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}
	}

	calculatedHash, err := calculateFileHash(outputFilePath)
	if err != nil {
		return err
	}
	//fmt.Println("hash", calculatedHash)
	//fmt.Println("metahash", metadata.Hash)
	if calculatedHash != metadata.Hash {
		return errors.New("File hash check failed - Maybe tampered - Use with caution")
	}

	// Remove the encrypted file if decryption and integrity check succeed
	err = os.Remove(filePath)
	if err != nil {
		return fmt.Errorf("error while removing encrypted file: %v", err)
	}
	return nil
}


// Utility function to locate the metadata separator
func findSeparatorIndex(data, sep []byte) int {
	for i := 0; i <= len(data)-len(sep); i++ {
		if string(data[i:i+len(sep)]) == string(sep) {
			return i
		}
	}
	return -1 // Separator not found
}

// ProcessFolder recursively encrypts/decrypts files in a folder
func processFolder(sourceFolderPath string, key []byte, encrypt bool) error {
	return filepath.Walk(sourceFolderPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if encrypt {
			if filepath.Ext(path) != ".enc" {
				err = encryptFile(path, key)
				if err != nil {
					fmt.Printf("Error in Encryption : %s \n", err)
				}
			}
		} else {
			if filepath.Ext(path) == ".enc" {
				err = decryptFile(path, key)
				if err != nil {
					fmt.Printf("Error in decryption : %s \n", err)
				}
			}
		}
		return nil
	})
}

// PromptPasswordSalt hides password input and collects password & salt
func promptPasswordSalt() ([]byte, []byte, error) {
	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, nil, err
	}

	fmt.Print("Enter salt: ")
	saltBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, nil, err
	}

	if len(passwordBytes) == 0 || len(saltBytes) == 0 {
		return nil, nil, errors.New("password and salt cannot be empty")
	}

	return passwordBytes, saltBytes, nil
}

func main() {
	var sourcePath string
	var choice string

	args := os.Args[1:]

	if len(args) >= 1 && ( args[0] == "e" || args[0] == "d" ) {
		choice = args[0]
	} else {
		fmt.Print("Enter (e)ncrypt or (d)ecrypt: ")
		fmt.Scanln(&choice)
	}
	if choice != "e" && choice != "d" {
		fmt.Print("Wrong option - Please run again and enter e or d")
		return
	}

	if len(args) >= 2 {
		sourcePath = args[1]
	} else {
		fmt.Print("Enter a file or folder path: ")
		fmt.Scanln(&sourcePath)
	}

	password, salt, err := promptPasswordSalt()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	key := deriveKey(password, salt)

	switch choice {
	case "e":
		err = processFolder(sourcePath, key, true)
	case "d":
		err = processFolder(sourcePath, key, false)
	default:
		fmt.Println("Invalid choice")
		return
	}

	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Println("Operation completed successfully.")
	}
}
