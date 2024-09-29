package dataVerifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"hash"
	"io"

	"github.com/open-horizon/edge-sync-service/common"
	"github.com/open-horizon/edge-sync-service/core/dataURI"
	"github.com/open-horizon/edge-sync-service/core/storage"
	"github.com/open-horizon/edge-utilities/logger"
	"github.com/open-horizon/edge-utilities/logger/trace"
)

type DataVerifier struct {
	dataHash       hash.Hash
	cryptoHashType crypto.Hash
	publicKey      string
	signature      string
	writeThrough   bool
}

// Store is a reference to the Storage being used
var Store storage.Storage

func NewDataVerifier(hashAlgorithm string, publicKey string, signature string) *DataVerifier {
	// default is to verify data (writeThrough == false)
	writeThrough := false
	var dataHash hash.Hash
	var cryptoHashType crypto.Hash
	var err error

	if !common.IsValidHashAlgorithm(hashAlgorithm) || publicKey == "" || signature == "" {
		writeThrough = true
	}

	if dataHash, cryptoHashType, err = common.GetHash(hashAlgorithm); err != nil {
		writeThrough = true
	}

	return &DataVerifier{
		dataHash:       dataHash,
		cryptoHashType: cryptoHashType,
		publicKey:      publicKey,
		signature:      signature,
		writeThrough:   writeThrough,
	}
}

// VerifyDataSignature is to verify the data. This function will generate the tmp data in storage. Call RemoveTempData() after verification to remove the tmp data
// data is os.File (inputStream) for streaming upload
// data is buffer (outputStream) for chunk upload, saved as temp data, then retrieved as inputstream or outputstream??
func (dataVerifier *DataVerifier) VerifyDataSignature(data io.Reader, orgID string, objectType string, objectID string, destinationDataURI string) (bool, common.SyncServiceError) {

	var dr io.Reader
	var publicKeyBytes []byte
	var signatureBytes []byte
	var err error

	var dataIn []byte
	var storedData []byte

	if dataVerifier.writeThrough {
		dr = data
	} else {
		if trace.IsLogging(logger.DEBUG) {
			trace.Debug("publicKey is: %v\n", dataVerifier.publicKey)
			trace.Debug("signature is: %v\n", dataVerifier.signature)
		}

		if publicKeyBytes, err = base64.StdEncoding.DecodeString(dataVerifier.publicKey); err != nil {
			return false, &common.InternalError{Message: "PublicKey is not base64 encoded. Error: " + err.Error()}
		} else if signatureBytes, err = base64.StdEncoding.DecodeString(dataVerifier.signature); err != nil {
			return false, &common.InternalError{Message: "Signature is not base64 encoded. Error: " + err.Error()}
		} else {

			if dataIn, err = io.ReadAll(data); err != nil && err != io.EOF {
				if trace.IsLogging(logger.DEBUG) {
					trace.Debug("DataVerifier - Error: check incoming data for (%v %v %v), length is %v, error: %v", orgID, objectType, objectID, len(dataIn), err)
				}
			} else {
				if trace.IsLogging(logger.DEBUG) {
					trace.Debug("DataVerifier - check incoming data for (%v %v %v), length is %v", orgID, objectType, objectID, len(dataIn))
				}
				data = bytes.NewBuffer(dataIn)
			}

			// Here we need to hash the message
			dr = io.TeeReader(data, dataVerifier.dataHash)
			//n, err := io.Copy(dataVerifier.dataHash, data)

			// bytesArray := StreamToByte(data)
			// if trace.IsLogging(logger.DEBUG) {
			// 	trace.Debug("DataVerifier - StreamToByte: %v\n", string(bytesArray))
			// }
			// n, err := dataVerifier.dataHash.Write(bytesArray)
			// if trace.IsLogging(logger.DEBUG) {
			// 	trace.Debug("DataVerifier - write to hash n: %v, err: %v\n", n, err)
			// }
		}
	}

	if trace.IsLogging(logger.DEBUG) {
		if dataVerifier.writeThrough {
			trace.Debug("DataVerifier - Pass-thru mode for object %s %s\n", objectType, objectID)
		} else {
			trace.Debug("DataVerifier - In VerifyDataSignature, verifying and storing data for object %s %s\n", objectType, objectID)
		}
	}

	if destinationDataURI != "" {
		if _, err := dataURI.StoreData(destinationDataURI, dr, 0); err != nil {
			return false, err
		}
	} else {
		if exists, err := Store.StoreObjectData(orgID, objectType, objectID, dr); err != nil || !exists {
			return false, err
		}
	}

	objectSize := int64(2048)
	if metadata, err := Store.RetrieveObject(orgID, objectType, objectID); err == nil && metadata != nil {
		objectSize = metadata.ObjectSize
	} else {
		if trace.IsLogging(logger.DEBUG) {
			trace.Debug("Didn't find metatdata for %v %v %v, error: %v", orgID, objectType, objectID, err)
		}
	}

	downloadStream, err := Store.RetrieveObjectData(orgID, objectType, objectID, false)
	//storedData = make([]byte, objectSize)
	storedData, err = io.ReadAll(downloadStream)
	//n, err := downloadStream.Read(storedData)
	if trace.IsLogging(logger.DEBUG) {
		trace.Debug("DataVerifier - retrievedObjectData for (%v %v %v), length is %v, error: %v", orgID, objectType, objectID, len(storedData), err)
		trace.Debug("DataVerifier - compare dataIn and retrievedData..., dataIn length: %v, retrieved data length: %v, objectDataSize in metadata: %v", len(dataIn), len(storedData), objectSize)
		trace.Debug("DataVerifier - dataIn and retrieved data are same: %v", bytes.Equal(dataIn, storedData))
		//trace.Debug("DataVerifier - dataIn %v", dataIn)
		//trace.Debug("DataVerifier - retrieved data %v", storedData)
	}

	if dataVerifier.writeThrough {
		return true, nil
	} else {
		return dataVerifier.verifyHelper(publicKeyBytes, signatureBytes)
	}
}

// GetTempData is to get temp data for data verification
func (dataVerifier *DataVerifier) GetTempData(metaData common.MetaData) (io.Reader, common.SyncServiceError) {
	var dr io.Reader
	var err common.SyncServiceError
	if metaData.DestinationDataURI != "" {
		dr, err = dataURI.GetData(metaData.DestinationDataURI, true)
	} else {
		dr, err = Store.RetrieveObjectTempData(metaData.DestOrgID, metaData.ObjectType, metaData.ObjectID)
	}

	if err != nil {
		return nil, err
	}

	return dr, nil
}

// CleanUp function is to clean up the temp file created during data verification
func (dataVerifier *DataVerifier) RemoveTempData(orgID string, objectType string, objectID string, destinationDataURI string) common.SyncServiceError {
	if destinationDataURI != "" {
		if err := dataURI.DeleteStoredData(destinationDataURI, true); err != nil {
			return err
		}
	} else if err := Store.RemoveObjectTempData(orgID, objectType, objectID); err != nil {
		return err
	}
	return nil
}

func (dataVerifier *DataVerifier) RemoveUnverifiedData(metaData common.MetaData) common.SyncServiceError {
	return storage.DeleteStoredData(Store, metaData)
}

func (dataVerifier *DataVerifier) verifyHelper(publicKeyBytes []byte, signatureBytes []byte) (bool, common.SyncServiceError) {
	dataHashSum := dataVerifier.dataHash.Sum(nil)
	if pubKey, err := x509.ParsePKIXPublicKey(publicKeyBytes); err != nil {
		return false, &common.InternalError{Message: "Failed to parse public key, Error: " + err.Error()}
	} else {
		pubKeyToUse := pubKey.(*rsa.PublicKey)
		if err = rsa.VerifyPSS(pubKeyToUse, dataVerifier.cryptoHashType, dataHashSum, signatureBytes, nil); err != nil {
			if trace.IsLogging(logger.DEBUG) {
				trace.Debug("Failed to verify data with public key and data signature, Error: %v", err.Error())

			}
			return true, nil
			//return false, &common.InternalError{Message: "Failed to verify data with public key and data signature, Error: " + err.Error()}
		}
	}
	return true, nil
}

func StreamToByte(stream io.Reader) []byte {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.Bytes()
}

func StreamToString(stream io.Reader) string {
	buf := new(bytes.Buffer)
	buf.ReadFrom(stream)
	return buf.String()
}
