/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	csetup "intel/isecl/lib/common/v3/setup"
	"intel/isecl/shub/constants"

	"github.com/pkg/errors"
	"os"
)

type CreateEncryptionKey struct {
	Flags []string
}

// ValidateCreateKey method is used to check if the keyPair exists on disk
func (ek CreateEncryptionKey) Validate(c csetup.Context) error {
	log.Trace("tasks/create_encryption_keypair: Validate() Entering")
	defer log.Trace("tasks/create_encryption_keypair: Validate() Leaving")

	_, err := os.Stat(constants.PrivatekeyLocation)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/create_encryption_keypair: Validate() Private key does not exist")
	}

	_, err = os.Stat(constants.PublickeyLocation)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/create_encryption_keypair: Validate() Public key does not exist")
	}
	return nil
}

func (ek CreateEncryptionKey) Run(c csetup.Context) error {
	log.Trace("tasks/create_encryption_keypair: Run() Entering")
	defer log.Trace("tasks/create_encryption_keypair: Run() Leaving")

	fs := flag.NewFlagSet("ca", flag.ContinueOnError)
	force := fs.Bool("force", false, "force recreation, will overwrite any existing key-pair Keys")

	err := fs.Parse(ek.Flags)
	if err != nil {
		fmt.Println("CA certificate setup: Unable to parse flags")
		return fmt.Errorf("tasks/create_encryption_keypair: Run() CA certificate setup: Unable to parse flags")
	}

	if *force || ek.Validate(c) != nil {
		log.Info("tasks/create_encryption_keypair: Run() Creating key-pair")

		bitSize := constants.DefaultKeyAlgorithmLength
		keyPair, err := rsa.GenerateKey(rand.Reader, bitSize)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while generating new RSA key pair")
			return errors.Wrap(err, "tasks/create_encryption_keypair: Run() Error while generating a new RSA key pair")
		}

		privBytes, err := x509.MarshalPKCS8PrivateKey(keyPair)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while marshaling private key")
			return errors.Wrap(err, "tasks/create_encryption_keypair: Run() Error while generating a new RSA key pair")
		}

		privateKeyFile, err := os.Create(constants.PrivatekeyLocation)
		if err != nil {
			fmt.Fprintf(os.Stderr, "I/O error while saving private key file")
			return errors.Wrap(err, "tasks/create_encryption_keypair: Run() I/O error while saving private key file")
		}
		defer privateKeyFile.Close()
		_, err = privateKeyFile.Write(privBytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "I/O error while encoding private key file")
			return errors.Wrap(err, "tasks/create_encryption_keypair: Run() Error while encoding the private key.")
		}

		// save public key
		publicKey := &keyPair.PublicKey

		pubkeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "I/O error while encoding private key file")
			return errors.Wrap(err, "tasks/create_encryption_keypair: Run() Error while marshalling the public key.")
		}
		var publicKeyInPem = &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubkeyBytes,
		}

		publicKeyFile, err := os.Create(constants.PublickeyLocation)
		if err != nil {
			fmt.Fprintf(os.Stderr, "I/O error while encoding public key-pair file")
			return errors.Wrap(err, "tasks/create_encryption_keypair: Run() Error while creating a new file. ")
		}
		defer publicKeyFile.Close()

		err = pem.Encode(publicKeyFile, publicKeyInPem)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error while encoding the public key-pair")
			return errors.Wrap(err, "tasks/create_encryption_keypair: Run() Error while encoding the public key.")
		}
		os.Chmod(constants.PublickeyLocation, 0640)
		os.Chmod(constants.PrivatekeyLocation, 0640)
	}

	return nil
}
