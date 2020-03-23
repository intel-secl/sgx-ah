/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/sgx-attestation-hub/types"

type HostRepository interface {
	Create(types.Host) (*types.Host, error)
	Retrieve(types.Host) (*types.Host, error)
	RetrieveAll(types.Host) (types.Hosts, error)
	Update(types.Host) error
	Delete(types.Host) error
	//RetrieveActiveHost(types.Host) (*types.Host, error)
}
