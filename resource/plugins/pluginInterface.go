/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package plugins

import (
	//"intel/isecl/sgx-attestation-hub/resource"
	"intel/isecl/sgx-attestation-hub/types"
)

type PluginType interface {

	// Methods
	Pushdata(p1 types.PublishData, p2 types.Plugin)
}