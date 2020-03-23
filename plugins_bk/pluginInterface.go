/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package resource

import (
	"intel/isecl/sgx-attestation-hub/resource"
)

type PluginType interface {

	// Methods
	Pushdata(p1 PublishData, p2 Plugin)
}
