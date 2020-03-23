/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package plugins

import (
	//	"fmt"
	clog "intel/isecl/lib/common/log"
	//"intel/isecl/sgx-attestation-hub/resource"
)

var log = clog.GetDefaultLogger()

type Kubernetes struct{}

func Pushdata(p1 resource.PublishData, p2 resource.Plugin) {
	log.Info("data: ", p1)
	log.Info("plugin: ", p2)
}
