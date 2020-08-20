/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/shub/types"

type TenantPluginCredentialRepository interface {
	Create(types.TenantPluginCredential) (*types.TenantPluginCredential, error)
	Retrieve(types.TenantPluginCredential) (*types.TenantPluginCredential, error)
	RetrieveAll(types.TenantPluginCredential) (types.TenantPluginCredentials, error)
	RetrieveByTenantId(string) (types.TenantPluginCredentials, error)
	Update(types.TenantPluginCredential) error
	Delete(types.TenantPluginCredential) error
}
