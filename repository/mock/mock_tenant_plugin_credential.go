/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/sgx-attestation-hub/types"
)

type MockTenantPluginCredentialRepository struct {
	CreateFunc      func(types.TenantPluginCredential) (*types.TenantPluginCredential, error)
	RetrieveFunc    func(types.TenantPluginCredential) (*types.TenantPluginCredential, error)
	RetrieveAllFunc func(types.TenantPluginCredential) (types.TenantPluginCredentials, error)
	UpdateFunc      func(types.TenantPluginCredential) error
	DeleteFunc      func(types.TenantPluginCredential) error
}

func (m *MockTenantPluginCredentialRepository) Create(p types.TenantPluginCredential) (*types.TenantPluginCredential, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(p)
	}
	return nil, nil
}

func (m *MockTenantPluginCredentialRepository) Retrieve(p types.TenantPluginCredential) (*types.TenantPluginCredential, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(p)
	}
	return nil, nil
}

func (m *MockTenantPluginCredentialRepository) RetrieveAll(p types.TenantPluginCredential) (types.TenantPluginCredentials, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(p)
	}
	return nil, nil
}

func (m *MockTenantPluginCredentialRepository) Update(p types.TenantPluginCredential) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(p)
	}
	return nil
}

func (m *MockTenantPluginCredentialRepository) Delete(p types.TenantPluginCredential) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(p)
	}
	return nil
}
