// SGX HUB
//
// SGX Hub is responsible for getting host’s platform details from SGX Host Verification Service (SHVS) and pushing the details to orchestrator.
// SGX Hub uses the node SGX information obtained from SHVS to update the OpenStack (custom traits) or K8S (CRDs) orchestrators.
// SGX Hub registers the tenant and maintains mapping of tenantID and hardwareUUID. SGX Hub listening port is user-configurable.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 1.0
//  Host: sgx-ah.com:14000
//  BasePath: /sgx-ah/v1
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package docs
