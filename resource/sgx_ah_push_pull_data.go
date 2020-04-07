package resource

import (
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/sgx-attestation-hub/config"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/types"
	"net/http"
	"strconv"
)

type HostPlaformData struct {
	Id           string `json:"host_id" gorm:"type:uuid;unique;primary_key;"`
	SGXSupported bool   `json:"sgx_supported"`
	SGXEnabled   bool   `json:"sgx_enabled"`
	FLCEnabled   bool   `json:"flc_enabled"`
	EPCSize      string `json:"epc_size"`
	TCBUpToDate  bool   `json:"tcb_upToDate"`
}

type HostPlaformDataArray []HostPlaformData

type HostBasicInfo struct {
	Id            string `json:"host_id" gorm:"type:uuid;unique;primary_key;"`
	HostName      string `json:"host_name"`
	ConnectionURL string `json:"connection_string"`
	HardwareUUID  string `json:"uuid" gorm:"type:uuid;unique"`
}

type HostBasicInfoArray []HostBasicInfo

func FetchAllHostsFromHVS(sahDB repository.SAHDatabase) error {

	conf := config.Global()

	if conf == nil {
		return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: Failed to Load configuratoin"))
	}

	getSahUrl := conf.ShvsBaseUrl + "hosts"
	bearerToken := conf.BearerToken
	var resp, err = GetApi("GET", getSahUrl, bearerToken)

	if resp == nil {
		return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: nil response recieved"))
	} else if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: Invalid status code received:%d", resp.StatusCode))
	} else if err != nil {
		return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: Error :", err))
	}

	var hvsResponse HostBasicInfoArray
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&hvsResponse)
	log.Debug("FetchAllHostsFromHVS: Error: ", err)
	numberOfHosts := len(hvsResponse)
	log.Debug("FetchAllHostsFromHVS: Total Number of Hosts: ", numberOfHosts)

	if numberOfHosts <= 0 {
		return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: Number of host:%d", numberOfHosts))
	}

	for i := 0; i < numberOfHosts; i++ {
		url := conf.ShvsBaseUrl + "platform-data?HostName=" + hvsResponse[i].HostName
		response, err := GetApi("GET", url, bearerToken)
		if response == nil {
			return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: nil response"))
		} else if err != nil {
			return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: Error :", err))
		}

		var platformDataResp HostPlaformDataArray
		dec := json.NewDecoder(response.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&platformDataResp)
		log.Debug("FetchAllHostsFromHVS: Number of platform data fetched id ", len(platformDataResp))
		if len(platformDataResp) <= 0 {
			return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: Error Platform data fetched is : %d", len(platformDataResp)))
		}

		host := types.Host{
			Id:            hvsResponse[i].Id,
			HostName:      hvsResponse[i].HostName,
			ConnectionURL: hvsResponse[i].ConnectionURL,
			HardwareUUID:  hvsResponse[i].HardwareUUID,
			SGXSupported:  platformDataResp[0].SGXSupported,
			SGXEnabled:    platformDataResp[0].SGXEnabled,
			FLCEnabled:    platformDataResp[0].FLCEnabled,
			EPCSize:       platformDataResp[0].EPCSize,
			TCBUpToDate:   platformDataResp[0].TCBUpToDate,
		}

		if sahDB == nil {
			return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: Error: sahDB", sahDB))
		}

		_, dbErr := sahDB.HostRepository().Create(host)

		if dbErr != nil {
			return errors.New(fmt.Sprintf("FetchAllHostsFromHVS: Error: ", dbErr, host))
		}
	}
	return err
}

func FetchHostRegisteredInLastFewMinutes(sahDB repository.SAHDatabase, hostRefreshTimeInMinutes int) error {

	//Below code to fetch all host in last  minutes(hostRefreshTimeInMinutes)
	conf := config.Global()

	if conf == nil {
		return errors.New(fmt.Sprintf("FetchHostRegisteredInLastFewMinutes: Unable to load conf:", conf))
	}

	getSahUrl := conf.ShvsBaseUrl + "platform-data?numberOfMinutes=" + strconv.Itoa(hostRefreshTimeInMinutes)
	bearerToken := conf.BearerToken
	var resp, err = GetApi("GET", getSahUrl, bearerToken)

	if resp == nil || err != nil {
		return errors.New(fmt.Sprintf("FetchHostRegisteredInLastFewMinutes: Error: ", err, " response: ", resp))
	} else if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("FetchHostRegisteredInLastFewMinutes: Invalid status code received:%d", resp.StatusCode))
	}
	// here we are converting Http response in struct
	var hostPlatformData HostPlaformDataArray
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&hostPlatformData)

	numberOfHostsUpdated := len(hostPlatformData)
	if numberOfHostsUpdated == 0 {
		return errors.New(fmt.Sprintf("FetchHostRegisteredInLastFewMinutes: Number of host: %d", numberOfHostsUpdated))
	}
	// below code to fetch platform data for each host
	for i := 0; i < 1; i++ { // numberOfHostsUpdated; i++ {
		getSahUrl = conf.ShvsBaseUrl + "hosts/" + hostPlatformData[0].Id
		response, err := GetApi("GET", getSahUrl, bearerToken)
		if err != nil {
			log.Error("FetchHostRegisteredInLastFewMinutes: ", err)
		}
		// here we are converting Http response in struct
		var hvsResponseForHostId HostBasicInfo
		dec := json.NewDecoder(response.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&hvsResponseForHostId)

		host := types.Host{
			HostName: hvsResponseForHostId.HostName,
		}
		// retrieve Data from database to check whether host is present in Database
		if sahDB == nil {
			log.Error("FetchHostRegisteredInLastFewMinutes: Error: sahDB", sahDB)
		}

		existingHost, retrivalError := sahDB.HostRepository().RetrieveAll(host)
		if retrivalError != nil && len(existingHost) < 1 {
			log.Error("FetchHostRegisteredInLastFewMinutes: Host does not Exist in database so we are going to create Host in database and got error while retrieving data from database: ", retrivalError)
		}

		// if host is not present in database then if will be executed and  new entry will created in Database
		// else part will be executed if host is already present then we will update the database
		if existingHost == nil || len(existingHost) < 1 {
			host = types.Host{
				Id:            hostPlatformData[i].Id,
				HostName:      hvsResponseForHostId.HostName,
				ConnectionURL: hvsResponseForHostId.ConnectionURL,
				HardwareUUID:  hvsResponseForHostId.HardwareUUID,
				SGXSupported:  hostPlatformData[i].SGXSupported,
				SGXEnabled:    hostPlatformData[i].SGXEnabled,
				FLCEnabled:    hostPlatformData[i].FLCEnabled,
				EPCSize:       hostPlatformData[i].EPCSize,
				TCBUpToDate:   hostPlatformData[i].TCBUpToDate,
			}

			_, err := sahDB.HostRepository().Create(host)

			if err != nil {
				log.Error("FetchHostRegisteredInLastFewMinutes: Failed to create Host:", err)
			} else {
				log.Info("FetchHostRegisteredInLastFewMinutes: Successfully created Host in DB")
			}
		} else {
			numberOfHostsWithSameHostName := len(existingHost)
			log.Debug("Number of host exists in DB: ", numberOfHostsWithSameHostName)
			for j := 0; j < numberOfHostsWithSameHostName; j++ {
				host = types.Host{
					Id:            existingHost[j].Id,
					HostName:      hvsResponseForHostId.HostName,
					ConnectionURL: hvsResponseForHostId.ConnectionURL,
					HardwareUUID:  existingHost[j].HardwareUUID,
					SGXSupported:  hostPlatformData[i].SGXSupported,
					SGXEnabled:    hostPlatformData[i].SGXEnabled,
					FLCEnabled:    hostPlatformData[i].FLCEnabled,
					EPCSize:       hostPlatformData[i].EPCSize,
					TCBUpToDate:   hostPlatformData[i].TCBUpToDate,
				}
				updated_host := sahDB.HostRepository().Update(host)
				if updated_host == nil {
					log.Info("FetchHostRegisteredInLastFewMinutes: Updated database successfully")
				}
			}
		}
	}
	return nil
}
