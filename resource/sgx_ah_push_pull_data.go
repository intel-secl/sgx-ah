package resource

import (
	"encoding/json"
	"github.com/pkg/errors"
	"intel/isecl/sgx-attestation-hub/config"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/types"
	"net/url"
	"strconv"
	"time"
)

type HostPlatformData struct {
	Id           string `json:"host_id" gorm:"type:uuid;unique;primary_key;"`
	SGXSupported bool   `json:"sgx_supported"`
	SGXEnabled   bool   `json:"sgx_enabled"`
	FLCEnabled   bool   `json:"flc_enabled"`
	EPCSize      string `json:"epc_size"`
	TCBUpToDate  bool   `json:"tcb_upToDate"`
	ValidTo      string `json:"validTo"`
}

type HostPlatformDataArray []HostPlatformData

type HostBasicInfo struct {
	Id            string `json:"host_id" gorm:"type:uuid;unique;primary_key;"`
	HostName      string `json:"host_name"`
	ConnectionURL string `json:"connection_string"`
	HardwareUUID  string `json:"uuid" gorm:"type:uuid;unique"`
}

type HostBasicInfoArray []HostBasicInfo

func FetchAllHostsFromHVS(sahDB repository.SAHDatabase) error {
	log.Trace("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Entering")
	defer log.Trace("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Leaving")

	conf := config.Global()
	if conf == nil {
		return errors.New("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Failed to Load configuration")
	}

	getSHVSUrl := conf.ShvsBaseUrl + "hosts"
	SHVSUrl, parseErr := url.Parse(getSHVSUrl)
	if parseErr != nil {
		return errors.Wrap(parseErr, "resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Configured SHVS URL is malformed")
	}

	resp, err := GetApi("GET", SHVSUrl.String())
	if err != nil {
		return errors.Wrap(err, "resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Error fetching hosts from HVS")
	}

	var hvsResponse HostBasicInfoArray
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&hvsResponse)
	if err != nil {
		return errors.Wrap(err, "resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Error decoding host info response from HVS")
	}

	numberOfHosts := len(hvsResponse)
	log.Debug("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Total Number of Hosts: ", numberOfHosts)
	if numberOfHosts == 0 {
		return errors.New("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() No hosts have been retrieved from HVS")
	}

	for i := 0; i < numberOfHosts; i++ {
		url := conf.ShvsBaseUrl + "platform-data?HostName=" + hvsResponse[i].HostName
		response, err := GetApi("GET", url)
		if err != nil {
			log.WithError(err).Errorf("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Error fetching platform data of the host %s from HVS", hvsResponse[i].HostName)
			continue
		}

		var platformDataResp HostPlatformDataArray
		dec := json.NewDecoder(response.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&platformDataResp)
		if err != nil {
			log.WithError(err).Errorf("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Error decoding platform data response from HVS of host %s", hvsResponse[i].HostName)
			continue
		}

		log.Debug("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Number of platform data fetched id ", len(platformDataResp))
		if len(platformDataResp) == 0 {
			log.Errorf("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() No platform data for the host %s has been retrieved from HVS", hvsResponse[i].HostName)
			continue
		}

		hostByHUUID, _ := sahDB.HostRepository().Retrieve(types.Host{HardwareUUID: hvsResponse[i].HardwareUUID})
		if hostByHUUID != nil {
			host := types.Host{
				Id:            hvsResponse[i].Id,
				HostName:      hvsResponse[i].HostName,
				ConnectionURL: hvsResponse[i].ConnectionURL,
				HardwareUUID:  hostByHUUID.HardwareUUID,
				CreatedTime:   hostByHUUID.CreatedTime,
				UpdatedTime:   time.Now(),
				SGXSupported:  platformDataResp[0].SGXSupported,
				SGXEnabled:    platformDataResp[0].SGXEnabled,
				FLCEnabled:    platformDataResp[0].FLCEnabled,
				EPCSize:       platformDataResp[0].EPCSize,
				TCBUpToDate:   platformDataResp[0].TCBUpToDate,
				ValidTo:       platformDataResp[0].ValidTo,
			}
			err = sahDB.HostRepository().Update(host)
			if err != nil {
				log.WithError(err).Errorf("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Error updating host record of host %s in DB", hvsResponse[i].HostName)
				continue
			}
		} else {
			host := types.Host{
				Id:            hvsResponse[i].Id,
				HostName:      hvsResponse[i].HostName,
				ConnectionURL: hvsResponse[i].ConnectionURL,
				HardwareUUID:  hvsResponse[i].HardwareUUID,
				CreatedTime:   time.Now(),
				UpdatedTime:   time.Now(),
				SGXSupported:  platformDataResp[0].SGXSupported,
				SGXEnabled:    platformDataResp[0].SGXEnabled,
				FLCEnabled:    platformDataResp[0].FLCEnabled,
				EPCSize:       platformDataResp[0].EPCSize,
				TCBUpToDate:   platformDataResp[0].TCBUpToDate,
				ValidTo:       platformDataResp[0].ValidTo,
			}
			_, err = sahDB.HostRepository().Create(host)
			if err != nil {
				log.WithError(err).Errorf("resource/sgx_ah_push_pull_data: FetchAllHostsFromHVS() Error creating host record of host %s in DB", hvsResponse[i].HostName)
				continue
			}
		}
	}
	return err
}

func FetchHostRegisteredInLastFewMinutes(sahDB repository.SAHDatabase, hostRefreshTimeInMinutes int) error {
	log.Trace("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Entering")
	defer log.Trace("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Leaving")

	//Below code to fetch all hosts updated/registered in last few minutes(hostRefreshTimeInMinutes)
	conf := config.Global()
	if conf == nil {
		return errors.New("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Unable to load configuration")
	}

	getSahUrl := conf.ShvsBaseUrl + "platform-data?numberOfMinutes=" + strconv.Itoa(hostRefreshTimeInMinutes)
	resp, err := GetApi("GET", getSahUrl)
	if err != nil {
		return errors.Wrap(err, "resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Error fetching platform data of the hosts updated/registered in last few minutes")
	}

	// here we are converting Http response in struct
	var hostPlatformData HostPlatformDataArray
	dec := json.NewDecoder(resp.Body)
	dec.DisallowUnknownFields()
	err = dec.Decode(&hostPlatformData)
	if err != nil {
		return errors.Wrap(err, "resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Error decoding platform data response from HVS")
	}

	numberOfHostsUpdated := len(hostPlatformData)
	if numberOfHostsUpdated == 0 {
		log.Info("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() No hosts have been updated")
		return nil
	}

	// below code to fetch platform data for each host
	for i := 0; i < numberOfHostsUpdated; i++ {
		getSahUrl = conf.ShvsBaseUrl + "hosts/" + hostPlatformData[i].Id
		response, err := GetApi("GET", getSahUrl)
		if err != nil {
			log.WithError(err).Errorf("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Error fetching host %s updated/registered in last few minutes", hostPlatformData[i].Id)
			continue
		}

		// here we are converting Http response in struct
		var hostInfo HostBasicInfo
		dec := json.NewDecoder(response.Body)
		err = dec.Decode(&hostInfo)
		if err != nil {
			log.WithError(err).Errorf("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Error decoding host info response from HVS for host %s", hostPlatformData[i].Id)
			continue
		}

		host := types.Host{
			HardwareUUID: hostInfo.HardwareUUID,
		}
		existingHost, _ := sahDB.HostRepository().Retrieve(host)

		// if host is not present in database then if will be executed and  new entry will created in Database
		// else part will be executed if host is already present then we will update the database
		if existingHost == nil {
			host = types.Host{
				Id:            hostPlatformData[i].Id,
				HostName:      hostInfo.HostName,
				ConnectionURL: hostInfo.ConnectionURL,
				HardwareUUID:  hostInfo.HardwareUUID,
				CreatedTime:   time.Now(),
				UpdatedTime:   time.Now(),
				SGXSupported:  hostPlatformData[i].SGXSupported,
				SGXEnabled:    hostPlatformData[i].SGXEnabled,
				FLCEnabled:    hostPlatformData[i].FLCEnabled,
				EPCSize:       hostPlatformData[i].EPCSize,
				TCBUpToDate:   hostPlatformData[i].TCBUpToDate,
				ValidTo:       hostPlatformData[i].ValidTo,
			}

			_, err := sahDB.HostRepository().Create(host)
			if err != nil {
				log.WithError(err).Errorf("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Error creating host record in DB for host %s", hostPlatformData[i].Id)
				continue
			}
			log.Info("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Successfully created Host in DB")
		} else {
			host = types.Host{
				Id:            existingHost.Id,
				HostName:      hostInfo.HostName,
				ConnectionURL: hostInfo.ConnectionURL,
				HardwareUUID:  existingHost.HardwareUUID,
				CreatedTime:   existingHost.CreatedTime,
				UpdatedTime:   time.Now(),
				SGXSupported:  hostPlatformData[i].SGXSupported,
				SGXEnabled:    hostPlatformData[i].SGXEnabled,
				FLCEnabled:    hostPlatformData[i].FLCEnabled,
				EPCSize:       hostPlatformData[i].EPCSize,
				TCBUpToDate:   hostPlatformData[i].TCBUpToDate,
				ValidTo:       hostPlatformData[i].ValidTo,
			}
			err := sahDB.HostRepository().Update(host)
			if err != nil {
				log.WithError(err).Errorf("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Error updating host record in DB for host %s", hostPlatformData[i].Id)
				continue
			}
			log.Info("resource/sgx_ah_push_pull_data: FetchHostRegisteredInLastFewMinutes() Successfully updated Host in DB")
		}
	}
	return nil
}
