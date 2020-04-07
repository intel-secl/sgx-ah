package attestationServicePollerJob

import (
	clog "intel/isecl/lib/common/log"
	"intel/isecl/sgx-attestation-hub/config"
	"intel/isecl/sgx-attestation-hub/constants"
	"intel/isecl/sgx-attestation-hub/repository"
	"intel/isecl/sgx-attestation-hub/repository/postgres"
	"intel/isecl/sgx-attestation-hub/resource"
	"time"
)

var log = clog.GetDefaultLogger()

func Execute(sahDB repository.SAHDatabase) error {

	conf := config.Global()
	out, fileExistsErr := resource.FileExists(constants.ConfigDir + constants.HubTimeStamp)
	log.Info("File to save timestamp: ", constants.ConfigDir+constants.HubTimeStamp)
	currentTime := time.Now()
	formatedTime := currentTime.Format(time.UnixDate)

	if out == false {
		log.Debug("attestationServicePollerJob.Execute(): Error: ", fileExistsErr)
		err := resource.FetchAllHostsFromHVS(sahDB)
		log.Debug("attestationServicePollerJob.Execute(): Error: ", err)
		if err != nil {
			return err
		}
		resource.WriteDataIn(constants.ConfigDir+constants.HubTimeStamp, formatedTime)
	} else {
		log.Info("attestationServicePollerJob.Execute(): Refresh Time: ", conf.SchedulerTimer)
		err := resource.FetchHostRegisteredInLastFewMinutes(sahDB, conf.SchedulerTimer)
		if err != nil {
			log.Debug("attestationServicePollerJob.Execute(): ", err)
			return err
		}
		resource.WriteDataIn(constants.ConfigDir+constants.HubTimeStamp, formatedTime)
	}
	return nil

}
