package main

import (
	"io/ioutil"
	"log"
	"testing"
	"time"

	"gopkg.in/yaml.v2"
)

func TestConfig(t *testing.T) {
	contents, err := ioutil.ReadFile("someta_config_example.yaml")
	if err != nil {
		log.Fatal(err)
	}
	var smConf SometaConf
	err = yaml.Unmarshal(contents, &smConf)
	if err != nil {
		log.Fatal(err)
	}

	if smConf.Someta.Command != "sleep 60" {
		t.Log("bad command", smConf.Someta.Command)
		t.Fail()
	}
	if smConf.Someta.Outfilebase != "metadata" {
		t.Log("bad outfilebase", smConf.Someta.Outfilebase)
		t.Fail()
	}
	if !smConf.Someta.Verbose {
		t.Log("expected verbose to be true")
		t.Fail()
	}
	if smConf.Someta.Quiet {
		t.Log("expected quiet to be false")
		t.Fail()
	}
	if !smConf.Someta.UseLogfile {
		t.Log("expected uselogfile to be true")
		t.Fail()
	}
	if smConf.Someta.StatusInterval != time.Second*5 {
		t.Log("bad status interval", smConf.Someta.StatusInterval)
		t.Fail()
	}
	if smConf.Someta.MonitorInterval != time.Second*1 {
		t.Log("bad monitor interval", smConf.Someta.MonitorInterval)
		t.Fail()
	}
	if smConf.Someta.MetaFlushInterval != time.Minute*10 {
		t.Log("bad metaflush interval", smConf.Someta.MetaFlushInterval)
		t.Fail()
	}
	if smConf.Someta.FileRolloverInterval != time.Hour*1 {
		t.Log("bad filerollover interval", smConf.Someta.FileRolloverInterval)
		t.Fail()
	}
	if smConf.Someta.WarmCoolTime != time.Second*2 {
		t.Log("bad warmcool time", smConf.Someta.WarmCoolTime)
		t.Fail()
	}
	if smConf.Someta.CPUAffinity != -1 {
		t.Log("bad cpu affinity", smConf.Someta.CPUAffinity)
		t.Fail()
	}
	if len(smConf.Monitors) != 8 {
		t.Log("wrong number of monitors found", len(smConf.Monitors))
		t.Fail()
	}
}
