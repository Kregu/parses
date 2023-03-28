package main

import (
	"encoding/xml"
)

type Selftest struct {
	XMLName xml.Name `xml:"selftest"`
	Text    string   `xml:",chardata"`
	Xmlns   string   `xml:"xmlns,attr"`
	Version string   `xml:"version,attr"`
	File    []struct {
		Text string `xml:",chardata"`
		Name string `xml:"name,attr"`
	} `xml:"file"`
	Error     []string `xml:"error"`
	Sandbox   []string `xml:"sandbox"`
	Release   []string `xml:"release"`
	Title     []string `xml:"title"`
	Timestamp string   `xml:"timestamp"`
	Valid     string   `xml:"valid"`
	Checking  string   `xml:"checking"`
	Firmware  struct {
		Text    string `xml:",chardata"`
		Version string `xml:"version"`
		Title   string `xml:"title"`
	} `xml:"firmware"`
	Component []struct {
		Text        string `xml:",chardata"`
		Name        string `xml:"name"`
		Description []struct {
			Text string `xml:",chardata"`
			Lang string `xml:"lang,attr"`
		} `xml:"description"`
		Details []struct {
			Text string `xml:",chardata"`
			Lang string `xml:"lang,attr"`
		} `xml:"details"`
		Priority  string `xml:"priority"`
		Size      string `xml:"size"`
		Order     string `xml:"order"`
		Version   string `xml:"version"`
		Hash      string `xml:"hash"`
		Installed string `xml:"installed"`
		Queued    string `xml:"queued"`
		Group     string `xml:"group"`
		Libndm    string `xml:"libndm"`
		Depend    string `xml:"depend"`
		Script    []struct {
			Text string `xml:",chardata"`
			Mode string `xml:"mode,attr"`
		} `xml:"script"`
		Regions string `xml:"regions"`
	} `xml:"component"`
	Group []struct {
		Text        string `xml:",chardata"`
		Name        string `xml:"name"`
		Description []struct {
			Text string `xml:",chardata"`
			Lang string `xml:"lang,attr"`
		} `xml:"description"`
		Order   string `xml:"order"`
		Details []struct {
			Text string `xml:",chardata"`
			Lang string `xml:"lang,attr"`
		} `xml:"details"`
		MaxSelect string `xml:"max-select"`
	} `xml:"group"`
	Certificate []struct {
		Text            string `xml:",chardata"`
		Domain          string `xml:"domain"`
		IsNdns          string `xml:"is-ndns"`
		ShouldBeRenewed string `xml:"should-be-renewed"`
		IsExpired       string `xml:"is-expired"`
		IssueTime       string `xml:"issue-time"`
		ExpirationTime  string `xml:"expiration-time"`
	} `xml:"certificate"`
	Acme struct {
		Text                          string `xml:",chardata"`
		ServerEnabled                 string `xml:"server-enabled"`
		RealTime                      string `xml:"real-time"`
		NdnsDomain                    string `xml:"ndns-domain"`
		NdnsDomainAcme                string `xml:"ndns-domain-acme"`
		NdnsDomainError               string `xml:"ndns-domain-error"`
		DefaultDomain                 string `xml:"default-domain"`
		DirectoryURI                  string `xml:"directory-uri"`
		KeyType                       string `xml:"key-type"`
		DefaultDomainCertificateValid string `xml:"default-domain-certificate-valid"`
		AccountPending                string `xml:"account-pending"`
		AccountRunning                string `xml:"account-running"`
		GetPending                    string `xml:"get-pending"`
		GetRunning                    string `xml:"get-running"`
		RevokePending                 string `xml:"revoke-pending"`
		RevokeRunning                 string `xml:"revoke-running"`
		ReissueQueueSize              string `xml:"reissue-queue-size"`
		Retries                       string `xml:"retries"`
		CheckerTimer                  string `xml:"checker-timer"`
		ApplyTimer                    string `xml:"apply-timer"`
		AcmeAccount                   string `xml:"acme-account"`
		NextTryTa                     string `xml:"next-try-ta"`
		Jitter                        string `xml:"jitter"`
	} `xml:"acme"`
	Station []struct {
		Text          string   `xml:",chardata"`
		Mac           string   `xml:"mac"`
		Ap            string   `xml:"ap"`
		Authenticated string   `xml:"authenticated"`
		Txrate        string   `xml:"txrate"`
		Uptime        string   `xml:"uptime"`
		Txbytes       string   `xml:"txbytes"`
		Rxbytes       string   `xml:"rxbytes"`
		Ht            string   `xml:"ht"`
		Mode          string   `xml:"mode"`
		Gi            string   `xml:"gi"`
		Rssi          string   `xml:"rssi"`
		Mcs           string   `xml:"mcs"`
		Txss          string   `xml:"txss"`
		Ebf           string   `xml:"ebf"`
		DlMu          string   `xml:"dl-mu"`
		Security      string   `xml:"security"`
		V11           []string `xml:"_11"`
	} `xml:"station"`
	Buttons struct {
		Text   string `xml:",chardata"`
		Button []struct {
			Text          string `xml:",chardata"`
			Name          string `xml:"name,attr"`
			IsSwitch      string `xml:"is_switch"`
			Position      string `xml:"position"`
			PositionCount string `xml:"position_count"`
			Clicks        string `xml:"clicks"`
			Elapsed       string `xml:"elapsed"`
			HoldDelay     string `xml:"hold_delay"`
		} `xml:"button"`
	} `xml:"buttons"`
	Weekday string `xml:"weekday"`
	Day     string `xml:"day"`
	Month   string `xml:"month"`
	Year    string `xml:"year"`
	Hour    string `xml:"hour"`
	Min     string `xml:"min"`
	Sec     string `xml:"sec"`
	Msec    string `xml:"msec"`
	Dst     string `xml:"dst"`
	Tz      struct {
		Text      string `xml:",chardata"`
		Locality  string `xml:"locality"`
		Stdoffset string `xml:"stdoffset"`
		Dstoffset string `xml:"dstoffset"`
		Usesdst   string `xml:"usesdst"`
		Rule      string `xml:"rule"`
		Custom    string `xml:"custom"`
	} `xml:"tz"`
	Agent []struct {
		Text    string `xml:",chardata"`
		Service struct {
			Text                string `xml:",chardata"`
			State               string `xml:"state"`
			TokenAlias          string `xml:"token_alias"`
			Since               string `xml:"since"`
			LoopDelay           string `xml:"loop_delay"`
			LoopInterval        string `xml:"loop_interval"`
			LoopLimit           string `xml:"loop_limit"`
			LoopSleep           string `xml:"loop_sleep"`
			TcpConnectTimeout   string `xml:"tcp_connect_timeout"`
			SerialIn            string `xml:"serial_in"`
			SerialOut           string `xml:"serial_out"`
			DirectAccess        string `xml:"direct_access"`
			Transport           string `xml:"transport"`
			TargetList          string `xml:"target_list"`
			TargetHost          string `xml:"target_host"`
			TargetPort          string `xml:"target_port"`
			SuspendTimeout      string `xml:"suspend_timeout"`
			SessionCheckTimeout string `xml:"session_check_timeout"`
			StatusCode          string `xml:"status_code"`
			EventStore          struct {
				Text     string `xml:",chardata"`
				Tx       string `xml:"tx"`
				Retx     string `xml:"retx"`
				Dropped  string `xml:"dropped"`
				CackHit  string `xml:"cack_hit"`
				CackMiss string `xml:"cack_miss"`
				Pending  string `xml:"pending"`
			} `xml:"event_store"`
		} `xml:"service"`
		Domain string `xml:"domain"`
	} `xml:"agent"`
	Enabled  []string `xml:"enabled"`
	Linked   string   `xml:"linked"`
	Prepared string   `xml:"prepared"`
	Fqdn     string   `xml:"fqdn"`
	Touch    string   `xml:"touch"`
	Header   []struct {
		Text string `xml:",chardata"`
		Name string `xml:"name,attr"`
	} `xml:"header"`
	Stats []struct {
		Text     string   `xml:",chardata"`
		Path     string   `xml:"path"`
		Duration []string `xml:"duration"`
		Count    string   `xml:"count"`
	} `xml:"stats"`
	Servicetag  []string `xml:"servicetag"`
	Servicehost string   `xml:"servicehost"`
	Servicepass string   `xml:"servicepass"`
	Wlanssid    string   `xml:"wlanssid"`
	Wlankey     string   `xml:"wlankey"`
	Wlanwps     string   `xml:"wlanwps"`
	Country     string   `xml:"country"`
	Ndmhwid     string   `xml:"ndmhwid"`
	Product     string   `xml:"product"`
	Ctrlsum     string   `xml:"ctrlsum"`
	Serial      []string `xml:"serial"`
	Signature   string   `xml:"signature"`
	Integrity   string   `xml:"integrity"`
	Locked      string   `xml:"locked"`
	ProxyStatus struct {
		Text        string `xml:",chardata"`
		ProxyName   string `xml:"proxy-name"`
		ProxyConfig string `xml:"proxy-config"`
		ProxyStat   string `xml:"proxy-stat"`
		ProxySafe   string `xml:"proxy-safe"`
	} `xml:"proxy-status"`
	Dnsf   string `xml:"dnsf"`
	Module []struct {
		Text string `xml:",chardata"`
		Name string `xml:"name"`
		Size string `xml:"size"`
		Used string `xml:"used"`
		Subs string `xml:"subs"`
		Args string `xml:"args"`
	} `xml:"module"`
	Environment struct {
		Text         string `xml:",chardata"`
		DNSPRESETSTS string `xml:"DNS_PRESETS_TS"`
		NDWMws       string `xml:"NDW_mws"`
	} `xml:"environment"`
	Mac       string `xml:"mac"`
	Hwid      string `xml:"hwid"`
	Cid       string `xml:"cid"`
	Interface []struct {
		Text          string   `xml:",chardata"`
		Name          string   `xml:"name,attr"`
		ID            string   `xml:"id"`
		Index         string   `xml:"index"`
		InterfaceName string   `xml:"interface-name"`
		Type          string   `xml:"type"`
		Description   string   `xml:"description"`
		Traits        []string `xml:"traits"`
		Link          string   `xml:"link"`
		Connected     string   `xml:"connected"`
		State         string   `xml:"state"`
		Mtu           string   `xml:"mtu"`
		TxQueueLength string   `xml:"tx-queue-length"`
		Port          []struct {
			Text          string   `xml:",chardata"`
			Name          string   `xml:"name,attr"`
			ID            string   `xml:"id"`
			Index         string   `xml:"index"`
			InterfaceName string   `xml:"interface-name"`
			Label         string   `xml:"label"`
			Type          string   `xml:"type"`
			Traits        []string `xml:"traits"`
			Role          struct {
				Text string `xml:",chardata"`
				For  string `xml:"for,attr"`
			} `xml:"role"`
			Link             string `xml:"link"`
			Speed            string `xml:"speed"`
			Duplex           string `xml:"duplex"`
			AutoNegotiation  string `xml:"auto-negotiation"`
			FlowControl      string `xml:"flow-control"`
			Eee              string `xml:"eee"`
			LastChange       string `xml:"last-change"`
			LastOverflow     string `xml:"last-overflow"`
			CableDiagnostics string `xml:"cable-diagnostics"`
			Public           string `xml:"public"`
			LinkGroup        struct {
				Text      string `xml:",chardata"`
				Supported string `xml:"supported"`
			} `xml:"link-group"`
			Transceiver string `xml:"transceiver"`
			SfpCombo    string `xml:"sfp-combo"`
		} `xml:"port"`
		Label string `xml:"label"`
		Role  struct {
			Text string `xml:",chardata"`
			For  string `xml:"for,attr"`
		} `xml:"role"`
		Speed            string `xml:"speed"`
		Duplex           string `xml:"duplex"`
		AutoNegotiation  string `xml:"auto-negotiation"`
		FlowControl      string `xml:"flow-control"`
		Eee              string `xml:"eee"`
		LastChange       string `xml:"last-change"`
		LastOverflow     string `xml:"last-overflow"`
		CableDiagnostics string `xml:"cable-diagnostics"`
		Public           string `xml:"public"`
		LinkGroup        struct {
			Text      string `xml:",chardata"`
			Supported string `xml:"supported"`
		} `xml:"link-group"`
		Group         string   `xml:"group"`
		Usedby        []string `xml:"usedby"`
		Mac           string   `xml:"mac"`
		AuthType      string   `xml:"auth-type"`
		Address       string   `xml:"address"`
		Mask          string   `xml:"mask"`
		Uptime        string   `xml:"uptime"`
		Global        string   `xml:"global"`
		SecurityLevel string   `xml:"security-level"`
		Transceiver   string   `xml:"transceiver"`
		SfpCombo      string   `xml:"sfp-combo"`
		Hwstate       string   `xml:"hwstate"`
		Bitrate       string   `xml:"bitrate"`
		Channel       string   `xml:"channel"`
		Bandwidth     string   `xml:"bandwidth"`
		BusyChannels  []string `xml:"busy-channels"`
		Temperature   string   `xml:"temperature"`
		Ssid          string   `xml:"ssid"`
		Encryption    string   `xml:"encryption"`
		Ap            string   `xml:"ap"`
		Bridge        struct {
			Text      string `xml:",chardata"`
			Interface []struct {
				Text      string `xml:",chardata"`
				Link      string `xml:"link,attr"`
				Inherited string `xml:"inherited,attr"`
			} `xml:"interface"`
		} `xml:"bridge"`
		Defaultgw         string `xml:"defaultgw"`
		Priority          string `xml:"priority"`
		Remote            string `xml:"remote"`
		Fail              string `xml:"fail"`
		Via               string `xml:"via"`
		IpsecEnabled      string `xml:"ipsec-enabled"`
		IpsecIkev2Allowed string `xml:"ipsec-ikev2-allowed"`
		IpsecIkev2Enabled string `xml:"ipsec-ikev2-enabled"`
	} `xml:"interface"`
	Mactable []struct {
		Text  string `xml:",chardata"`
		Port  string `xml:"port"`
		Mac   string `xml:"mac"`
		Aging string `xml:"aging"`
		Vlan  string `xml:"vlan"`
	} `xml:"mactable"`
	Checked           string `xml:"checked"`
	Reliable          string `xml:"reliable"`
	GatewayAccessible string `xml:"gateway-accessible"`
	DnsAccessible     string `xml:"dns-accessible"`
	HostAccessible    string `xml:"host-accessible"`
	CaptiveAccessible string `xml:"captive-accessible"`
	Internet          string `xml:"internet"`
	Gateway           struct {
		Text       string `xml:",chardata"`
		Interface  string `xml:"interface"`
		Address    string `xml:"address"`
		Failures   string `xml:"failures"`
		Accessible string `xml:"accessible"`
		Excluded   string `xml:"excluded"`
	} `xml:"gateway"`
	Captive struct {
		Text     string `xml:",chardata"`
		Host     string `xml:"host"`
		Response string `xml:"response"`
		Location string `xml:"location"`
		Failures string `xml:"failures"`
		Resolved string `xml:"resolved"`
		Address  string `xml:"address"`
	} `xml:"captive"`
	Arp []struct {
		Text      string `xml:",chardata"`
		Ip        string `xml:"ip"`
		Mac       string `xml:"mac"`
		Interface string `xml:"interface"`
		Name      string `xml:"name"`
		State     string `xml:"state"`
	} `xml:"arp"`
	Conntrack struct {
		Text string `xml:",chardata"`
		Ipv4 string `xml:"ipv4"`
	} `xml:"conntrack"`
	Lease []struct {
		Text     string `xml:",chardata"`
		Ip       string `xml:"ip"`
		Mac      string `xml:"mac"`
		Via      string `xml:"via"`
		Hostname string `xml:"hostname"`
		Name     string `xml:"name"`
		Expires  string `xml:"expires"`
	} `xml:"lease"`
	DhcpClient []struct {
		Text    string `xml:",chardata"`
		ID      string `xml:"id"`
		Name    string `xml:"name"`
		Service string `xml:"service"`
		State   string `xml:"state"`
	} `xml:"dhcp-client"`
	Pool []struct {
		Text      string `xml:",chardata"`
		Name      string `xml:"name,attr"`
		Interface struct {
			Text    string `xml:",chardata"`
			Binding string `xml:"binding,attr"`
		} `xml:"interface"`
		Network string `xml:"network"`
		Begin   string `xml:"begin"`
		End     string `xml:"end"`
		Router  struct {
			Text    string `xml:",chardata"`
			Default string `xml:"default,attr"`
		} `xml:"router"`
		Lease struct {
			Text    string `xml:",chardata"`
			Default string `xml:"default,attr"`
		} `xml:"lease"`
		State string `xml:"state"`
		Debug string `xml:"debug"`
	} `xml:"pool"`
	Host []struct {
		Text      string `xml:",chardata"`
		Mac       string `xml:"mac"`
		Via       string `xml:"via"`
		Ip        string `xml:"ip"`
		Hostname  string `xml:"hostname"`
		Name      string `xml:"name"`
		Interface struct {
			Text        string `xml:",chardata"`
			ID          string `xml:"id"`
			Name        string `xml:"name"`
			Description string `xml:"description"`
		} `xml:"interface"`
		Dhcp struct {
			Text    string `xml:",chardata"`
			Expires string `xml:"expires"`
		} `xml:"dhcp"`
		Registered      string `xml:"registered"`
		Access          string `xml:"access"`
		Schedule        string `xml:"schedule"`
		Priority        string `xml:"priority"`
		Active          string `xml:"active"`
		Rxbytes         string `xml:"rxbytes"`
		Txbytes         string `xml:"txbytes"`
		Uptime          string `xml:"uptime"`
		FirstSeen       string `xml:"first-seen"`
		LastSeen        string `xml:"last-seen"`
		Link            string `xml:"link"`
		AutoNegotiation string `xml:"auto-negotiation"`
		Speed           string `xml:"speed"`
		Duplex          string `xml:"duplex"`
		Port            string `xml:"port"`
		TrafficShape    struct {
			Text     string `xml:",chardata"`
			Rx       string `xml:"rx"`
			Tx       string `xml:"tx"`
			Mode     string `xml:"mode"`
			Schedule string `xml:"schedule"`
		} `xml:"traffic-shape"`
		Ssid          string   `xml:"ssid"`
		Ap            string   `xml:"ap"`
		Authenticated string   `xml:"authenticated"`
		Txrate        string   `xml:"txrate"`
		Ht            string   `xml:"ht"`
		Mode          string   `xml:"mode"`
		Gi            string   `xml:"gi"`
		Rssi          string   `xml:"rssi"`
		Mcs           string   `xml:"mcs"`
		Txss          string   `xml:"txss"`
		Ebf           string   `xml:"ebf"`
		DlMu          string   `xml:"dl-mu"`
		V11           []string `xml:"_11"`
		Security      string   `xml:"security"`
		DnsFilter     struct {
			Text    string `xml:",chardata"`
			Engine  string `xml:"engine"`
			Profile string `xml:"profile"`
			Mode    string `xml:"mode"`
			Level   string `xml:"level"`
		} `xml:"dns-filter"`
	} `xml:"host"`
	CurrentConfig string `xml:"current-config"`
	Server        []struct {
		Text      string `xml:",chardata"`
		Address   string `xml:"address"`
		Port      string `xml:"port"`
		Domain    string `xml:"domain"`
		Global    string `xml:"global"`
		Service   string `xml:"service"`
		Interface string `xml:"interface"`
	} `xml:"server"`
	Neighbour []struct {
		Text          string `xml:",chardata"`
		ID            string `xml:"id"`
		Via           string `xml:"via"`
		Mac           string `xml:"mac"`
		AddressFamily string `xml:"address-family"`
		Address       string `xml:"address"`
		Interface     string `xml:"interface"`
		FirstSeen     string `xml:"first-seen"`
		LastSeen      string `xml:"last-seen"`
		Leasetime     string `xml:"leasetime"`
		Expired       string `xml:"expired"`
		MwsDuplicate  string `xml:"mws-duplicate"`
		Wireless      string `xml:"wireless"`
	} `xml:"neighbour"`
	Table58 struct {
		Text  string `xml:",chardata"`
		Route []struct {
			Text        string `xml:",chardata"`
			Destination string `xml:"destination"`
			Gateway     string `xml:"gateway"`
			Interface   string `xml:"interface"`
			Metric      string `xml:"metric"`
			Flags       string `xml:"flags"`
			Rejecting   string `xml:"rejecting"`
			Proto       string `xml:"proto"`
			Floating    string `xml:"floating"`
			Static      string `xml:"static"`
		} `xml:"route"`
	} `xml:"table_58"`
	Table59 struct {
		Text  string `xml:",chardata"`
		Route []struct {
			Text        string `xml:",chardata"`
			Destination string `xml:"destination"`
			Gateway     string `xml:"gateway"`
			Interface   string `xml:"interface"`
			Metric      string `xml:"metric"`
			Flags       string `xml:"flags"`
			Rejecting   string `xml:"rejecting"`
			Proto       string `xml:"proto"`
			Floating    string `xml:"floating"`
			Static      string `xml:"static"`
		} `xml:"route"`
	} `xml:"table_59"`
	Table254 struct {
		Text  string `xml:",chardata"`
		Route []struct {
			Text        string `xml:",chardata"`
			Destination string `xml:"destination"`
			Gateway     string `xml:"gateway"`
			Interface   string `xml:"interface"`
			Metric      string `xml:"metric"`
			Flags       string `xml:"flags"`
			Rejecting   string `xml:"rejecting"`
			Proto       string `xml:"proto"`
			Floating    string `xml:"floating"`
			Static      string `xml:"static"`
		} `xml:"route"`
	} `xml:"table_254"`
	Rule  string `xml:"rule"`
	Ipset []struct {
		Text            string `xml:",chardata"`
		NDMBFDTelnet    string `xml:"_NDM_BFD_Telnet"`
		NDMBFDHTTP      string `xml:"_NDM_BFD_Http"`
		NDMHTSPMACBLOCK string `xml:"_NDM_HTSP_MAC_BLOCK"`
		NDMHTSPMACALLOW string `xml:"_NDM_HTSP_MAC_ALLOW"`
		NDMDNSSRVS      string `xml:"_NDM_DNS_SRVS"`
		NDMDNSINTR      string `xml:"_NDM_DNS_INTR"`
		NDMDNSBYPS      string `xml:"_NDM_DNS_BYPS"`
		NDMVPNSRVL2TP   string `xml:"_NDM_VPNSRV_L2TP"`
		NDMVPNSRVSSTP   string `xml:"_NDM_VPNSRV_SSTP"`
	} `xml:"ipset"`
	Date string `xml:"date"`
	User []struct {
		Text string `xml:",chardata"`
		Cur  string `xml:"cur"`
		Min  string `xml:"min"`
		Max  string `xml:"max"`
		Avg  string `xml:"avg"`
	} `xml:"user"`
	Checksum   string `xml:"checksum"`
	Easyconfig string `xml:"easyconfig"`
	FailSafe   struct {
		Text     string `xml:",chardata"`
		Action   string `xml:"action"`
		Unsaved  string `xml:"unsaved"`
		TimeLeft string `xml:"time-left"`
		Rollback string `xml:"rollback"`
		Blocked  string `xml:"blocked"`
	} `xml:"fail-safe"`
	Mwst     string `xml:"mwst"`
	Name     string `xml:"name"`
	Booked   string `xml:"booked"`
	Domain   string `xml:"domain"`
	Address  string `xml:"address"`
	Address6 string `xml:"address6"`
	Updated  string `xml:"updated"`
	Access   string `xml:"access"`
	Access6  string `xml:"access6"`
	Xns      string `xml:"xns"`
	Ttp      struct {
		Text      string `xml:",chardata"`
		Direct    string `xml:"direct"`
		Interface string `xml:"interface"`
		Address   string `xml:"address"`
	} `xml:"ttp"`
	Registrator struct {
		Text          string `xml:",chardata"`
		Reasons       string `xml:"reasons"`
		State         string `xml:"state"`
		Delay         string `xml:"delay"`
		WanIp         string `xml:"wan-ip"`
		WanIp6        string `xml:"wan-ip6"`
		SentWanIp     string `xml:"sent-wan-ip"`
		SentWanIp6    string `xml:"sent-wan-ip6"`
		LastNrReason  string `xml:"last-nr-reason"`
		LastError     string `xml:"last-error"`
		SinceLastCall string `xml:"since-last-call"`
		SinceLastNr   string `xml:"since-last-nr"`
		FailureCount  string `xml:"failure-count"`
		Fallback      string `xml:"fallback"`
	} `xml:"registrator"`
	Netfilter string `xml:"netfilter"`
	Status    struct {
		Text         string `xml:",chardata"`
		Elapsed      string `xml:"elapsed"`
		Server       string `xml:"server"`
		Accurate     string `xml:"accurate"`
		Synchronized string `xml:"synchronized"`
		Ndsstime     string `xml:"ndsstime"`
		Usertime     string `xml:"usertime"`
	} `xml:"status"`
	Pingcheck struct {
		Text    string `xml:",chardata"`
		Profile string `xml:"profile"`
	} `xml:"pingcheck"`
	Process []struct {
		Text        string   `xml:",chardata"`
		Comm        string   `xml:"comm"`
		OomAdj      string   `xml:"oom-adj"`
		OomScore    string   `xml:"oom-score"`
		OomScoreAdj string   `xml:"oom-score-adj"`
		Arg         []string `xml:"arg"`
		State       string   `xml:"state"`
		Pid         string   `xml:"pid"`
		Ppid        string   `xml:"ppid"`
		VmSize      string   `xml:"vm-size"`
		VmRss       string   `xml:"vm-rss"`
		VmData      string   `xml:"vm-data"`
		VmStk       string   `xml:"vm-stk"`
		VmExe       string   `xml:"vm-exe"`
		VmLib       string   `xml:"vm-lib"`
		VmSwap      string   `xml:"vm-swap"`
		Threads     string   `xml:"threads"`
		Fds         string   `xml:"fds"`
		Statistics  struct {
			Text     string `xml:",chardata"`
			Interval string `xml:"interval"`
			Cpu      struct {
				Text string `xml:",chardata"`
				Now  string `xml:"now"`
				Min  string `xml:"min"`
				Max  string `xml:"max"`
				Avg  string `xml:"avg"`
				Cur  string `xml:"cur"`
			} `xml:"cpu"`
		} `xml:"statistics"`
		Object struct {
			Text  string `xml:",chardata"`
			ID    string `xml:"id"`
			State string `xml:"state"`
		} `xml:"object"`
		Service struct {
			Text       string `xml:",chardata"`
			Configured string `xml:"configured"`
			Alive      string `xml:"alive"`
			Started    string `xml:"started"`
			State      string `xml:"state"`
		} `xml:"service"`
	} `xml:"process"`
	Schedule struct {
		Text   string `xml:",chardata"`
		Name   string `xml:"name,attr"`
		Action []struct {
			Text string `xml:",chardata"`
			Type string `xml:"type,attr"`
			Left string `xml:"left,attr"`
			Next string `xml:"next,attr"`
			Dow  string `xml:"dow"`
			Time string `xml:"time"`
		} `xml:"action"`
	} `xml:"schedule"`
	NdnsName           string `xml:"ndns-name"`
	HasNdnsCertificate string `xml:"has-ndns-certificate"`
	Hostname           string `xml:"hostname"`
	Domainname         string `xml:"domainname"`
	Cpuload            string `xml:"cpuload"`
	Memory             string `xml:"memory"`
	Swap               string `xml:"swap"`
	Memtotal           string `xml:"memtotal"`
	Memfree            string `xml:"memfree"`
	Membuffers         string `xml:"membuffers"`
	Memcache           string `xml:"memcache"`
	Swaptotal          string `xml:"swaptotal"`
	Swapfree           string `xml:"swapfree"`
	Uptime             string `xml:"uptime"`
	Interval           string `xml:"interval"`
	Busy               struct {
		Text string `xml:",chardata"`
		Cur  string `xml:"cur"`
		Min  string `xml:"min"`
		Max  string `xml:"max"`
		Avg  string `xml:"avg"`
	} `xml:"busy"`
	Nice struct {
		Text string `xml:",chardata"`
		Cur  string `xml:"cur"`
		Min  string `xml:"min"`
		Max  string `xml:"max"`
		Avg  string `xml:"avg"`
	} `xml:"nice"`
	System struct {
		Text string `xml:",chardata"`
		Cur  string `xml:"cur"`
		Min  string `xml:"min"`
		Max  string `xml:"max"`
		Avg  string `xml:"avg"`
	} `xml:"system"`
	Iowait struct {
		Text string `xml:",chardata"`
		Cur  string `xml:"cur"`
		Min  string `xml:"min"`
		Max  string `xml:"max"`
		Avg  string `xml:"avg"`
	} `xml:"iowait"`
	Irq struct {
		Text string `xml:",chardata"`
		Cur  string `xml:"cur"`
		Min  string `xml:"min"`
		Max  string `xml:"max"`
		Avg  string `xml:"avg"`
	} `xml:"irq"`
	Sirq struct {
		Text string `xml:",chardata"`
		Cur  string `xml:"cur"`
		Min  string `xml:"min"`
		Max  string `xml:"max"`
		Avg  string `xml:"avg"`
	} `xml:"sirq"`
	Debug struct {
		Text  string `xml:",chardata"`
		State string `xml:"state"`
		Alarm string `xml:"alarm"`
	} `xml:"debug"`
	Mode struct {
		Text         string `xml:",chardata"`
		Active       string `xml:"active"`
		Selected     string `xml:"selected"`
		Supported    string `xml:"supported"`
		HwControlled string `xml:"hw_controlled"`
		HwLocked     string `xml:"hw_locked"`
	} `xml:"mode"`
	Zram struct {
		Text    string `xml:",chardata"`
		Enabled string `xml:"enabled"`
	} `xml:"zram"`
	Tag     []string `xml:"tag"`
	Threads struct {
		Text   string `xml:",chardata"`
		Thread []struct {
			Text             string `xml:",chardata"`
			Name             string `xml:"name"`
			Tid              string `xml:"tid"`
			LockListComplete string `xml:"lock_list_complete"`
			Locks            struct {
				Text string `xml:",chardata"`
				Lock struct {
					Text       string `xml:",chardata"`
					Precedence struct {
						Text  string `xml:",chardata"`
						Name  string `xml:"name"`
						Order string `xml:"order"`
					} `xml:"precedence"`
					State    string `xml:"state"`
					Since    string `xml:"since"`
					Duration string `xml:"duration"`
				} `xml:"lock"`
			} `xml:"locks"`
			Backtrace struct {
				Text  string `xml:",chardata"`
				Calls string `xml:"calls"`
				Error string `xml:"error"`
			} `xml:"backtrace"`
			Statistics struct {
				Text     string `xml:",chardata"`
				Interval string `xml:"interval"`
				Cpu      struct {
					Text string `xml:",chardata"`
					Now  string `xml:"now"`
					Min  string `xml:"min"`
					Max  string `xml:"max"`
					Avg  string `xml:"avg"`
					Cur  string `xml:"cur"`
				} `xml:"cpu"`
			} `xml:"statistics"`
		} `xml:"thread"`
	} `xml:"threads"`
	Entry []struct {
		Text        string `xml:",chardata"`
		Index       string `xml:"index"`
		Interface   string `xml:"interface"`
		Protocol    string `xml:"protocol"`
		Port        string `xml:"port"`
		ToAddress   string `xml:"to-address"`
		ToPort      string `xml:"to-port"`
		Description string `xml:"description"`
		Policy      string `xml:"policy"`
		Packets     string `xml:"packets"`
		Bytes       string `xml:"bytes"`
	} `xml:"entry"`
	Usb  string `xml:"usb"`
	Arch string `xml:"arch"`
	Ndm  struct {
		Text  string `xml:",chardata"`
		Exact string `xml:"exact"`
		Cdate string `xml:"cdate"`
	} `xml:"ndm"`
	Bsp struct {
		Text  string `xml:",chardata"`
		Exact string `xml:"exact"`
		Cdate string `xml:"cdate"`
	} `xml:"bsp"`
	Ndw struct {
		Text       string `xml:",chardata"`
		Version    string `xml:"version"`
		Features   string `xml:"features"`
		Components string `xml:"components"`
	} `xml:"ndw"`
	Ndw3 struct {
		Text    string `xml:",chardata"`
		Version string `xml:"version"`
	} `xml:"ndw3"`
	Manufacturer string `xml:"manufacturer"`
	Vendor       string `xml:"vendor"`
	Series       string `xml:"series"`
	Model        string `xml:"model"`
	HwVersion    string `xml:"hw_version"`
	HwType       string `xml:"hw_type"`
	HwID         string `xml:"hw_id"`
	Device       string `xml:"device"`
	Region       string `xml:"region"`
	Description  string `xml:"description"`
}
