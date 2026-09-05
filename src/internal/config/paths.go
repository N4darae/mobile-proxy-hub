package config

const (
	Product = "dongled"

	NftFamily = "inet"
	NftTable  = Product

	GroupName = Product
	GroupGID  = 6100

	SessionCookie = "__Host-" + Product + "_session"
	APIKeyPrefix  = "dgl_live_"

	UnitBackend     = Product + ".service"
	UnitProxyTpl    = Product + "-proxy@.service"
	UnitBackup      = Product + "-backup.service"
	UnitBackupTimer = Product + "-backup.timer"

	Pin3proxyCommit = "122ca26249aaaac9156e0805891555c70e19f2b3"

	KEKCredName = "kek"

	DefaultBackupKeep = 14
)

var (
	ProxyConfDir = EtcDir + "/proxy"

	DBPath      = StateDir + "/" + Product + ".db"
	Bin3proxy   = BinDir + "/3proxy"
	FarmMarker  = EtcDir + "/FARM"
	KEKCredFile = EtcDir + "/kek.cred"
)

func (c Config) FarmMarkerPath() string {
	if c.EtcDir == "" {
		return FarmMarker
	}
	return c.EtcDir + "/FARM"
}

func ProxyUnit(user string) string {
	return Product + "-proxy@" + user + ".service"
}

func ProxyConfigPath(user string) string {
	return ProxyConfDir + "/" + user + ".cfg"
}

func ProxyLogPath(user string) string {
	return LogDir + "/" + user + ".log"
}
