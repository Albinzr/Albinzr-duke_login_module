package duke_login_module

import (
	"github.com/Albinzr/duke_login_module/database"
	"github.com/Albinzr/duke_login_module/login_config"
	"github.com/Albinzr/duke_login_module/router"
)

type Config login_config.Config

func (c *Config) Init() {

	dbConfig := &database.LoginDBConfig{
		CollectionName: c.CollectionName,
		Database:       c.Database,
		Iss:            c.Iss,
		Aud:            c.Aud,
	}

	dbConfig.Init()

	routerConfig := &router.Config{
		DBConfig:    dbConfig,
		LoginConfig: (*login_config.Config)(c),
	}

	routerConfig.Init()

}
