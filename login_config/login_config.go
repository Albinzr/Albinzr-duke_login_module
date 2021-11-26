package login_config

import "go.mongodb.org/mongo-driver/mongo"

type Config struct {
	Database               *mongo.Database
	CollectionName         string
	Aud                    string
	Iss                    string
	SecretKey              string
	ForgotPasswordCallback func(emailId string, token string)
}
