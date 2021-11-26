package duke_login_module

import (
	"fmt"
	"testing"

	"go.mongodb.org/mongo-driver/mongo"
)

var config = &Config{
	Database:               &mongo.Database{}, //change to db instance
	CollectionName:         "user_test",
	Aud:                    "billing.login_test.com",
	Iss:                    "login_test.com",
	ForgotPasswordCallback: resetPasswordEmail,
}

func TestHello(t *testing.T) {
	fmt.Println("hi")
	config.Init()
}

func resetPasswordEmail(emailId string, url string) {
	fmt.Println(emailId, "----->", url)
}
