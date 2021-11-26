package router

import (
	"errors"
	"fmt"
	"github.com/Albinzr/duke_login_module/database"
	"github.com/Albinzr/duke_login_module/helpers"
	"github.com/Albinzr/duke_login_module/login_config"
	"github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"time"
)

type Config struct {
	DBConfig    *database.LoginDBConfig
	LoginConfig *login_config.Config
}

func (c *Config) Init() {
	http.HandleFunc("/login", c.loginHandler)
	http.HandleFunc("/signup", c.signUpHandler)
	http.HandleFunc("/resetPassword", c.resetPasswordHandler)
	http.HandleFunc("/forgotPassword", c.forgotPasswordHandler)
}

func (c *Config) loginHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := req.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		resp := util.ErrorResponse("invalid param", "login not valid", err)
		_, _ = w.Write(resp)
		return
	}
	username := req.Form.Get("username")
	password := req.Form.Get("password")
	util.LogInfo(username, password)
	userInfo, err := c.DBConfig.FindUser(username)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		resp := util.ErrorResponse("invalid access", "login not valid", err)
		_, _ = w.Write(resp)
		return
	}

	hashPassword := []byte(userInfo["password"].(string))

	if !isPasswordValid(hashPassword, []byte(password)) {
		w.WriteHeader(http.StatusUnauthorized)
		resp := util.ErrorResponse("invalid access", "not matching", nil)
		_, _ = w.Write(resp)
		return
	}

	objId := userInfo["_id"].(primitive.ObjectID)
	validToken, err := c.getJWT(username, objId)

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		resp := util.ErrorResponse("please try after sometime", "Failed to generate token", err)
		_, _ = w.Write(resp)
		return
	}

	data := `{
			"id":"` + objId.Hex() + `",
			"username":"` + userInfo["username"].(string) + `",
			"token":"` + validToken + `"
			}`
	resp := util.SuccessResponse(data)
	_, _ = w.Write(resp)
}

func (c *Config) signUpHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	err := req.ParseForm()
	if err != nil {
		resp := util.ErrorResponse("invalid param", "param is not valid", err)
		_, _ = w.Write(resp)
		return
	}
	username := req.Form.Get("username")
	password := req.Form.Get("password")
	emailId := req.Form.Get("emailId")

	if len(username) < 4 && len(password) < 8 && len(emailId) < 5 {
		w.WriteHeader(http.StatusBadRequest)
		resp := util.ErrorResponse("incomplete data", "param is not valid", nil)
		_, _ = w.Write(resp)
		return
	}
	user := database.User{}
	user.Username = username
	user.EmailId = emailId
	user.Password = getHash([]byte(password))
	objId, err := c.DBConfig.CreateUser(user)

	if err != nil {
		util.LogError("", err)
		w.WriteHeader(http.StatusBadRequest)
		resp := util.ErrorResponse("please try after sometime", "unable to create user in db", err)
		_, _ = w.Write(resp)
		return
	}

	util.LogInfo(user.Password)
	user.Password = getHash([]byte(user.Password))
	validToken, err := c.getJWT(username, objId)
	fmt.Println(validToken)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		resp := util.ErrorResponse("please try after sometime", "Failed to generate token", err)
		_, _ = w.Write(resp)
		return
	}
	resp := util.SuccessResponse(`{"token":"` + string(validToken) + `"}`)
	_, _ = w.Write(resp)
	return
}

func (c *Config) resetPasswordHandler(w http.ResponseWriter, req *http.Request) {
	fmt.Print("in 1")
	w.Header().Set("Content-Type", "application/json")
	err := req.ParseForm()
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		resp := util.ErrorResponse("invalid param", "login not valid", err)
		_, _ = w.Write(resp)
		return
	}
	tokenString := req.Form.Get("token")
	password := req.Form.Get("password")
	if len(password) < 8 {
		w.WriteHeader(http.StatusUnauthorized)
		resp := util.ErrorResponse("invalid password", "not a strong password", err)
		_, _ = w.Write(resp)
		return
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return c.LoginConfig.SecretKey, nil
	})

	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		resp := util.ErrorResponse("invalid token", "token not valid", err)
		_, _ = w.Write(resp)
		return
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	emailId := claims["emailId"].(string)

	if c.DBConfig.IsUserValid(emailId) {
		passwordHash := getHash([]byte(password))
		if c.DBConfig.UpdatePassword(emailId, passwordHash) {
			resp := util.SuccessResponse(`{"response":"password successfully"}`)
			_, _ = w.Write(resp)
		}
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		resp := util.ErrorResponse("invalid emailId", "not a valid emailId", err)
		_, _ = w.Write(resp)
		return
	}

}

func (c *Config) forgotPasswordHandler(w http.ResponseWriter, req *http.Request) {

	w.Header().Set("Content-Type", "application/json")
	err := req.ParseForm()
	if err != nil {
		resp := util.ErrorResponse("invalid param", "param incorrect", err)
		_, _ = w.Write(resp)
		return
	}
	emailId := req.Form.Get("emailId")
	util.LogInfo(emailId, "====>")
	if c.DBConfig.IsUserValid(emailId) {
		token, err := c.resetToken(emailId)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			resp := util.ErrorResponse("please try after sometime", "Failed to generate token", err)
			_, _ = w.Write(resp)
		}

		c.LoginConfig.ForgotPasswordCallback(emailId, token)
		resp := util.SuccessResponse("null")
		_, _ = w.Write(resp)
		return
	} else {
		resp := util.ErrorResponse("invalid emailId", "emailId not found", nil)
		_, _ = w.Write(resp)
		return
	}

}

///-------------------///

func (c *Config) getJWT(username string, userId primitive.ObjectID) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["username"] = username
	claims["userId"] = userId
	claims["aud"] = c.DBConfig.Aud
	claims["iss"] = c.DBConfig.Iss
	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()

	tokenString, err := token.SignedString(c.LoginConfig.SecretKey)

	if err != nil {
		util.LogError("Something Went Wrong:", err)
		return "", err
	}

	return tokenString, nil
}

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		util.LogError("could not creat hash", err)
	}
	return string(hash)
}

func isPasswordValid(hash []byte, password []byte) bool {
	if bcrypt.CompareHashAndPassword(hash, password) != nil {
		return false
	}
	return true
}

func (c *Config) resetToken(emailId string) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["emailId"] = emailId
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	tokenString, err := token.SignedString(c.LoginConfig.SecretKey)
	if err != nil {
		util.LogError("Something Went Wrong:", err)
		return "", err
	}
	return tokenString, nil
}
