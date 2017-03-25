package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"io/ioutil"
	Password "password"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
)

var database *sql.DB
var secretKey = []byte("5gjZ7caBbn58J0MqSA3tBiR3OTNTnIKjzIizDJkHTELz8yo4IHyOuUBUUWTkeJ6g7mRjO7Idl98JElbukkYiUOSR7RcJuavxEW7G")

type Signin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Message  string `json:"message"`
	Token    string `json:"token"`
	Username string `json:"username"`
}
type request struct {
	Token string `json:"token"`
}

type User struct {
	ID       int64  `json:"first"`
	First    string `json:"first"`
	Last     string `json:"last"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Prof     string `json:"prof"`
	Salt     string `json:"salt"`
}
type Users struct {
	Users []User `json:"users"`
}
type config struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Db       string `json:"db"`
}

type Datasets struct {
	Datasets []Dataset `json:"datasets"`
}

type Dataset struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Desc string `json:"description"`
	URL  string `json:"datasetUrl"`
	Cost string `json:"cost"`
	Date string `json:"date"`
}

const (
	serverName   = "localhost"
	SSLport      = ":433"
	HTTPport     = ":8080"
	SSLprotocol  = "https://"
	HTTPprotocol = "http://"
)

func StartServer() {

	//use config file
	file, err := ioutil.ReadFile("/etc/radioweb/configurations.json")
	if err != nil {
		db, err := sql.Open("mysql", "root:@/RadioWeb_Dev")
		database = db
		if err != nil {
			fmt.Printf("Error while connecting to db: %s", err.Error())
		}
	} else {
		var dbconfig config
		json.Unmarshal(file, &dbconfig)
		// fmt.Printf("%v\n", dbconfig)
		db, err := sql.Open("mysql", dbconfig.User+":"+dbconfig.Password+"@/"+dbconfig.Db)
		if err != nil {
			fmt.Printf("Error while connecting to db: %s", err.Error())
		}
		database = db
	}

	//Exported function

}
func decryptToken(getToken string) int64 {
	token, _ := jwt.Parse(getToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return secretKey, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["uid"])
		id, err := claims["uid"].(int64)
		if err != true {
			fmt.Println("Error reading claims")
		}
		return id
		// return int64(id)
		// fmt.Println(claims["uid"])
	}
	return -1
}

func redirectNonSecure(w http.ResponseWriter, r *http.Request) {
	log.Println("Non-secure request initiated, redirecting.")
	redirectURL := "https://" + serverName + r.RequestURI
	// log.Println(redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)

}
func getToken(userid int64) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid": userid,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Second * 3600 * 24).Unix(),
	})
	jwtToken, err := token.SignedString(secretKey)
	if err != nil {

	}
	return jwtToken
}
func returnDatasetList(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Printf("\n Requess for datasets found")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	token := r.Header.Get("Authorization")
	// token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0OTAzMDI4MzYsImlhdCI6MTQ5MDIxNjQzNiwidWlkIjo1fQ.E_6tzzQCLtJ1dlFMWLTP8VgH4B8qD9kia9v1iepeP9E"
	uid := decryptToken(token)
	if uid == -1 {
		var response Response
		response.Message = "Retry login"
		output, _ := json.Marshal(response)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, string(output))
		// fmt.Fprintf(w, "Retry login")
	} else {
		rows, err := database.Query("select * from availDatasets")
		if err != nil {
			fmt.Printf("\n Error quering database %s", err.Error())
		}
		Response := Datasets{}
		for rows.Next() {
			dataset := Dataset{}
			rows.Scan(&dataset.ID, &dataset.Name, &dataset.Desc, &dataset.URL, &dataset.Cost, &dataset.Date)
			Response.Datasets = append(Response.Datasets, dataset)
		}

		output, _ := json.Marshal(Response)
		fmt.Fprintln(w, string(output))
	}

}

func storeImages(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {

}
func parsePost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	decoder := json.NewDecoder(r.Body)

	var t Signin
	err := decoder.Decode(&t)

	if err != nil {
		fmt.Printf("Error occurred %s", err.Error())
	}
	// fmt.Println(t.Username)
	var user User
	var response Response
	database.QueryRow("Select id,email,password,salt from Users where email='"+t.Username+"';").Scan(&user.ID, &user.Email, &user.Password, &user.Salt)
	hash := Password.GenerateHash(user.Salt, t.Password)
	if hash == user.Password {
		fmt.Printf("\nThe username is: %s\n ", user.Email)
		response.Message = "Correct Password"
		response.Token = getToken(user.ID)
		fmt.Printf("The token is %s", response.Token)
		response.Username = user.Email

	} else {
		response.Message = "Incorrect Password"
		response.Token = ""
	}
	output, _ := json.Marshal(response)
	w.Header().Set("Access-Control-Allow-Origin", "*")
	fmt.Fprint(w, string(output))
}

func parseToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	log.Println("Checking Token")
	var req request
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		fmt.Println("There was error : " + err.Error())
	}
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return secretKey, nil
	})
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		fmt.Println(claims["uid"])
	} else {
		fmt.Println(err)
	}
	fmt.Fprintf(w, "HAHA")
}

func createUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var newUser User
	var getUser User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&newUser)
	if err != nil {
		fmt.Println("There was this error : " + err.Error())
	}
	var response Response
	salt, password := Password.ReturnPassword(newUser.Password)
	sql := "Insert into Users SET email='" +
		newUser.Email +
		"',first='" + newUser.First +
		"',last='" + newUser.Last +
		"',password='" + password +
		"',salt='" + salt + "', prof='" + newUser.Prof + "';"
	q, err := database.Exec(sql)
	if err != nil {
		fmt.Printf("Error creating user: %s", err.Error())
		response.Message = err.Error()
		response.Token = ""
	} else {
		database.QueryRow("Select id from Users where email='" + newUser.Email + "';").Scan(&getUser.ID)
		response.Message = "Success"
		response.Token = getToken(getUser.ID)
		response.Username = newUser.Email
	}
	fmt.Println(q)
	output, _ := json.Marshal(response)
	fmt.Fprintln(w, string(output))
}

//the main server
func main() {
	StartServer()
	router := httprouter.New()
	router.POST("/api/test", parsePost)
	router.POST("/api/register", createUser)
	router.GET("/api/datasets", returnDatasetList)
	router.POST("/api/token", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "Hello,world")
	})
	router.GET("/api/view", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "Hello,world")
	})
	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"Authorization"},
		AllowedHeaders:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowCredentials: true,
	})
	// handler := cors.Default()
	handle := handler.Handler(router)
	log.Fatal(http.ListenAndServeTLS(":8080", "./cert.pem", "./key.pem", handle))
}
