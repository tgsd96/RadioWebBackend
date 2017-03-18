package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	_ "github.com/go-sql-driver/mysql"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
)

var database *sql.DB

type Signin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Message string `json:"message"`
}

type User struct {
	First    string `json:"first"`
	Last     string `json:"last"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Prof     string `json:"prof"`
}
type Users struct {
	Users []User `json:"users"`
}

const (
	serverName   = "localhost"
	SSLport      = ":433"
	HTTPport     = ":8080"
	SSLprotocol  = "https://"
	HTTPprotocol = "http://"
)

func StartServer() {
	//Exported function
	db, err := sql.Open("mysql", "root:!lscd@/RadioWeb_Dev")
	if err != nil {

	}
	database = db
}

func parsePost(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	decoder := json.NewDecoder(r.Body)

	var t Signin
	err := decoder.Decode(&t)

	if err != nil {
		fmt.Printf("Error occurred %s", err.Error())
	}
	fmt.Println(t.Username)
	var user User
	var response Response
	database.QueryRow("Select password from Users where email='" + t.Username + "';").Scan(&user.Password)
	fmt.Printf("\nThe username is: " + user.Password)
	if t.Password == user.Password {
		response.Message = "Correct Password"
	} else {
		response.Message = "Incorrect Password"
	}
	output, _ := json.Marshal(response)
	fmt.Fprint(w, string(output))
}

func createUser(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var newUser User
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&newUser)
	if err != nil {
		fmt.Println("There was this error : " + err.Error())
	}
	var response Response
	sql := "Insert into Users SET email='" +
		newUser.Email +
		"',first='" + newUser.First +
		"',last='" + newUser.Last +
		"',password='" + newUser.Password +
		"',salt='we232d', Prof='" + newUser.Prof + "';"
	q, err := database.Exec(sql)
	if err != nil {
		response.Message = err.Error()
	} else {
		response.Message = "Success"
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
	router.GET("/api/view", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "Hello,world")
	})
	handler := cors.Default().Handler(router)
	log.Fatal(http.ListenAndServeTLS(":"+os.Getenv("PORT"), "./cert.pem", "./key.pem", handler))
	fmt.Println("How are you?")
}
