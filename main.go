/**
	Main server - API implementation in golang.
		TODO : Implement Graceful server
		TODO : Provide Better responses on invalid requests
 */

package main

// Imports
import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"io/ioutil"
	Password "password"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/julienschmidt/httprouter"
	"github.com/rs/cors"
)

/*
 *	Configurations- TODO: change for production
 */
var database *sql.DB
var secretKey = []byte("5gjZ7caBbn58J0MqSA3tBiR3OTNTnIKjzIizDJkHTELz8yo4IHyOuUBUUWTkeJ6g7mRjO7Idl98JElbukkYiUOSR7RcJuavxEW7G")
var configDir = "/etc/radioweb/"
var configFile = "configurations.json"


/*
 *	Structures - Defines various structures, some of which are required for the JSON parsing
 *	TODO : Refactor the structures to a different file
 */

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

// Some constants
const (
	serverName   = "localhost"
	SSLport      = ":433"
	HTTPport     = ":8080"
	SSLprotocol  = "https://"
	HTTPprotocol = "http://"
)

//===================Helper Functions=====================================================================

/*
 *	Run configurations before starting server
 */
func runConfig() {

	//use config file
	file, err := ioutil.ReadFile(configDir+configFile)
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
}

/*
 *	Function to return a jwt token by storing the user id in it and then encrypting
 *	it with secret key
 */

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

/*
 *	Helper function to decrypt a jwt token based on the secret key
 */
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
			//fmt.Println("Error reading claims")
		}
		return id
	}
	return -1
}

//============================API Endpoints==============================================================

/*
 *  register() - Register a user based on http requests
 */
func register(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
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

/*
 *	Login() - Login users with a combination of username and password.
 */
func login(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
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
/*
 *	sendDataset() - Send the list of available dataset
 */
func sendDataset(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	//fmt.Printf("")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	token := r.Header.Get("Authorization")
	// token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0OTAzMDI4MzYsImlhdCI6MTQ5MDIxNjQzNiwidWlkIjo1fQ.E_6tzzQCLtJ1dlFMWLTP8VgH4B8qD9kia9v1iepeP9E"
	uid := decryptToken(token)
	if uid == -1 {
		fmt.Println("Wrong token sent, returning error message.")
		var response Response
		response.Message = "Retry login"
		output, _ := json.Marshal(response)
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, string(output))
		// fmt.Fprintf(w, "Retry login")
	} else {
		fmt.Printf("Request for datasets by userId : %d", uid)
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

/*
 *	upload() - upload dataset
 */

func upload(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Println("Upload encountered!")
	fmt.Fprintf(w, "Recieved files :P")
	err := r.ParseMultipartForm(10000)
	if err != nil {
		log.Fatal("Error")
		fmt.Println("Error occured during parsing the request")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	m := r.MultipartForm
	files := m.File["dataset"]
	for i := range files {
		file, err := files[i].Open()
		defer file.Close()
		if err != nil {
			fmt.Println("Error occured during parsing file")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		dst, err := os.Create(files[i].Filename)
		defer dst.Close()
		fmt.Printf("\nSaving file, %s ", files[i].Filename)
		if _, err := io.Copy(dst, file); err != nil {
			fmt.Printf("Error occured during saving the file : %s", err.Error())
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	var message Response
	message.Message = "Uploaded image"
	resp, _ := json.Marshal(message)
	fmt.Fprintf(w, string(resp))
}

/*
 *	Unused function.
 *	TODO : Implement better https
 */
func _(w http.ResponseWriter, r *http.Request) {
	log.Println("Non-secure request initiated, redirecting.")
	redirectURL := "https://" + serverName + r.RequestURI
	// log.Println(redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusMovedPermanently)

}

//the main server
func main() {
	runConfig()
	router := httprouter.New()

	// Routes ------
	router.POST("/api/test", login)
	router.POST("/api/register", register)
	router.GET("/api/datasets", sendDataset)
	router.POST("/api/token", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "Hello,world")
	})
	router.POST("/api/upload", upload)
	router.GET("/api/view", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		fmt.Fprintf(w, "Hello,world")
	})

	// Allow Cross Origin requests
	handler := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedHeaders:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowCredentials: true,
	})
	// handler := cors.Default()
	handle := handler.Handler(router)
	fmt.Println("Starting server at https://localhost:8080")
	log.Fatal(http.ListenAndServeTLS(HTTPport, "./cert.pem", "./key.pem", handle))
}
