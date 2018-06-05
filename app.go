package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"gopkg.in/mgo.v2/bson"

	. "app/config"
	. "app/dao"
	. "app/models"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var config = Config{}
var dao = ContactsDAO{}
var dao2 = UsersDAO{}

type person struct {
	username string
	password string
}

var store = sessions.NewCookieStore([]byte("secretkey"))

// func AuthRequired(handler http.HandlerFunc) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		session, _ := store.Get(r, "session")
// 		_, ok := session.Values["username"]
// 		if !ok {
// 			http.Redirect(w, r, "/", 302)
// 			return
// 		}
// 		handler.ServeHTTP(w, r)
// 	}
// }

// func ApiAuthREquired(handler http.HandlerFunc) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		session, _ := store.Get(r, "session")
// 		_, ok := session.Values["username"]
// 		if !ok {
// 			respondWithJson(w, http.StatusBadRequest, "Invalid token!")
// 			return
// 		}
// 		handler.ServeHTTP(w, r)
// 	}
// }

func ApiAuthRequired(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userToken := r.Header.Get("Authorization")
		if userToken == "" {
			respondWithJson(w, http.StatusBadRequest, "Header authorization is not set!")
			return
		}
		tok, err := r.Cookie("session")
		if err != nil {
			respondWithJson(w, http.StatusBadRequest, "Internal server error!")
			return
		}
		token := tok.Value
		if userToken != token {
			respondWithJson(w, http.StatusBadRequest, "Invalid authorization token!")
			return
		}
		session, _ := store.Get(r, "session")
		u, ok := session.Values["username"]
		if !ok {
			respondWithJson(w, http.StatusBadRequest, "Invalid token!")
			return
		}
		username := u.(string)
		user, err := dao2.FindUser(username)
		if err != nil {
			respondWithJson(w, http.StatusBadRequest, "User authorization is invalid!")
			return
		}

		if user.SessionToken != token {
			respondWithJson(w, http.StatusBadRequest, "Invalid token!")
			return
		}

		handler.ServeHTTP(w, r)
	}
}

func NoCache(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set the headers
		w.Header().Set("Cache-Control", "no-cache, private, max-age=0")
		w.Header().Set("Expires", time.Unix(0, 0).Format(http.TimeFormat))
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("X-Accel-Expires", "0")
		h.ServeHTTP(w, r)
	}
}

// GET list of contacts
func AllContactsEndPoint(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	username, _ := session.Values["username"]
	contacts, err := dao.FindAll(username.(string))
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusOK, contacts)
}

// GET a contact by its ID
// func FindContactEndpoint(w http.ResponseWriter, r *http.Request) {
// 	params := mux.Vars(r)
// 	contact, err := dao.FindById(params["id"])
// 	if err != nil {
// 		respondWithError(w, http.StatusBadRequest, "Invalid Contact ID")
// 		return
// 	}
// 	respondWithJson(w, http.StatusOK, contact)
// }

// GET a contact by its Mobile
func FindContactEndpoint(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	session, _ := store.Get(r, "session")
	username, _ := session.Values["username"]
	contact, err := dao.FindByMobile(params["mobile"], username.(string))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid Contact Mobile")
		return
	}
	respondWithJson(w, http.StatusOK, contact)
}

// POST a new contact
func CreateContactEndPoint(w http.ResponseWriter, r *http.Request) {
	var contact Contact
	r.ParseForm()
	name := r.PostForm.Get("name")
	mobile := r.PostForm.Get("mobile")
	address := r.PostForm.Get("address")
	contact.Name = name
	contact.Mobile = mobile
	contact.Address = address

	session, _ := store.Get(r, "session")
	username, _ := session.Values["username"]
	contact.Username = username.(string)
	// defer r.Body.Close()
	// if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
	// 	respondWithError(w, http.StatusBadRequest, "Invalid request payload")
	// 	return
	// }
	var Name = contact.Name
	var Username = contact.Username
	contact1, err1 := dao.FindByName(Name, Username)
	if err1 == nil {
		respondWithError(w, http.StatusBadRequest, "This name already exists with number "+contact1.Mobile+" !!")
		return
	}
	var Mobile = contact.Mobile
	contact2, err2 := dao.FindByMobile(Mobile, Username)
	if err2 == nil {
		respondWithError(w, http.StatusBadRequest, "This number already exists with name "+contact2.Name+" !!")
		return
	}
	contact.ID = bson.NewObjectId()
	if err := dao.Insert(contact); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusCreated, contact)
	// http.Redirect(w, r, "/index", 302)
}

// PUT update an existing contact
func UpdateContactEndPoint(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var contact Contact
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	session, _ := store.Get(r, "session")
	username, _ := session.Values["username"]
	contact.Username = username.(string)
	if err := dao.Update(contact); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusOK, map[string]string{"result": "success"})
}

// DELETE an existing contact
func DeleteContactEndPoint(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var contact Contact
	if err := json.NewDecoder(r.Body).Decode(&contact); err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	id := contact.ID.Hex()
	contact2, _ := dao.FindById(id)
	if err := dao.Delete(contact2); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusOK, map[string]string{"result": "success"})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	respondWithJson(w, code, map[string]string{"error": msg})
}

func respondWithJson(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}

// Parse the configuration file 'config.toml', and establish a connection to DB
func init() {
	config.Read()

	dao.Server = config.Server
	dao.Database = config.Database
	dao.Connect()
	dao2.Server = config.Server
	dao2.Database = config.Database
	dao2.Connect2()
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// b, err := ioutil.ReadAll(r.Body)
	// defer r.Body.Close()
	// fmt.Println("req", r)
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	// var userperson person
	// err = json.Unmarshal(b, &userperson)
	// if err != nil {
	// 	http.Error(w, err.Error(), 500)
	// 	return
	// }
	// output, err := json.Marshal(userperson)
	// if err != nil {
	// 	http.Error(w, err.Error(), 500)
	// 	return
	// }
	// fmt.Println("b", b)
	// if r.Body == nil {
	// 	http.Error(w, "Please send a request body", 400)
	// 	return
	// }
	// fmt.Println("body", r.Body)
	// if err := json.NewDecoder(r.Body).Decode(&userperson); err != nil {
	// 	fmt.Println("err", err)
	// 	respondWithError(w, http.StatusBadRequest, "Invalid request payload")
	// 	return
	// }

	// fmt.Println("@@@@@@@@", userperson.username)
	var user User
	user, err := dao2.FindUser(username)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "User not registered.")
		return
	}
	hash := []byte(user.Password)

	err = bcrypt.CompareHashAndPassword(hash, []byte(password))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid password, Please try again.")
		return
	}
	session, _ := store.Get(r, "session")
	session.Values["username"] = username
	session.Save(r, w)

	// fmt.Println("id", session)
	// fmt.Println("###", w)
	// fmt.Println("res", w.Header().Get("Set-Cookie")[8:164])
	token := w.Header().Get("Set-Cookie")[8:164]
	user.SessionToken = token
	// fmt.Println("user", user)
	if err := dao2.Update(user); err != nil {
		// fmt.Println("err", err)
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusOK, user)
	// http.Redirect(w, r, "/index", 302)
}

func registerPostHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	confirmPass := r.PostForm.Get("confirmPass")
	if password != confirmPass {
		respondWithError(w, http.StatusBadRequest, "Confirm password is not same as password!")
		return
	}
	_, err := dao2.FindUser(username)
	if err == nil {
		respondWithError(w, http.StatusBadRequest, "User already registered.")
		return
	}
	cost := bcrypt.DefaultCost
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return
	}
	// n := bytes.Index(hash, []byte{0})
	// n := bytes.IndexByte(hash, 0)
	n := len(hash)
	s := string(hash[:n])
	// p := person{username: username, password: s}
	var user User
	user.ID = bson.NewObjectId()
	user.UserName = username
	user.Password = s
	// fmt.Println(p, user)
	if err := dao2.Insert(user); err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondWithJson(w, http.StatusCreated, user)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session")
	username, ok := session.Values["username"]
	if !ok {
		respondWithJson(w, http.StatusBadRequest, "No such session is present!")
		return
	}
	var user User
	user, err := dao2.FindUser(username.(string))
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Internal Server Error!")
		return
	}
	user.SessionToken = ""
	if err := dao2.Update(user); err != nil {
		fmt.Println("err", err)
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}
	delete(session.Values, "username")
	session.Options.MaxAge = -1
	_ = session.Save(r, w)
	respondWithJson(w, http.StatusOK, "logged out successfully!")
}

// func testGetHandler(w http.ResponseWriter, r *http.Request) {
// 	session, _ := store.Get(r, "session")
// 	untyped, ok := session.Values["username"]
// 	if !ok {
// 		return
// 	}
// 	username, ok := untyped.(string)
// 	if !ok {
// 		return
// 	}
// 	w.Write([]byte(username))
// }

// Define HTTP request routes
func main() {
	r := mux.NewRouter()
	r.HandleFunc("/contacts", ApiAuthRequired(AllContactsEndPoint)).Methods("GET")
	r.HandleFunc("/contacts", ApiAuthRequired(CreateContactEndPoint)).Methods("POST")
	r.HandleFunc("/contacts", ApiAuthRequired(UpdateContactEndPoint)).Methods("PUT")
	r.HandleFunc("/contacts", ApiAuthRequired(DeleteContactEndPoint)).Methods("DELETE")
	r.HandleFunc("/contacts/{mobile}", ApiAuthRequired(FindContactEndpoint)).Methods("GET")
	r.HandleFunc("/login", loginPostHandler).Methods("POST")
	r.HandleFunc("/register", registerPostHandler).Methods("POST")
	r.HandleFunc("/logout", ApiAuthRequired(LogoutHandler)).Methods("GET")
	if err := http.ListenAndServe(":3000", r); err != nil {
		log.Fatal(err)
	}
}
