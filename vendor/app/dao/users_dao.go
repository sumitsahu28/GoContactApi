package dao

import (
	"fmt"
	"log"

	. "app/models"

	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type UsersDAO struct {
	Server   string
	Database string
}

var db2 *mgo.Database

const (
	COLLECTION2 = "users"
)

// Establish a connection to database
func (m *UsersDAO) Connect2() {
	session, err := mgo.Dial(m.Server)
	if err != nil {
		log.Fatal(err)
	}
	db2 = session.DB(m.Database)
}

// Find a user by its username
func (m *UsersDAO) FindUser(username string) (User, error) {
	var user User
	err := db2.C(COLLECTION2).Find(bson.M{"username": username}).One(&user)
	return user, err
}

// Insert a user into database
func (m *UsersDAO) Insert(user User) error {
	err := db2.C(COLLECTION2).Insert(&user)
	fmt.Println("erroooooo", err)
	return err
}

// Upadate a user database
func (m *UsersDAO) Update(user User) error {
	fmt.Println("ID", user.ID)
	fmt.Println("#####", &user)
	err := db2.C(COLLECTION2).UpdateId(user.ID, &user)
	return err
}
