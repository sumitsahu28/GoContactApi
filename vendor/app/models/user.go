package models

import "gopkg.in/mgo.v2/bson"

// Represents a User, we uses bson keyword to tell the mgo driver how to name
// the properties in mongodb document
type User struct {
	ID           bson.ObjectId `bson:"_id" json:"id"`
	UserName     string        `bson:"username" json:"username"`
	Password     string        `bson:"password" json:"password"`
	SessionToken string        `bson:"sessiontoken" json:"sessiontoken"`
}
