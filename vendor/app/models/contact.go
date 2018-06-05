package models

import "gopkg.in/mgo.v2/bson"

// Represents a contact, we uses bson keyword to tell the mgo driver how to name
// the properties in mongodb document
type Contact struct {
	ID       bson.ObjectId `bson:"_id" json:"id"`
	Name     string        `bson:"name" json:"name"`
	Mobile   string        `bson:"mobile" json:"mobile"`
	Address  string        `bson:"address" json:"address"`
	Username string        `bson:"username" json:"username"`
}
