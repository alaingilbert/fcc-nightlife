package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/JustinBeckwith/go-yelp/yelp"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo"
	"github.com/labstack/gommon/log"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/twitter"
	"github.com/urfave/cli"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var yelpClient *yelp.Client

type H map[string]interface{}

var session *mgo.Session
var authTokenCookieName = "auth-token"
var dbname string

type Template struct {
	templates *template.Template
}

type User struct {
	ID                 bson.ObjectId `bson:"_id"`
	NickName           string
	TwitterID          string
	SessionKey         string
	TwitterAccessToken string
	TwitterAvatarURL   string
	Name               string
}

type Business struct {
	ID     bson.ObjectId `bson:"_id"`
	YelpID string
	Going  []string
}

func (b *Business) IsUserGoing(userID string) int {
	isGoing := -1
	for idx, id := range b.Going {
		if id == userID {
			isGoing = idx
			break
		}
	}
	return isGoing
}

func (b *Business) AddUser(userID string) {
	if b.IsUserGoing(userID) == -1 {
		b.Going = append(b.Going, userID)
	}
}

func (b *Business) RemoveUser(userID string) {
	goingIdx := b.IsUserGoing(userID)
	if goingIdx > -1 {
		b.Going = append(b.Going[:goingIdx], b.Going[goingIdx+1:]...)
	}
}

func (b *Business) ToggleUser(userID string) {
	goingIdx := b.IsUserGoing(userID)
	if goingIdx > -1 {
		b.RemoveUser(userID)
	} else {
		b.AddUser(userID)
	}
}

func (t *Template) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	var files []string
	files = append(files, "templates/base.html")
	files = append(files, fmt.Sprintf("templates/%s.html", name))
	tmpl := template.Must(template.ParseFiles(files...))
	return tmpl.Execute(w, data)
}

func getYelpBusinessesIDs(yelpBusinesses []yelp.Business) []string {
	var ids []string
	for _, business := range yelpBusinesses {
		ids = append(ids, business.ID)
	}
	return ids
}

func mainHandler(c echo.Context) error {
	location := strings.Trim(c.QueryParam("location"), " \r\t\n")
	user := c.Get("user").(User)
	var yelpBusinesses []yelp.Business
	var businesses []Business
	var tmp []H
	data := H{"businesses": tmp, "location": location, "user": user, "goings": businesses}
	if location != "" {
		results, err := yelpClient.DoSimpleSearch("bar", location)
		if err != nil {
			fmt.Println("Failed to search yelp", err)
			return c.Render(200, "index", data)
		}
		yelpBusinesses = results.Businesses
		yelpBusinessesIDs := getYelpBusinessesIDs(yelpBusinesses)
		s := session.Copy()
		defer s.Close()
		businessesCollection := s.DB(dbname).C("businesses")
		businessesCollection.Find(bson.M{"yelpid": bson.M{"$in": yelpBusinessesIDs}}).All(&businesses)
		data["going"] = businesses
		for _, yb := range yelpBusinesses {
			tmp1 := H{"yb": yb}
			for _, b := range businesses {
				if b.YelpID == yb.ID {
					tmp1["going"] = len(b.Going)
					found := false
					for _, g := range b.Going {
						if g == user.TwitterID {
							found = true
							break
						}
					}
					tmp1["you_going"] = found
					break
				}
			}
			tmp = append(tmp, tmp1)
		}
		data["businesses"] = tmp
	}
	return c.Render(200, "index", data)
}

func goingHandler(c echo.Context) error {
	location := c.FormValue("location")
	businessID := c.FormValue("business_id")
	user := c.Get("user").(User)
	s := session.Copy()
	defer s.Close()
	businessesCollection := s.DB(dbname).C("businesses")
	var business Business
	if err := businessesCollection.Find(bson.M{"yelpid": businessID}).One(&business); err != nil {
		business.ID = bson.NewObjectId()
		business.YelpID = businessID
		business.Going = append(business.Going, user.TwitterID)
		if err := businessesCollection.Insert(business); err != nil {
			fmt.Println("failed to create business", err)
		}
		return c.Redirect(303, fmt.Sprintf("/?location=%s", location))
	} else {
		business.ToggleUser(user.TwitterID)
		if err := businessesCollection.Update(bson.M{"_id": business.ID}, bson.M{"$set": bson.M{"going": business.Going}}); err != nil {
			fmt.Println(err)
			return c.String(500, "Failed to update your profile")
		}
	}
	return c.Redirect(303, fmt.Sprintf("/?location=%s", location))
}

func NewUserFromGothUser(gothUser goth.User) *User {
	u := new(User)
	u.ID = bson.NewObjectId()
	u.NickName = gothUser.NickName
	u.TwitterID = gothUser.UserID
	u.SessionKey = ""
	u.TwitterAccessToken = gothUser.AccessToken
	u.TwitterAvatarURL = gothUser.AvatarURL
	u.Name = gothUser.Name
	return u
}

func GenerateToken() string {
	// This error can safely be ignored.
	// Only crash when year is outside of [0,9999]
	key, _ := time.Now().MarshalText()
	token := hex.EncodeToString(hmac.New(sha256.New, key).Sum(nil))
	return token
}

func authTwitterHandler(c echo.Context) error {
	// try to get the user without re-authenticating
	res := c.Response()
	req := c.Request()
	location := c.QueryParam("location")
	if user, err := gothic.CompleteUserAuth(res, req); err == nil {
		s := session.Copy()
		defer s.Close()
		token := GenerateToken()
		usersCollection := s.DB(dbname).C("users")
		if err := usersCollection.Update(bson.M{"twitterid": user.UserID}, bson.M{"$set": bson.M{"sessionkey": token}}); err != nil {
			u := NewUserFromGothUser(user)
			u.SessionKey = token
			if err := usersCollection.Insert(*u); err != nil {
				if !mgo.IsDup(err) {
					return err
				}
			}
		}
		cookie := http.Cookie{Name: authTokenCookieName, Value: token, Path: "/"}
		c.SetCookie(&cookie)
		return c.Redirect(303, fmt.Sprintf("/?location=%s", location))
	} else {
		cookie := http.Cookie{Name: "callback-location", Value: location, Path: "/"}
		c.SetCookie(&cookie)
		gothic.BeginAuthHandler(res, req)
		return nil
	}
}

func authTwitterCallbackHandler(c echo.Context) error {
	gothUser, err := gothic.CompleteUserAuth(c.Response(), c.Request())
	if err != nil {
		return err
	}
	s := session.Copy()
	defer s.Close()
	token := GenerateToken()
	usersCollection := s.DB(dbname).C("users")
	if err := usersCollection.Update(bson.M{"twitterid": gothUser.UserID}, bson.M{"$set": bson.M{"sessionkey": token}}); err != nil {
		u := NewUserFromGothUser(gothUser)
		u.SessionKey = token
		if err := usersCollection.Insert(*u); err != nil {
			if !mgo.IsDup(err) {
				return err
			}
		}
	}
	cookie := http.Cookie{Name: authTokenCookieName, Value: token, Path: "/"}
	c.SetCookie(&cookie)
	locationCookie, _ := c.Cookie("callback-location")
	return c.Redirect(303, fmt.Sprintf("/?location=%s", locationCookie.Value))
}

func logoutHandler(c echo.Context) error {
	cookie1 := &http.Cookie{
		Name:   fmt.Sprintf("twitter%s", gothic.SessionName),
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	}
	c.SetCookie(cookie1)
	location := c.QueryParam("location")
	cookie := http.Cookie{Name: authTokenCookieName, Value: "", Path: "/"}
	c.SetCookie(&cookie)
	return c.Redirect(302, fmt.Sprintf("/?location=%s", location))
}

func ensureIndex() {
	s := session.Copy()
	defer s.Close()
	usersCollection := s.DB(dbname).C("users")
	index := mgo.Index{
		Key:        []string{"twitterid"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	if err := usersCollection.EnsureIndex(index); err != nil {
		panic(err)
	}
	businessesCollection := s.DB(dbname).C("besinesses")
	index = mgo.Index{
		Key:        []string{"yelpid"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
	if err := businessesCollection.EnsureIndex(index); err != nil {
		panic(err)
	}
}

// IsAuthMiddleware will ensure user is authenticated.
// - Find user from context
// - If user is empty, redirect to home
func IsAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		user := c.Get("user").(User)
		if user.TwitterID == "" {
			return c.Redirect(302, "/")
		}
		return next(c)
	}
}

// SetUserMiddleware Get user and put it into echo context.
// - Get auth-token from cookie
// - If exists, get user from database
// - If found, set user in echo context
// - Otherwise, empty user will be put in context
func SetUserMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		var user User
		authCookie, err := c.Cookie(authTokenCookieName)
		if err != nil {
			c.Set("user", user)
			return next(c)
		}
		s := session.Copy()
		defer s.Close()
		usersCollection := s.DB(dbname).C("users")
		if err := usersCollection.Find(bson.M{"sessionkey": authCookie.Value}).One(&user); err != nil {
		}
		c.Set("user", user)
		return next(c)
	}
}

func getProvider(req *http.Request) (string, error) {
	return "twitter", nil
}

func start(c *cli.Context) error {
	goth.UseProviders(
		twitter.NewAuthenticate(os.Getenv("TWITTER_KEY"), os.Getenv("TWITTER_SECRET"), os.Getenv("TWITTER_CALLBACK")),
	)
	gothic.Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	gothic.GetProviderName = getProvider

	dbname = os.Getenv("MONGODB_DBNAME")
	var err error
	session, err = mgo.Dial(os.Getenv("MONGODB_URI"))
	if err != nil {
		return err
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)
	ensureIndex()

	options := &yelp.AuthOptions{
		ConsumerKey:       os.Getenv("YELP_CONSUMER_KEY"),
		ConsumerSecret:    os.Getenv("YELP_CONSUMER_SECRET"),
		AccessToken:       os.Getenv("YELP_TOKEN"),
		AccessTokenSecret: os.Getenv("YELP_TOKEN_SECRET"),
	}
	yelpClient = yelp.New(options, nil)

	t := &Template{}
	e := echo.New()
	e.Renderer = t
	e.Debug = true
	e.Logger.SetLevel(log.INFO)
	e.Use(SetUserMiddleware)
	e.GET("/", mainHandler)
	e.GET("/auth/twitter", authTwitterHandler)
	e.GET("/auth/twitter/callback", authTwitterCallbackHandler)
	e.GET("/logout", logoutHandler)

	needAuthGroup := e.Group("")
	needAuthGroup.Use(IsAuthMiddleware)
	needAuthGroup.POST("/going", goingHandler)
	port := c.Int("port")
	e.Logger.Fatal(e.Start(fmt.Sprintf(":%d", port)))

	return nil
}

func main() {
	app := cli.NewApp()
	app.Author = "Alain Gilbert"
	app.Email = "alain.gilbert.15@gmail.com"
	app.Name = "FCC nightlife app"
	app.Usage = "FCC nightlife app"
	app.Version = "0.0.1"
	app.Flags = []cli.Flag{
		cli.IntFlag{
			Name:   "port",
			Value:  3001,
			Usage:  "Webserver port",
			EnvVar: "PORT",
		},
	}
	app.Action = start
	app.Run(os.Args)
}
