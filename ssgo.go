package main

import (
    "log"
    "bytes"
    "encoding/json"
    "net/http"
    "html/template"
    "code.google.com/p/go.crypto/bcrypt"
    "github.com/gorilla/mux"
    "github.com/gorilla/sessions"
    "database/sql"
    "github.com/coopernurse/gorp"
    _ "github.com/go-sql-driver/mysql"
)

const DefaultHost = "www.speedrunslive.com"

var store = sessions.NewCookieStore(
    []byte("ITS-AN-AUTHENTICATION-TO-EVERYBODY"), // auth key should preferrably be 32/64 bytes
    // []byte("ITS-AN-ENCRYPTION-TO-EVERYBODY"), // encryption key if set should be 16/24/32 bytes
    // []byte("ITS-AN-OLD-AUTHENTICATION-TO-EVERYBODY"),
    // []byte("ITS-AN-OLD-ENCRYPTION-TO-EVERYBODY"), // back support for deprecated keys
)
var templates = template.Must(template.ParseFiles([]string{"login.html"}...))
var dbm *gorp.DbMap

type User struct {
    Id       int64  `db:"id"       json:"id"`
    Username string `db:"username" json:"username"`
    Password string `db:"-"        json:"-"`
    Hash     []byte `db:"password" json:"-"`
}

func ConstructString(strings ...string) string {
    var buf bytes.Buffer
    for _, str := range strings {
        buf.WriteString(str)
    }
    return buf.String()
}

func Render(w http.ResponseWriter, name string, i interface{}) bool {
    var buf bytes.Buffer
    if err := templates.ExecuteTemplate(&buf, name, i); err != nil {
        log.Println("Failed to execute template '%s', error: %s", name, err)
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return false
    } else {
        w.Write(buf.Bytes())
    }
    return true
}

func LoginGet(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "session-name")
    if err != nil {
        panic(err)
    }

    if len(r.URL.Query()["returnTo"]) > 0 {
        session.Values["returnTo"] = r.URL.Query()["returnTo"][0]
    } else {
        session.Values["returnTo"] = DefaultHost
    }

    var messages []string

    if flashes := session.Flashes("message"); len(flashes) > 0 {
        log.Println(flashes)
        for _, flash := range flashes {
            messages = append(messages, flash.(string))
        }
    }

    session.Save(r, w)

    Render(w, "login.html", messages)
}

func LoginPost(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "session-name")
    if err != nil {
        panic(err)
    }

    var returnTo string
    if returnUrl, ok := session.Values["returnTo"]; ok {
        returnTo = returnUrl.(string)
    } else {
        returnTo = DefaultHost
    }

    user := GetUser(r.PostFormValue("username"))
    if user != nil {
        err := bcrypt.CompareHashAndPassword(user.Hash, []byte(r.PostFormValue("password")))
        if err == nil {
            encodedUser, err := json.Marshal(user)
            if err != nil {
                panic(err)
            }
            session.Values["user"] = string(encodedUser)
            // if remember {
            //     // no expiration
            // } else {
            //     // default expiration of 30 days?
            // }

            err = session.Save(r, w)
            if err != nil {
                panic(err)
            }
            http.Redirect(
                w, r, ConstructString("http://", returnTo),
                http.StatusMovedPermanently,
            )
        }
    }

    session.AddFlash("Invalid username or password", "message")
    err = session.Save(r, w)
    if err != nil {
        panic(err)
    }
    http.Redirect(w, r, ConstructString("/login?returnTo=", returnTo),
        http.StatusMovedPermanently,
    )
}

func LogoutGet(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "session-name")
    if err != nil {
        panic(err)
    }
    session.Options.MaxAge = -1
    err = session.Save(r, w)
    if err != nil {
        panic(err)
    }
    session.Options.MaxAge = 30*34*3600

    DefaultRoute(w, r)
}

func AuthGet(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "session-name")
    if err != nil {
        panic(err)
    }

    encodedUser := session.Values["user"]

    if encodedUser == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    var tmpUser User
    err = json.Unmarshal([]byte(encodedUser.(string)), &tmpUser)

    user := GetUser(tmpUser.Username)
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
    } else {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(encodedUser.(string)))
    }
}

func DefaultRoute(w http.ResponseWriter, r *http.Request) {
        http.Redirect(w, r, ConstructString("/login?returnTo=", DefaultHost),
            http.StatusMovedPermanently,
        )
    }

func GetUser(username string) *User {
    var user User
    err := dbm.SelectOne(&user, `select * from user where username=?`, username)
    if err == sql.ErrNoRows {
        return nil;
    } else if err != nil {
        panic(err)
    }
    return &user
}

func main() {
    db, err := sql.Open("mysql", "speedrunslive:srladmin@/ssgo")
    if err != nil {
        panic(err)
    }

    dbm = &gorp.DbMap{Db: db, Dialect: gorp.MySQLDialect{"InnoDB", "UTF8"}}

    user := dbm.AddTableWithName(User{}, "user").SetKeys(true, "id")
    user.ColMap("username").SetUnique(true).SetMaxSize(25)

    err = dbm.CreateTablesIfNotExists()
    if err != nil {
        panic(err)
    }

    defer dbm.Db.Close()

    r := mux.NewRouter()
    r.HandleFunc("/", DefaultRoute).Methods("GET")
    r.HandleFunc("/login", LoginGet).Methods("GET")
    r.HandleFunc("/login", LoginPost).Methods("POST")
    r.HandleFunc("/logout", LogoutGet).Methods("GET")
    r.HandleFunc("/auth", AuthGet).Methods("GET")
    http.Handle("/", r)

    log.Println("Listening on :9000...")
    http.ListenAndServe(":9000", nil)
}