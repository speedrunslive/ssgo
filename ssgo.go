package main

import (
    "log"
    "bytes"
    "strconv"
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
    Id       int64  `db:"id"`
    Username string `db:"username"`
    Password string `db:"-"`
    Hash     []byte `db:"password"`
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
    vars := mux.Vars(r)
    session, err := store.Get(r, "session-name")
    if err != nil {
        panic(err)
    }

    if returnTo, ok := vars["returnTo"]; ok {
        session.AddFlash(returnTo, "returnTo")
    }

    var messages []string

    if flashes := session.Flashes("message"); len(flashes) > 0 {
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

    if flashes := session.Flashes("returnTo"); len(flashes) > 0 {
        for _, flash := range flashes {
            returnTo = flash.(string)
        }
    } else {
        returnTo = DefaultHost
    }

    user := GetUser(r.PostFormValue("username"))
    if user != nil {
        err := bcrypt.CompareHashAndPassword(user.Hash, []byte(r.PostFormValue("password")))
        if err == nil {
            session.Values["userid"] = user.Id
            session.Values["username"] = user.Username
            // if remember {
            //     // no expiration
            // } else {
            //     // default expiration of 30 days?
            // }

            var buf bytes.Buffer
            buf.WriteString("http://")
            buf.WriteString(returnTo)

            err = session.Save(r, w)
            if err != nil {
                panic(err)
            }
            http.Redirect(w, r, buf.String(), http.StatusMovedPermanently)
        }
    }

    var buf bytes.Buffer
    buf.WriteString("/login/")
    buf.WriteString(returnTo)

    session.AddFlash("Invalid username or password", "message")
    err = session.Save(r, w)
    if err != nil {
        panic(err)
    }
    http.Redirect(w, r, buf.String(), http.StatusMovedPermanently)
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

    var buf bytes.Buffer
    buf.WriteString("/login/")
    buf.WriteString(DefaultHost)

    http.Redirect(w, r, buf.String(), http.StatusMovedPermanently)
}

func AuthGet(w http.ResponseWriter, r *http.Request) {
    session, err := store.Get(r, "session-name")
    if err != nil {
        panic(err)
    }

    id := session.Values["userid"]
    name := session.Values["username"]

    if id == nil || name == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    userid := id.(int64)
    username := name.(string)

    user := GetUser(username)
    if user == nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
    } else {
        var buf bytes.Buffer
        buf.WriteString("{\"id\":\"")
        buf.WriteString(strconv.FormatInt(userid, 10))
        buf.WriteString("\",\"username\":\"")
        buf.WriteString(username)
        buf.WriteString("\"}")
        w.Header().Set("Content-Type", "application/json")
        w.Write(buf.Bytes())
    }
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
    db, err := sql.Open("mysql", "username:password@/ssgo")
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
    r.HandleFunc("/",
        func(w http.ResponseWriter, r *http.Request) {
            http.Redirect(w, r, "/login", http.StatusMovedPermanently)
        })
    r.HandleFunc("/login/{returnTo}", LoginGet).Methods("GET")
    r.HandleFunc("/login", LoginPost).Methods("POST")
    r.HandleFunc("/logout", LogoutGet).Methods("GET")
    r.HandleFunc("/auth", AuthGet).Methods("GET")
    http.Handle("/", r)

    log.Println("Listening on :9000...")
    http.ListenAndServe(":9000", nil)
}