package sqldb

import (
	"fmt"
	"os"
	"testing"

	"github.com/iliafrenkel/go-pb/src/api"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var usrSvc *DBUserService
var tokenSecret = "5TEdWbDmxZ2ASXcMinBYwGi66vHiU9rq"

func TestMain(m *testing.M) {
	var err error
	var db *gorm.DB
	db, err = gorm.Open(postgres.Open("host=localhost user=test password=test dbname=test port=5432 sslmode=disable"), &gorm.Config{})
	if err != nil {
		fmt.Printf("Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	db.Migrator().DropTable(&api.User{})
	usrSvc, _ = New(SvcOptions{
		DBConnection:  db,
		DBAutoMigrate: true,
	})

	os.Exit(m.Run())
}

func Test_DBConnectionPing(t *testing.T) {
	t.Parallel()
	db, err := gorm.Open(postgres.Open("host=localhost user=test password=test dbname=test port=5432 sslmode=disable"), &gorm.Config{})
	if err != nil {
		t.Errorf("Failed to connect to database: %v\n", err)
		return
	}
	_, err = New(SvcOptions{
		DBConnection:  db,
		DBAutoMigrate: false,
	})
	if err != nil {
		t.Errorf("Failed to ping the database: %v\n", err)
		return
	}
}

func Test_CreateUser(t *testing.T) {
	t.Parallel()

	var usr = api.UserRegister{
		Username:   "test",
		Email:      "test@example.com",
		Password:   "12345",
		RePassword: "12345",
	}

	err := usrSvc.Create(usr)

	if err != nil {
		t.Errorf("Failed to create a user: %v", err)
	}

	// Check if we can find the user by username
	u, err := usrSvc.store.Find(api.User{Username: usr.Username})
	if err != nil {
		t.Errorf("findByUsername failed: %w", err)
		return
	}
	if u == nil {
		t.Errorf("Failed to find a user by username")
	}
	// Check if we can find the user by email
	u, err = usrSvc.store.Find(api.User{Email: usr.Email})
	if err != nil {
		t.Errorf("findByUsername failed: %w", err)
		return
	}
	if u == nil {
		t.Errorf("Failed to find a user by email")
	}

	// Try to create with the same username but different email
	usr.Email = "another@example.com"
	err = usrSvc.Create(usr)
	if err == nil {
		t.Errorf("Succeeded to create a user with existing username")
	}
	// Try to create with the same email but different username
	usr.Email = "test@example.com"
	usr.Username = "test2"
	err = usrSvc.Create(usr)
	if err == nil {
		t.Errorf("Succeeded to create a user with existing email")
	}
}

func Test_CreateUserEmptyUsername(t *testing.T) {
	t.Parallel()

	var usr = api.UserRegister{
		Username:   "",
		Email:      "emptyusername@example.com",
		Password:   "12345",
		RePassword: "12345",
	}
	err := usrSvc.Create(usr)
	if err == nil {
		t.Errorf("Succeeded to create a user with empty username")
	}
}
func Test_CreateUserEmptyEmail(t *testing.T) {
	t.Parallel()

	var usr = api.UserRegister{
		Username:   "emptyemail",
		Email:      "",
		Password:   "12345",
		RePassword: "12345",
	}
	err := usrSvc.Create(usr)
	if err == nil {
		t.Errorf("Succeeded to create a user with empty email")
	}
}

func Test_CreateUserPasswordsDontMatch(t *testing.T) {
	t.Parallel()

	var usr = api.UserRegister{
		Username:   "nonmatchingpasswords",
		Email:      "nonmatchingpasswords@example.com",
		Password:   "12345",
		RePassword: "54321",
	}
	err := usrSvc.Create(usr)
	if err == nil {
		t.Errorf("Succeeded to create a user with non-matching passwords")
	}
}

func Test_AuthenticateUser(t *testing.T) {
	t.Parallel()

	var usr = api.UserRegister{
		Username:   "auth",
		Email:      "auth@example.com",
		Password:   "12345",
		RePassword: "12345",
	}
	err := usrSvc.Create(usr)
	if err != nil {
		t.Errorf("Failed to create a user: %v", err)
	}

	var usrLogin = api.UserLogin{
		Username: usr.Username,
		Password: usr.Password,
	}

	inf, err := usrSvc.Authenticate(usrLogin, tokenSecret)

	if err != nil {
		t.Errorf("Failed to authenticate a user: %v", err)
	}

	if err == nil && inf.Token == "" {
		t.Errorf("Failed to authenticate a user: error is nil but token is empty")
	}

	//user doesn't exist
	usrLogin = api.UserLogin{
		Username: "idontexist",
		Password: "idontmatter",
	}

	_, err = usrSvc.Authenticate(usrLogin, tokenSecret)

	if err == nil {
		t.Errorf("Authentication succeeded for a user that doesn't exist: %#v", usrLogin)
	}

	//wrong password
	usrLogin = api.UserLogin{
		Username: usr.Username,
		Password: "wrong",
	}
	_, err = usrSvc.Authenticate(usrLogin, tokenSecret)

	if err == nil {
		t.Errorf("Authentication succeeded with incorrect password: %#v", usrLogin)
	}
}

func Test_ValidateToken(t *testing.T) {
	t.Parallel()

	var usr = api.UserRegister{
		Username:   "validate",
		Email:      "validate@example.com",
		Password:   "12345",
		RePassword: "12345",
	}
	err := usrSvc.Create(usr)
	if err != nil {
		t.Errorf("Failed to create a user: %v", err)
	}

	var usrLogin = api.UserLogin{
		Username: usr.Username,
		Password: usr.Password,
	}

	inf, err := usrSvc.Authenticate(usrLogin, tokenSecret)

	if err != nil {
		t.Errorf("Failed to authenticate a user: %v", err)
	}

	u, err := usrSvc.store.Find(api.User{Username: usr.Username})
	if err != nil {
		t.Errorf("findByUsername failed: %w", err)
		return
	}
	v, err := usrSvc.Validate(*u, inf.Token, tokenSecret)
	if err != nil {
		t.Errorf("Failed to validate token: %v", err)
	}
	if v.Username == "" || v.Token == "" {
		t.Errorf("Token validation failed: %s - %#v", inf.Token, v)

	}
}
