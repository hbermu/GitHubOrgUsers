//Copyright 2019 Hector Bermudez Perez
//Licensed to the Apache Software Foundation (ASF) under one
//or more contributor license agreements.  See the NOTICE file
//distributed with this work for additional information
//regarding copyright ownership.  The ASF licenses this file
//to you under the Apache License, Version 2.0 (the
//"License"); you may not use this file except in compliance
//with the License.  You may obtain a copy of the License at
//
//http://www.apache.org/licenses/LICENSE-2.0
//
//Unless required by applicable law or agreed to in writing,
//software distributed under the License is distributed on an
//"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
//KIND, either express or implied.  See the License for the
//specific language governing permissions and limitations
//under the License.

package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/spf13/viper"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/ldap.v3"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"os"
	"path"
	"strconv"
	"strings"
)

// Default Params
const (
	program           = "Github_Org_Users"
	Version           = "0.3.1"
	Revision          = "04/10/2019"
	Branch            = "master"
	BuildUser         = "hbermu"
	BuildDate         = "04/10/2019"
	defaultConfigPath = "./config.toml"

	// LDAP Default Config
	defaultLdapEnabled         = false
	defaultLdapUser            = "cn=admin,dc=org,dc=com"
	defaultLdapPassword        = "admin"
	defaultLdapHostname        = "localhost"
	defaultLdapPort            = 389
	defaultLdapBaseDN          = "dc=org,dc=com"
	defaultLdapSearchAttribute = "cn"
	//		Operation Choices
	ScopeBaseObject   = 0
	ScopeSingleLevel  = 1
	ScopeWholeSubtree = 2
	//		Scope Choices
	NeverDerefAliases   = 0
	DerefInSearching    = 1
	DerefFindingBaseObj = 2
	DerefAlways         = 3

	// SQLite Default Config
	defaultSQLiteEnabled  = true
	defaultSQLitePath     = "./sqlite.db"
	defaultSQLiteUser     = ""
	defaultSQLitePassword = ""

	// GitHub Default Config
	defaultGitHubToken      = ""
	defaultGitHubOrg        = "org"
	defaultGitHubSuf        = ""
	defaultGitHubIgnore     = "" // Format -> "item1,item2,item3,..."
	defaultGitHubDelete     = false
	GitHubApiPathGetUsers   = "/orgs/:org/members"
	GitHubApiPathRemoveUser = "/orgs/:org/members/:username"
	GitHubApiUrl            = "https://api.github.com"

	// SMTP Default Config
	defaultSMTPEnabled     = false
	defaultSMTPHost        = "smtp.gmail.com"
	defaultSMTPPort        = 587
	defaultSMTPUser        = "user@gmail.com"
	defaultSMTPPassword    = ""
	defaultSMTPSkipVerify  = true
	defaultSMTPFromAddress = "user@gmail.com"
	defaultSMTPFromName    = "User"
	defaultSMTPToAddresses = ""
)

type Config struct {
	// SMTP Config
	SMTPEnabled bool
	SMTPHost    string
	SMTPPort    int
	SMTPUser,
	SMTPPassword string
	SMTPSkipVerify bool
	SMTPFromAddress,
	SMTPFromName string
	SMTPToAddresses []string

	SQLiteEnabled bool
	SQLitePath,
	SQLiteUser,
	SQLitePassword string

	// GitHub Config
	GitHubToken,
	GitHubOrg,
	GitHubSuf string
	GitHubIgnore []string
	GitHubDelete bool

	// LDAP Config
	LdapEnabled bool
	LdapUser,
	LdapPassword,
	LdapHostname string
	LdapPort            int
	LdapBaseDN          string
	LdapSearchAttribute string
}

func readConfig(configPath string) Config {

	log.Infoln("Reading config file ", configPath)

	log.Debugln("Setting viper defaults Params")
	// Defaults
	//		LDAP
	viper.SetDefault("ldap.enabled", defaultLdapEnabled)
	viper.SetDefault("ldap.user", defaultLdapUser)
	viper.SetDefault("ldap.password", defaultLdapPassword)
	viper.SetDefault("ldap.hostname", defaultLdapHostname)
	viper.SetDefault("ldap.port", defaultLdapPort)
	viper.SetDefault("ldap.base_dn", defaultLdapBaseDN)
	viper.SetDefault("ldap.search_attribute", defaultLdapSearchAttribute)

	//		SQLite
	viper.SetDefault("sqlite.enabled", defaultSQLiteEnabled)
	viper.SetDefault("sqlite.path", defaultSQLitePath)
	viper.SetDefault("sqlite.user", defaultSQLiteUser)
	viper.SetDefault("sqlite.password", defaultSQLitePassword)

	// 		GitHub
	viper.SetDefault("github.token", defaultGitHubToken)
	viper.SetDefault("github.org", defaultGitHubOrg)
	viper.SetDefault("github.suf", defaultGitHubSuf)
	viper.SetDefault("github.ignore", defaultGitHubIgnore)
	viper.SetDefault("github.delete", defaultGitHubDelete)

	//		SMTP
	viper.SetDefault("smtp.enabled", defaultSMTPEnabled)
	viper.SetDefault("smtp.host", defaultSMTPHost)
	viper.SetDefault("smtp.port", defaultSMTPPort)
	viper.SetDefault("smtp.user", defaultSMTPUser)
	viper.SetDefault("smtp.password", defaultSMTPPassword)
	viper.SetDefault("smtp.skip_verify", defaultSMTPSkipVerify)
	viper.SetDefault("smtp.from_address", defaultSMTPFromAddress)
	viper.SetDefault("smtp.from_name", defaultSMTPFromName)
	viper.SetDefault("smtp.to_addresses", defaultSMTPToAddresses)

	// File Config without extension
	// ---- Split "file.ext" | "ext" -> "file"
	log.Debugln("Taking path bin")
	var file = strings.Split(path.Base(configPath), path.Ext(configPath))[0]

	// Config File name
	viper.SetConfigName(file)

	// Config File Paths
	log.Debugln("Setting all config paths")
	viper.AddConfigPath(path.Dir(configPath))
	viper.AddConfigPath(".") // Always search in ./

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}

	return Config{
		SMTPEnabled:         viper.GetBool("smtp.enabled"),
		SMTPHost:            viper.GetString("smtp.host"),
		SMTPPort:            viper.GetInt("smtp.port"),
		SMTPUser:            viper.GetString("smtp.user"),
		SMTPPassword:        viper.GetString("smtp.password"),
		SMTPSkipVerify:      viper.GetBool("smtp.skip_verify"),
		SMTPFromAddress:     viper.GetString("smtp.from_address"),
		SMTPFromName:        viper.GetString("smtp.from_name"),
		SMTPToAddresses:     strings.Split(viper.GetString("smtp.to_addresses"), ","),
		GitHubToken:         viper.GetString("github.token"),
		GitHubOrg:           viper.GetString("github.org"),
		GitHubSuf:           viper.GetString("github.suf"),
		GitHubIgnore:        strings.Split(viper.GetString("github.ignore"), ","),
		GitHubDelete:        viper.GetBool("github.delete"),
		SQLiteEnabled:       viper.GetBool("sqlite.enabled"),
		SQLitePath:          viper.GetString("sqlite.path"),
		SQLiteUser:          viper.GetString("sqlite.user"),
		SQLitePassword:      viper.GetString("sqlite.password"),
		LdapEnabled:         viper.GetBool("ldap.enabled"),
		LdapUser:            viper.GetString("ldap.user"),
		LdapPassword:        viper.GetString("ldap.password"),
		LdapHostname:        viper.GetString("ldap.hostname"),
		LdapPort:            viper.GetInt("ldap.port"),
		LdapBaseDN:          viper.GetString("ldap.base_dn"),
		LdapSearchAttribute: viper.GetString("ldap.search_attribute"),
	}
}

func getUsersLdap(config Config) []string {
	log.Info("Getting users form ldap")

	log.Debugln("Connect to LDAP server: " + config.LdapHostname + ":" + strconv.Itoa(config.LdapPort))
	// Bind with a read only user
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.LdapHostname, config.LdapPort))
	checkError(err)
	defer l.Close()

	log.Debugln("Using ldap user: ", config.LdapUser)
	if config.LdapPassword == defaultLdapPassword {
		log.Warnln("Using default password")
	}
	err = l.Bind(config.LdapUser, config.LdapPassword)
	checkError(err)

	log.Debugln("Creating ldap request")
	log.Debugln("Searching in Base DN: ", config.LdapBaseDN)
	log.Debugln("Searching the Attribute: ", config.LdapSearchAttribute)
	searchRequest := ldap.NewSearchRequest(
		config.LdapBaseDN, // The base dn to search
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		"(&(objectClass=organizationalPerson))", // The filter to apply
		[]string{config.LdapSearchAttribute},    // A list attributes to retrieve
		nil,
	)

	// Get results
	log.Infoln("Start the ldap search")
	sr, err := l.Search(searchRequest)
	checkError(err)

	log.Debugln("Copy all results to manage them")
	ldapUsers := make([]string, 0)
	for _, entry := range sr.Entries {
		log.Debugln("User getted:", entry.GetAttributeValue(config.LdapSearchAttribute))
		ldapUsers = append(ldapUsers, entry.GetAttributeValue(config.LdapSearchAttribute))
	}

	log.Infoln("Ldap Search Successfully")
	return ldapUsers
}

func getUsersSQLite(config Config) []string {
	log.Info("Getting users form SQLite")

	log.Debugln("Check if exist SQLite file")
	_, err := os.Stat(config.SQLitePath)
	checkError(err)


	sqliteUsers := make([]string, 0)

	log.Debugln("Starting SQLite connection")
	db, err := sql.Open("sqlite3", config.SQLitePath)
	checkError(err)

	sqlSequence := "SELECT username FROM github_users"
	log.Debugln("Preparing the SQL Swquence: " + sqlSequence)
	rows, err := db.Query(sqlSequence)
	checkError(err)
	var username string

	log.Debugln("Getting all rows")
	for rows.Next() {
		err = rows.Scan(&username)
		checkError(err)
		sqliteUsers = append(sqliteUsers, username)
		log.Debugln("User getted:", username)
	}

	log.Debugln("Closing DB")
	err = db.Close()
	checkError(err)

	return sqliteUsers
}

func delUsersSQLite(config Config, list []string){
	log.Info("Deleting users form SQLite")

	log.Debugln("Check if exist SQLite file")
	_, err := os.Stat(config.SQLitePath)
	checkError(err)

	log.Debugln("Starting SQLite connection")
	db, err := sql.Open("sqlite3", config.SQLitePath)
	checkError(err)

	sqlSequence := "DELETE FROM github_users WHERE username=?"
	log.Debugln("Preparing the SQL Swquence: " + sqlSequence)
	sequence, err := db.Prepare(sqlSequence)
	checkError(err)

	log.Debugln("Deleting rows from SQLite")
	for _, user := range list {
		log.Debugln("Deleting user: " + user)
		res, err := sequence.Exec(user)
		checkError(err)

		_, err = res.RowsAffected()
		checkError(err)
	}

	err = db.Close()
	checkError(err)

}

func createSQLSchema(path string) {
	log.Infoln("Creating Database with scheme")

	if path == defaultSQLitePath {
		log.Warnln("Using default SQLite path")
	}

	log.Debugln("Creating SQLite file")
	db, err := sql.Open("sqlite3", path)
	checkError(err)

	sqlStmt := `
	create table github_users (username text not null primary key, mail text not null, comment text);
	`
	log.Debugln("Prepare seq:", sqlStmt)

	_, err = db.Exec(sqlStmt)
	checkError(err)
	log.Infoln("SQLite created on", path)

	log.Debugln("Closing DB")
	err = db.Close()
	checkError(err)
}

func getUsersGitHub(config Config) []string {
	log.Info("Getting users form GitHub")

	var last = false
	var page = 1
	gitHubUsers := make([]string, 0)

	for !last {
		respBodyString := ""
		respBodyString, last = gitHubRequest(config, page)
		page = page + 1

		for _, entry := range strings.Split(respBodyString, "{\"login\":\"") {
			if entry != "[" {
				log.Debugln("User getted:", strings.Split(entry, "\",\"id\":")[0])
				gitHubUsers = append(gitHubUsers, strings.Split(entry, "\",\"id\":")[0])
			}
		}
	}
	return gitHubUsers

}

func gitHubRequest(config Config, page int) (string, bool) {
	apiUrl := GitHubApiUrl + strings.Replace(GitHubApiPathGetUsers, ":org", config.GitHubOrg, -1)

	if page > 1 {
		apiUrl = apiUrl + "?page=" + strconv.Itoa(page)
		log.Debugln("Getting page", page)
	}

	log.Debugln("Attack to url:", apiUrl)
	log.Debugln("Prepare the request")
	req, err := http.NewRequest(http.MethodGet, apiUrl, nil)
	checkError(err)

	if config.GitHubToken != defaultGitHubToken {
		req.Header.Add("Authorization", "token "+config.GitHubToken)
	} else {
		log.Warnln("Using empty GitHub Token")
	}
	req.Header.Add("Accept", "application/vnd.github.v3+json")

	log.Debugln("Create new http client")
	client := http.DefaultClient
	log.Debugln("Do the request")
	resp, err := client.Do(req)
	checkError(err)

	log.Debugln("Read the response body")
	body, err := ioutil.ReadAll(resp.Body)
	checkError(err)

	log.Debugln("Close the response body")
	defer resp.Body.Close()

	if strings.Contains(string(body), "documentation_url") {
		log.Fatal(string(body))
	}

	log.Debugln("Header received:", resp.Header.Get("Link"))
	return string(body), !strings.Contains(resp.Header.Get("Link"), "rel=\"last\"")

}

func checkExistSuf(config Config, githubUsers []string) ([]string, []string) {
	log.Infoln("Check if all users have the right suffix")

	wrongUsers := make([]string, 0)
	rightUsers := make([]string, 0)

	for _, user := range githubUsers {
		if !strings.Contains(strings.ToLower(user), strings.ToLower(config.GitHubSuf)) {
			log.Debugln("User without suffix founded:", user)

			if !contains(user, config.GitHubIgnore) {
				wrongUsers = append(wrongUsers, user)
			} else {
				log.Debugln("User is in ignore list")
			}
		} else {
			rightUsers = append(rightUsers, user)
		}
	}

	return wrongUsers, rightUsers
}

// This function compare 2 lists and return 2 lists
// @config -> Config struct
// @list1  -> List with string to search
// @list2  -> List with string to compare
//
// Returns:
//			[]string 1 -> String in @list1 and not in @list2
//			[]string 2 -> String in @list1 and @list2
func compareUsersLists(config Config, list1 []string, list2 []string) ([]string, []string) {
	log.Info("Comparing users from 2 lists")

	wrongUsers := make([]string, 0)
	rightUsers := make([]string, 0)

	for _, user := range list2 {

		if !contains(strings.Replace(strings.ToLower(user), strings.ToLower(config.GitHubSuf), "", -1),
			list1) {
			log.Debugln("Wrong user founded:", user)
			if !contains(user, config.GitHubIgnore) {
				wrongUsers = append(wrongUsers, user)
			} else {
				log.Debugln("User is in ignore list")
			}
		} else {
			rightUsers = append(rightUsers, user)
		}
	}
	return wrongUsers, rightUsers
}

func contains(user string, arrayUsers []string) bool {

	for _, userList := range arrayUsers {
		//log.Debugln("Compare " + user + " - " + userList)
		if strings.ToLower(userList) == strings.ToLower(user) {
			return true
		}
	}
	return false
}

func sendMailReport(config Config, message string, subject string) {
	log.Infoln("Send mail")

	log.Debugln("Preparing the message")
	message = subject + message
	message = message + "\nUn saludo."

	log.Debugln("Message to sent:", message)

	log.Debugln("Prepare the authentication")
	log.Debugln("SMTP User:", config.SMTPUser)
	if config.SMTPPassword == defaultSMTPPassword {
		log.Warnln("Using default snmtp password")
	}
	auth := smtp.PlainAuth("", config.SMTPUser, config.SMTPPassword, config.SMTPHost)

	log.Debugln("Sending mail")
	address := config.SMTPHost + ":" + strconv.Itoa(config.SMTPPort)
	log.Debugln("SMTP Server:", address)
	log.Debugln("SMTP From Address:", config.SMTPFromAddress)
	log.Debugln("SMTP To Address:", config.SMTPToAddresses)
	err := smtp.SendMail(address, auth, config.SMTPFromAddress, config.SMTPToAddresses, []byte(message))

	if err != nil {
		log.Warnln(err)
	} else {
		log.Infoln("Mail sended!")
	}
}

func deleteUsersGitHub(config Config, users []string) {
	log.Infoln("Preparing to remove users from GitHub")

	subject := "Subject: Usuarios eliminados de GitHub\n\n"
	message := "Los siguientes usuarios se han borrado:\n"

	// Replace org
	apiUrl := GitHubApiUrl + strings.Replace(GitHubApiPathRemoveUser, ":org", config.GitHubOrg, -1)

	for _, user := range users {
		// Replace user
		apiUrl = strings.Replace(apiUrl, ":username", user, -1)

		log.Debugln("Attack to url:", apiUrl)
		log.Debugln("Prepare the request")
		req, err := http.NewRequest(http.MethodDelete, apiUrl, nil)
		checkError(err)

		if config.GitHubToken != defaultGitHubToken {
			req.Header.Add("Authorization", "token "+config.GitHubToken)
		} else {
			log.Warnln("Using empty GitHub Token")
		}
		req.Header.Add("Accept", "application/vnd.github.v3+json")

		log.Debugln("Create new http client")
		client := http.DefaultClient
		log.Debugln("Do the request")
		_, err = client.Do(req)
		checkError(err)

		message = message + "\t" + user + "\n"
	}

	if config.SMTPEnabled {
		sendMailReport(config, message, subject)
	} else {
		log.Warnln("SMTP disabled")
		log.Warnln("The mail will not send")
		log.Warnln(message)
	}
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	version.Revision = Revision
	version.Branch = Branch
	version.BuildUser = BuildUser
	version.BuildDate = BuildDate
	version.Version = Version

	var (
		createSQLite     = kingpin.Command("create_db", "Create new SQLite Database")
		createSQLitePath = createSQLite.Arg("sqlite path", "Path to create the SQLite DB").Default(defaultSQLitePath).String()

		start      = kingpin.Command("start", "Start to compare Users with GitHub")
		configPath = start.Arg("config path", "Config file path").Default(defaultConfigPath).String()
	)

	// Check flags
	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print(program))
	kingpin.HelpFlag.Short('h')

	// Log Start
	log.Infoln("Starting "+program+" ", version.Info())
	log.Infoln("Build context", version.BuildContext())

	switch kingpin.Parse() {
	case "create_db":

		createSQLSchema(*createSQLitePath)

	case "start":
		config := readConfig(*configPath)

		if !(config.LdapEnabled || config.SQLiteEnabled) {
			log.Warnln("No source (sqlite and/or ldap) defined")
			os.Exit(0)
		}

		companyUsers := make([]string, 0)
		if config.LdapEnabled {
			for _, user := range  getUsersLdap(config){
				companyUsers = append(companyUsers, user)
			}
		}

		if config.SQLiteEnabled {
			for _, user := range  getUsersSQLite(config){
				companyUsers = append(companyUsers, user)
			}
		}

		usersGitHub := getUsersGitHub(config)

		wrongUsersNoSuf := make([]string, 0)
		rightUsers := make([]string, 0)
		wrongUsersNoSufNoRecon := make([]string, 0)
		wrongUsersNoSufRecon := make([]string, 0)
		wrongUsers := make([]string, 0)

		if config.GitHubSuf != "" {
			wrongUsersNoSuf, rightUsers = checkExistSuf(config, usersGitHub)
			wrongUsersNoSufNoRecon, wrongUsersNoSufRecon = compareUsersLists(config, companyUsers, wrongUsersNoSuf)
			wrongUsers, _ = compareUsersLists(config, companyUsers, rightUsers)
		} else {
			log.Debugln("Ignoring suffix")
			wrongUsersNoSufNoRecon, _ = compareUsersLists(config, companyUsers, usersGitHub)
		}

		usersSQLiteNoGithub,_ := compareUsersLists(config, usersGitHub, companyUsers)

		subject := "Subject: Usuarios erroneos en GitHub\n\n"
		message := "Hola:\n\nLos usuarios en la organización de" + config.GitHubOrg + "GitHub de las siguientes" +
			"listas no cumplen con las directrices y deberían ser eliminados inmediatamente:\n"

		usersToDelete := make([]string, 0)

		if len(wrongUsersNoSufRecon) > 0 {
			message = message + "Usuarios reconocidos sin el sufijo:\n"
			for _, user := range wrongUsersNoSufRecon {
				message = message + "\t" + user + "\n"
				usersToDelete = append(usersToDelete, user)
			}
		}
		if len(wrongUsers) > 0 {
			message = message + "Usuarios con el sufijo no reconocidos:\n"
			for _, user := range wrongUsers {
				message = message + "\t" + user + "\n"
				usersToDelete = append(usersToDelete, user)
			}
		}
		if len(wrongUsersNoSufNoRecon) > 0 {
			message = message + "Usuarios no reconocidos:\n"
			for _, user := range wrongUsersNoSufNoRecon {
				message = message + "\t" + user + "\n"
				usersToDelete = append(usersToDelete, user)
			}
		}
		if len(usersSQLiteNoGithub) > 0 {
			message = message + "Usuarios en base de datos pero no en GitHub:\n"
			for _, user := range usersSQLiteNoGithub {
				message = message + "\t" + user + "\n"
				usersToDelete = append(usersToDelete, user)
			}
			delUsersSQLite(config, usersSQLiteNoGithub)
			message = message + "Se han borrado estos usuarios de la base de datos\n"
		}
		if config.SMTPEnabled {
			if len(wrongUsersNoSufRecon) > 0 || len(wrongUsers) > 0 || len(wrongUsersNoSufNoRecon) > 0 {
				sendMailReport(config, message, subject)
			}
		} else {
			log.Warnln("SMTP disabled")
			log.Warnln("The mail will not send")
			log.Warnln(message)
		}

		if config.GitHubDelete {
			deleteUsersGitHub(config, usersToDelete)
		} else {
			log.Warnln("Delete GitHub users disabled")
		}

	}

	os.Exit(0)
}
