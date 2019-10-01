
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
	"fmt"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	"github.com/spf13/viper"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/ldap.v3"
	"io/ioutil"
	"net/http"
	"net/smtp"
	"path"
	"strconv"
	"strings"
)

// Default Params
const (
	program 				= "Github_Users_LDAP" // For Prometheus metrics.
	Version   				= "0.0.1"
	Revision  				= "01/10/2019"
	Branch    				= "master"
	BuildUser 				= "hbermu"
	BuildDate 				= "01/10/2019"
	defaultConfigPath 		= "./config.toml"

	// LDAP Default Config
	defaultLdapUser     	= "cn=admin,dc=org,dc=com"
	defaultLdapPassword 	= "admin"
	defaultLdapHostname 	= "localhost"
	defaultLdapPort     	= 389
	defaultLdapBaseDN		= "dc=org,dc=com"
	defaultLdapSearchAttribute	= "cn"
	//		Operation Choices
	ScopeBaseObject   		= 0
	ScopeSingleLevel  		= 1
	ScopeWholeSubtree 		= 2
	//		Scope Choices
	NeverDerefAliases   	= 0
	DerefInSearching    	= 1
	DerefFindingBaseObj 	= 2
	DerefAlways         	= 3

	// GitHub Default Config
	defaultGitHubToken 		= ""
	defaultGitHubOrg		= "org"
	defaultGitHubSuf		= ""
	defaultGitHubIgnore		= ""	// Format -> "item1,item2,item3,..."
	GitHubApiPath			= "/orgs/:org/members"
	GitHubApiUrl			= "https://api.github.com"

	// SMTP Default Config
	defaultSMTPEnabled 		= false
	defaultSMTPHost 		= "smtp.gmail.com"
	defaultSMTPPort 		= 587
	defaultSMTPUser 		= "user@gmail.com"
	defaultSMTPPassword 	= ""
	defaultSMTPSkipVerify 	= true
	defaultSMTPFromAddress 	= "user@gmail.com"
	defaultSMTPFromName 	= "User"
	defaultSMTPToAddresses  = ""
)



type Config struct {

	// SMTP Config
	SMTPEnabled		bool
	SMTPHost		string
	SMTPPort		int
	SMTPUser,
	SMTPPassword	string
	SMTPSkipVerify	bool
	SMTPFromAddress,
	SMTPFromName	string
	SMTPToAddresses	[]string

	// GitHub Config
	GitHubToken,
	GitHubOrg,
	GitHubSuf		string
	GitHubIgnore  []string

	// LDAP Config
	LdapUser,
	LdapPassword,
	LdapHostname 	string
	LdapPort 		int
	LdapBaseDN		string
	LdapSearchAttribute  string
}

func readConfig(configPath string) Config{

	log.Infoln("Reading config file ", configPath)

	log.Debugln("Setting viper defaults Params")
	// Defaults
	//		LDAP
	viper.SetDefault("ldap.user", 			defaultLdapUser)
	viper.SetDefault("ldap.password", 		defaultLdapPassword)
	viper.SetDefault("ldap.hostname", 		defaultLdapHostname)
	viper.SetDefault("ldap.port", 			defaultLdapPort)
	viper.SetDefault("ldap.base_dn", 		defaultLdapBaseDN)
	viper.SetDefault("ldap.search_attribute", defaultLdapSearchAttribute)

	// 		GitHub
	viper.SetDefault("github.token",		defaultGitHubToken)
	viper.SetDefault("github.org",			defaultGitHubOrg)
	viper.SetDefault("github.suf",			defaultGitHubSuf)
	viper.SetDefault("github.ignore",		defaultGitHubIgnore)

	//		SMTP
	viper.SetDefault("smtp.enabled",		defaultSMTPEnabled)
	viper.SetDefault("smtp.host",			defaultSMTPHost)
	viper.SetDefault("smtp.port",			defaultSMTPPort)
	viper.SetDefault("smtp.user",			defaultSMTPUser)
	viper.SetDefault("smtp.password",		defaultSMTPPassword)
	viper.SetDefault("smtp.skip_verify",	defaultSMTPSkipVerify)
	viper.SetDefault("smtp.from_address",	defaultSMTPFromAddress)
	viper.SetDefault("smtp.from_name",		defaultSMTPFromName)
	viper.SetDefault("smtp.to_addresses",	defaultSMTPToAddresses)


	// File Config without extension
	// ---- Split "file.ext" | "ext" -> "file"
	log.Debugln("Taking path bin")
	var file = strings.Split(path.Base(configPath), path.Ext(configPath))[0]

	// Config File name
	viper.SetConfigName(file)

	// Config File Paths
	log.Debugln("Setting all config paths")
	viper.AddConfigPath(path.Dir(configPath))
	viper.AddConfigPath(".")					// Always search in ./

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(err)
	}

	return Config{
		SMTPEnabled:     viper.GetBool		("smtp.enabled"),
		SMTPHost:        viper.GetString	("smtp.host"),
		SMTPPort:        viper.GetInt		("smtp.port"),
		SMTPUser:        viper.GetString	("smtp.user"),
		SMTPPassword:    viper.GetString	("smtp.password"),
		SMTPSkipVerify:  viper.GetBool		("smtp.skip_verify"),
		SMTPFromAddress: viper.GetString	("smtp.from_address"),
		SMTPFromName:    viper.GetString	("smtp.from_name"),
		SMTPToAddresses: strings.Split(viper.GetString	("smtp.to_addresses"), ","),
		GitHubToken:     viper.GetString	("github.token"),
		GitHubOrg:     	 viper.GetString	("github.org"),
		GitHubSuf:     	 viper.GetString	("github.suf"),
		GitHubIgnore:    strings.Split(viper.GetString	("github.ignore"), ","),
		LdapUser:        viper.GetString	("ldap.user"),
		LdapPassword:    viper.GetString	("ldap.password"),
		LdapHostname:    viper.GetString	("ldap.hostname"),
		LdapPort:        viper.GetInt		("ldap.port"),
		LdapBaseDN:		 viper.GetString	("ldap.base_dn"),
		LdapSearchAttribute: viper.GetString("ldap.search_attribute"),
	}
}


func getUsersLdap(config Config)  []string{
	log.Info("Getting users form ldap")

	log.Debugln("Connect to LDAP server: " + config.LdapHostname + ":" + strconv.Itoa(config.LdapPort) )
	// Bind with a read only user
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", config.LdapHostname, config.LdapPort))
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	log.Debugln("Using ldap user: ", config.LdapUser)
	if config.LdapPassword == defaultLdapPassword {
		log.Warnln("Using default password")
	}
	err = l.Bind(config.LdapUser, config.LdapPassword)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugln("Creating ldap request")
	log.Debugln("Searching in Base DN: ", config.LdapBaseDN)
	log.Debugln("Searching the Attribute: ", config.LdapSearchAttribute)
	searchRequest := ldap.NewSearchRequest(
		config.LdapBaseDN, 								// The base dn to search
		ScopeWholeSubtree, NeverDerefAliases, 0, 0, false,
		"(&(objectClass=organizationalPerson))", 	// The filter to apply
		[]string{config.LdapSearchAttribute},			// A list attributes to retrieve
		nil,
	)

	// Get results
	log.Infoln("Start the ldap search")
	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugln("Copy all results to manage them")
	ldapUsers := make([]string, 0)
	for _, entry := range sr.Entries {
		log.Debugln("User getted:", entry.GetAttributeValue(config.LdapSearchAttribute))
		ldapUsers = append(ldapUsers, entry.GetAttributeValue(config.LdapSearchAttribute))
	}

	log.Infoln("Ldap Search Successfully")
	return ldapUsers
}

func getUsersGitHub(config Config) []string{
	log.Info("Getting users form GitHub")

	var last = false
	var page = 1
	gitHubUsers := make([]string, 0)

	for !last{
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

func gitHubRequest(config Config, page int) (string, bool){
	apiUrl := GitHubApiUrl + strings.Replace(GitHubApiPath, ":org", config.GitHubOrg, -1 )

	if page > 1 {
		apiUrl = apiUrl + "?page=" + strconv.Itoa(page)
		log.Debugln("Getting page", page)
	}

	log.Debugln("Attack to url:", apiUrl)
	log.Debugln("Prepare the request")
	req, err := http.NewRequest(http.MethodGet, apiUrl, nil)
	if err != nil {
		log.Fatal(err)
	}

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
	if err != nil {
		log.Fatal(err)
	}

	log.Debugln("Read the response body")
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	log.Debugln("Close the response body")
	defer resp.Body.Close()

	if strings.Contains(string(body), "documentation_url"){
		log.Fatal(string(body))
	}

	log.Debugln("Header received:", resp.Header.Get("Link"))
	return string(body), !strings.Contains(resp.Header.Get("Link"), "rel=\"last\"")

}

func checkExistSuf(config Config, githubUsers []string) ([]string, []string){
	log.Infoln("Check if all users have the right suffix")

	wrongUsers := make([]string, 0)
	rightUsers := make([]string, 0)

	for _,user := range githubUsers {
		if !strings.Contains(strings.ToLower(user), strings.ToLower(config.GitHubSuf)){
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

	return wrongUsers,rightUsers
}

func compareUsersLists(config Config, ldapUsers []string, githubUsers []string) ([]string, []string){
	log.Info("Comparing users from GitHub and LDAP")

	wrongUsers := make([]string, 0)
	rightUsers := make([]string, 0)

	for _,user := range githubUsers {

		if !contains(strings.Replace(strings.ToLower(user), strings.ToLower(config.GitHubSuf), "", -1),
			ldapUsers) {
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
	return wrongUsers,rightUsers
}

func contains(user string, arrayUsers []string) bool{

	for _, userList := range arrayUsers {
		//log.Debugln("Compare " + user + " - " + userList)
		if strings.ToLower(userList) == strings.ToLower(user) {
			return true
		}
	}
	return false
}


func sendMailReport(config Config, wrongUsers []string, wrongUsersNoSufRecon []string, wrongUsersNoSufNoRecon []string){
	log.Infoln("Send mail with wrong users")

	log.Debugln("Preparing the message")
	message := "Subject: Usuarios erroneos en GitHub\n\n" +
		"Hola:\n\nLos usuarios en la organización de" + config.GitHubOrg + "GitHub de las siguientes listas no" +
		"cumplen con las directrices y deberían ser eliminados inmediatamente:\n" +
		"Usuarios reconocidos sin el sufijo:\n"
	for _,user := range wrongUsersNoSufRecon {
		message = message + "\t" + user + "\n"
	}
	message = message + "Usuarios con el sufijo no reconocidos:\n"
	for _,user := range wrongUsers {
		message = message + "\t" + user + "\n"
	}
	message = message + "Usuarios no reconocidos:\n"
	for _,user := range wrongUsersNoSufNoRecon {
		message = message + "\t" + user + "\n"
	}
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


func main() {
	version.Revision 	= Revision
	version.Branch 		= Branch
	version.BuildUser	= BuildUser
	version.BuildDate	= BuildDate
	version.Version		= Version

	var (
		configPath		= kingpin.Flag("config", "Config file path").Short('c').Default(defaultConfigPath).String()
	)

	// Check flags
	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print(program))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	// Log Start
	log.Infoln("Starting " + program + " ", version.Info())
	log.Infoln("Build context", version.BuildContext())

	config := readConfig(*configPath)

	usersLdap := getUsersLdap(config)
	usersGitHub := getUsersGitHub(config)

	wrongUsersNoSuf, rightUsers := checkExistSuf(config, usersGitHub)
	wrongUsersNoSufNoRecon, wrongUsersNoSufRecon := compareUsersLists(config, usersLdap, wrongUsersNoSuf)

	wrongUsers,_ := compareUsersLists(config, usersLdap, rightUsers)

	if config.SMTPEnabled {
		sendMailReport(config, wrongUsers, wrongUsersNoSufRecon, wrongUsersNoSufNoRecon)
	} else {
		log.Warnln("SMTP disabled")
		log.Warnln("The mail will not send")

		message :=  "Usuarios reconocidos sin el sufijo:\n"
		for _,user := range wrongUsersNoSufRecon {
			message = message + "\t" + user + "\n"
		}
		message = message + "\t" + "Usuarios con el sufijo no reconocidos:\n"
		for _,user := range wrongUsers {
			message = message + "\t" + user + "\n"
		}
		message = message + "\t" + "Usuarios no reconocidos:\n"
		for _,user := range wrongUsersNoSufNoRecon {
			message = message + "\t" + user + "\n"
		}
		log.Warnln(message)
	}
}
