# GitHubUsersLDAP
This little program get all users form GitHub organization and LDAP and compare (with a prefix) if all GitHub users are in LDAP.

## How to get and build
 To get this bin (and all dependencies) you have to execute:
 ```
go get github.com/hbermu/GitHubUsersLDAP.git
```
To compile and execute, go to the directory and execute:
```
go build
```
This generate the bin "GitHubUsersLDAP".

## How to run
First you need to have a right config file, you have an example [here](config.toml). Then you can run:
```
./GitHubUsersLDAP 
```
Or if you have the config file in other path:
```
./GitHubUsersLDAP --config="./config.toml"
```
If you want a better log:
```
./GitHubUsersLDAP --log.level="debug"
```


