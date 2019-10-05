# GitHubOrgUsers
This little program get all users form GitHub organization and LDAP and compare (with a prefix) if all GitHub users are in LDAP or SQLite DB.

## How to get and build
 To get this bin (and all dependencies) you have to execute:
 ```
go get github.com/hbermu/GitHubOrgUsers.git
```
To compile and execute, go to the directory and execute:
```
go build
```
This generate the bin "GitHubUsers".

## How to run
First you need to have a right config file, you have an example [here](config.toml). Then you can run:
```
./GitHubUsers start
```
Or if you have the config file in other path:
```
./GitHubUsers start ./config.toml
```
If you want a better log:
```
./GitHubUsers start --log.level="debug"
```
To create the SQLite DB with the schema:
```
./GitHubUsers start --log.level="debug"
```

## Run with Docker
You have a image on DockerHub to run this program with Docker. To do that you can run:
```
docker run -it -v /path/to/your/config/config.toml:/GitHubOrgUsers/config.toml hbermu/github_org_users start
```

Or with better log:
```
docker run -it -v /path/to/your/config/config.toml:/GitHubOrgUsers/config.toml hbermu/github_org_users start --log.level="debug"
```

In the case you need a list inside a SQLite DB:
```
docker run -it \
-v /path/to/your/config/config.toml:/GitHubOrgUsers/config.toml \
-v /path/to/your/db/sqlite.db:/GitHubOrgUsers/sqlite.db \
hbermu/github_org_users start
```

To create the Database SQLite and export it you must mount a volume inside the container and generate de Database. Here you have an example:
```
mkdir /tmp/db
chmod 777 /tmp/db
docker run -it -v /tmp/db:/tmp/  hbermu/github_org_users create_db /tmp/sqlite.db
mv /tmp/db/sqlite.db ./sqlite.db
chown $USER:$USER ./sqlite.db
```
