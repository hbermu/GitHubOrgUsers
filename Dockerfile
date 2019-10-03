FROM golang:1.13.1-alpine3.10
ENV CREATED 2019-10-01
LABEL maintainer1="Héctor Bermúdez<hbermu@protonmail.ch>"
LABEL name="GitHub-Users-Ldap" \
        version="0.2" \
        description="Compare users from github org with your LDAP" \
        license="Apache License 2.0"

# Install requisites
RUN apk update && \
    apk add git

# Create directory
RUN addgroup -S  comparator && \
    adduser -S -G comparator comparator

# Download repo and dependencies
RUN go get /go/src/github.com/hbermu/GitHubUsersLDAP

# Create config path and copy example file
RUN mkdir /etc/GitHubUsersLDAP
COPY config.toml /etc/GitHubUsersLDAP/config.toml

# Directory to use
WORKDIR /go/src/github.com/hbermu/GitHubUsersLDAP
ENTRYPOINT ["/go/bin/GitHubUsersLDAP", "--config=/etc/GitHubUsersLDAP/config.toml"]
