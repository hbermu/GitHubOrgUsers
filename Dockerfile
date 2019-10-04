FROM golang:1.13.1-alpine3.10 AS builder

# Install requisites
RUN apk update && \
    apk add gitgcc musl-dev

# Download repo and dependencies
RUN go get /go/src/github.com/hbermu/GitHubUsersLDAP

# Directory to use
WORKDIR /go/src/github.com/hbermu/GitHubUsersLDAP
ENTRYPOINT ["/go/bin/GitHubUsersLDAP", "--config=/etc/GitHubUsersLDAP/config.toml"]


FROM alpine:3.10
ENV CREATED 2019-10-01
LABEL maintainer1="Héctor Bermúdez<hbermu@protonmail.ch>"
LABEL name="GitHub-Users-Ldap" \
        version="0.2" \
        description="Compare users from github org with your LDAP" \
        license="Apache License 2.0"

# Install requisites
RUN apk update

# Create User
RUN addgroup -S  comparator && \
    adduser -S -G comparator comparator

# Create config path and copy example file
RUN mkdir /etc/GitHubOrgUsers
COPY config.toml /etc/GitHubOrgUsers/config.toml
COPY --from=builder /go/bin/GitHubOrgUsers /bin/GitHubOrgUsers

# Directory to use
WORKDIR /etc/GitHubOrgUsers
ENTRYPOINT ["/bin/GitHubUsersLDAP", "--config=/etc/GitHubOrgUsers/config.toml"]
