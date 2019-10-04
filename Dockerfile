FROM golang:1.13.1-alpine3.10 AS builder

# Install requisites
RUN apk update && \
    apk add gitgcc musl-dev

# Download repo and dependencies
RUN go get /go/src/github.com/hbermu/GitHubOrgUsers


FROM alpine:3.10
ENV CREATED 2019-10-01
LABEL maintainer1="Héctor Bermúdez<hbermu@protonmail.ch>"
LABEL name="GitHub-Users-Ldap" \
        version="0.3" \
        description="Compare users from github org with your LDAP or SQLite" \
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
ENTRYPOINT ["/bin/GitHubOrgUsers", "--config=/etc/GitHubOrgUsers/config.toml"]
