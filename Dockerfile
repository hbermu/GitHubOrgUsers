FROM golang:1.13.1-alpine3.10 AS builder

# Install requisites
RUN apk update && \
    apk add git gcc musl-dev

# Download repo and dependencies
RUN go get /go/src/github.com/hbermu/GitHubOrgUsers


FROM alpine:3.10
ENV CREATED 2019-10-01
LABEL maintainer1="Héctor Bermúdez<hbermu@protonmail.ch>"
LABEL name="GitHub-Users-Ldap" \
        version="0.4.1" \
        description="Compare users from github org with your LDAP and/or SQLite" \
        license="Apache License 2.0"

# Install requisites
RUN apk update

# Create User
RUN addgroup -S  comparator && \
    adduser -S -G comparator comparator

# Create config path and copy example file
RUN mkdir /GitHubOrgUsers

COPY config.toml /GitHubOrgUsers/config.toml
RUN chmod 555 /GitHubOrgUsers/config.toml

COPY --from=builder /go/bin/GitHubOrgUsers /GitHubOrgUsers/GitHubOrgUsers
RUN chmod 777 /GitHubOrgUsers/GitHubOrgUsers

RUN chown -R comparator:comparator /GitHubOrgUsers

# Directory to use
WORKDIR /GitHubOrgUsers/

USER comparator
ENTRYPOINT ["/GitHubOrgUsers/GitHubOrgUsers"]
#CMD ["start /etc/GitHubOrgUsers/config.toml"]
