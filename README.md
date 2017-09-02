# cf-fly

Generate a UAA client:

```bash
# Need openid for username, and cloud_controller.read for organizations
uaac client add cf-concourse-integration \
    --name "cf-concourse-integration" \
    --scope "openid cloud_controller.read" \
    --authorized_grant_types "authorization_code" \
    --redirect_uri "https://localhost/oauth2callback" \
    --access_token_validity "3600" \
    --secret "notasecret" \
    --autoapprove true

# Need openid for username, and cloud_controller.read for organizations
uaac client add cf-concourse-web-integration \
    --name "cf-concourse-web-integration" \
    --scope "openid cloud_controller.read" \
    --authorized_grant_types "authorization_code" \
    --redirect_uri "http://localhost:8090/v1/callback" \
    --access_token_validity "3600" \
    --secret "s3cr3t"
```

Build custom `fly`:

```bash
go get github.com/concourse/fly
cd $GOPATH/src/github.com/concourse/fly
git remote rename origin upstream
git remote add origin git@github.com:govau/fly.git
git fetch origin envtarget
git checkout envtarget
go build
mv fly ~/bin/fly
```

Build `cf` plug-in and server:

```bash
go get github.com/govau/cf-fly/cmd/{cf-fly-plugin,cf-fly-server}
```

Get `atc` going:

```bash
git clone https://github.com/concourse/concourse
cd concourse
git submodule update --init --recursive
export GOPATH=$PWD
cd $GOPATH/src/github.com/concourse/atc
git remote rename origin upstream
git remote add origin git@github.com:govau/atc.git
git fetch origin addjwk
git checkout addjwk
```

Run the stamper:

```bash
OUR_URL=http://localhost:8090 \
CONCOURSE_CALLBACK_URL=http://127.0.0.1:8080/auth/external/callback \
CONCOURSE_CLIENT_SECRET=secret \
CONCOURSE_CLIENT_ID=concourse \
UAA_WEB_CLIENT_SECRET=s3cr3t \
PORT=8090 \
CF_API=https://api.system.${ENV_DOMAIN} \
    cf-fly-server
```

Run `atc`:

```bash
go run cmd/atc/*.go \
  --postgres-user=postgres \
  --postgres-password=mysecretpassword \
  --basic-auth-username=foo \
  --basic-auth-password=bar \
  --external-sso-url=http://localhost:8090 \
  --external-sso-client-id=concourse \
  --external-sso-client-secret=secret \
  --log-level debug
```

Install the plug-in:

```bash
cf install-plugin $GOPATH/bin/cf-fly-plugin -f
```

Run it!

```bash
cf fly pipelines --verbose
```