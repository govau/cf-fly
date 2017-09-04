# cf-fly

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

Build `cf` plugin:

```bash
go get github.com/govau/cf-fly/cmd/cf-fly-plugin
```

Install the plug-in:

```bash
cf install-plugin $GOPATH/bin/cf-fly-plugin -f
```

Run it!

```bash
cf fly pipelines
```

NOTE:
Assumes that if your CF is at:
https://api.system.example.com

then you are running an SSO server at:
https://cf.system.system.example.com

and a Concourse server at:
https://concourse.system.example.com

TODO: cache tokens