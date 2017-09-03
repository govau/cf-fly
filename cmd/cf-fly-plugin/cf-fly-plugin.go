package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/concourse/fly/rc"
	jwt "github.com/dgrijalva/jwt-go"
	cfcommon "github.com/govau/cf-common"

	"code.cloudfoundry.org/cli/plugin"
)

type cfFly struct {
	ClientID     string
	ClientSecret string

	ConcourseServer string
	TokenServer     string
}

func (c *cfFly) getConcourseToken(cliConnection plugin.CliConnection, spaceID string) (string, error) {
	apiEndpoint, err := cliConnection.ApiEndpoint()
	if err != nil {
		return "", err
	}

	if c.ConcourseServer == "" {
		c.ConcourseServer = strings.Replace(apiEndpoint, "api.system", "concourse", 1)
	}

	if c.TokenServer == "" {
		c.TokenServer = strings.Replace(apiEndpoint, "api.system", "cf.system", 1)
	}

	uaaClient, err := cfcommon.NewUAAClientFromAPIURL(apiEndpoint)
	if err != nil {
		return "", err
	}

	at, err := cliConnection.AccessToken()
	if err != nil {
		return "", err
	}

	grant, err := uaaClient.ExchangeBearerTokenForClientToken(c.ClientID, c.ClientSecret, at)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, c.TokenServer+"/v1/sign", bytes.NewReader([]byte((&url.Values{
		"space": {spaceID},
	}).Encode())))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+grant.AccessToken)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", errors.New("bad status code")
	}

	b, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func getUnverifiedField(token, field string) (string, error) {
	bits := strings.Split(token, ".")
	if len(bits) != 3 {
		return "", errors.New("wrong number of bits in jwt")
	}
	seg, err := jwt.DecodeSegment(bits[1])
	if err != nil {
		return "", err
	}
	var m map[string]interface{}
	err = json.NewDecoder(bytes.NewReader(seg)).Decode(&m)
	if err != nil {
		return "", err
	}
	rv, _ := m[field].(string)
	if rv == "" {
		return "", errors.New("no such field")
	}
	return rv, nil
}

func (c *cfFly) Run(cliConnection plugin.CliConnection, args []string) {
	if args[0] == "fly" {
		sp, err := cliConnection.GetCurrentSpace()
		if err != nil {
			log.Fatal("error getting cur space: ", err)
		}

		token, err := c.getConcourseToken(cliConnection, sp.Guid)
		if err != nil {
			log.Fatal("error getting concourse token: ", err)
		}

		teamNameInToken, err := getUnverifiedField(token, "teamName")
		if err != nil {
			log.Fatal("error finding team in token: ", err)
		}

		b := &bytes.Buffer{}
		err = json.NewEncoder(b).Encode(&rc.TargetProps{
			API:      c.ConcourseServer,
			TeamName: teamNameInToken,
			Token: &rc.TargetToken{
				Type:  "EXTERNAL",
				Value: token,
			},
		})
		if err != nil {
			log.Fatal("error encoding json: ", err)
		}

		cmd := exec.Command("fly", args[1:]...)
		cmd.Env = append(cmd.Env, "FLY_TARGET_PROPS="+strings.TrimSpace(string(b.Bytes())))
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
	}
}

func (c *cfFly) GetMetadata() plugin.PluginMetadata {
	return plugin.PluginMetadata{
		Name: "Plugin to make it easy to work with Concourse",
		Version: plugin.VersionType{
			Major: 0,
			Minor: 1,
			Build: 0,
		},
		MinCliVersion: plugin.VersionType{
			Major: 6,
			Minor: 7,
			Build: 0,
		},
		Commands: []plugin.Command{
			{
				Name:     "fly",
				HelpText: "fly, subcommand - automatically logged in to team for space.",
				UsageDetails: plugin.Usage{
					Usage: "fly\n   cf fly <fly arguments>",
				},
			},
		},
	}
}

func main() {
	plugin.Start(&cfFly{
		ClientID:     "cf-concourse-integration",
		ClientSecret: "notasecret",
	})
}
