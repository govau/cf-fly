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
```
