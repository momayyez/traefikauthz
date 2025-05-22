# AuthZ Traefik

**AuthZ Traefik** is a custom authorization middleware plugin for [Traefik](https://traefik.io/) that validates access permissions using [Keycloak](https://www.keycloak.org/) and the [UMA 2.0 protocol](https://datatracker.ietf.org/doc/html/rfc8693).

It works by extracting the request path segments based on configurable indexes — for example, if your URL is `/v1/api/users/getall/extra`, and you've configured `resourceIndex: 3` and `scopeIndex: 4`, the permission will be derived as `users#getall`.

This permission string is then passed to Keycloak’s token endpoint using the `uma-ticket` grant to verify whether the user is allowed to access the requested resource.

---

### 🔐 Features
- 🔧 Authorization based on **configurable resource and scope indexes**
- 🔄 Uses `uma-ticket` grant type for permission evaluation
- ✅ Works with any valid access token issued by Keycloak
- ⚙️ Can be customized per route using Traefik’s dynamic configuration
- 🚀 Lightweight and easy to plug into your Traefik stack


---

### 📦 Plugin Usage Example

```yaml
http:
  middlewares:
    keycloak-authz:
      plugin:
        authztraefikgateway:
          keycloakURL: "https://keycloak.local/realms/demo/protocol/openid-connect/token"
          keycloakClientId: "traefik-client"
          resourceIndex: 3
          scopeIndex: 4
