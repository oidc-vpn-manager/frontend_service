# Frontend Web Interface for OpenVPN-Manager

This Python-Flask based service is designed to offer a user-facing frontend to consumers and administrators of a managed OpenVPN service. The service provides the following key features:

1. The service authenticates users with OIDC and allows collections of machines to receive a pre-shared authentication token (or "Pre-Shared Key") for hands-off deployment of server profiles.
2. A Web Portal or API access which will allow a user to request and then receive a complete OpenVPN profile with a unique certificate for the user. This request must be authenticated with OIDC before permitting the request and subsequent profile file.
3. A Web Portal to allow administrators to setup a "Pre-Shared Key" for server devices to request OpenVPN profile and certificate files.
4. A REST API, authenticated with the Pre-Shared Key, to request and then receive a tar-format archive file with server configuration and separate Root and Intermediate CA Certificate, plus server certificate and key.
5. Hand-off to a separate [Signing microservice](https://github.com/openvpn-manager/signing_service), ensuring key materials only transit the server and are never retained.
6. Hand-off to the [Certificate Transparency log microservice](https://github.com/openvpn-manager/certtransparency_service) to see issued certificate details.

## Folder structure

The application resides in the `app` directory. The test-suite lives in `tests` for unit, functional and integration tests. A separate "smoke" (or end-to-end) test suite lives in the separate [testing repository](https://github.com/openvpn-manager/end-to-end-tests).

## Contributing

Contributions are welcome! Since this is Free Software:

- No copyright assignment needed, but will be gratefully received.
- **Feature requests and improvements are gratefully received**, however they may not be implemented due to time constraints or if they don't align with the developer's vision for the project

---

## License

This software is released under the [GNU Affero General Public License version 3](LICENSE).

## AI Assistance Disclosure

This code was developed with assistance from AI tools. While released under a permissive license that allows unrestricted reuse, we acknowledge that portions of the implementation may have been influenced by AI training data. Should any copyright assertions or claims arise regarding uncredited imported code, the affected portions will be rewritten to remove or properly credit any unlicensed or uncredited work.
