# Administrator authentication

The administration summary reports the number of configured administrator
accounts, how many use FortiOS remote authentication, and discovered RADIUS,
LDAP, or TACACS+ servers. Credential values are not exported.

When administrator accounts exist and no supported AAA server or explicitly
remote-authenticated administrator is identified, the `local-admin-auth`
finding asks for review of account centralization and lifecycle controls.
Configured servers are not proof that administrators use them; other
authentication mechanisms are not assessed. Local accounts can be required for
break-glass access, so this is a review indicator rather than a claim that
local authentication is inherently insecure.

Review individual account status, assigned profiles, trusted hosts, MFA, and
emergency access procedures on the device. These details may require a more
specific FortiOS check in a future release.
