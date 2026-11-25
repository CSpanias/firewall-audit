# Administrator authentication

The administration summary reports the number of configured administrator
accounts, how many use FortiOS remote authentication, and discovered RADIUS,
LDAP, or TACACS+ servers. Credential values are not exported.

When administrator accounts exist but no supported central AAA server is
identified, the `local-admin-auth` finding asks for review of account
centralization and lifecycle controls. Local accounts can be required for
break-glass access, so this is a review indicator rather than a claim that
local authentication is inherently insecure.

Review individual account status, assigned profiles, trusted hosts, MFA, and
emergency access procedures on the device. These details may require a more
specific FortiOS check in a future release.
