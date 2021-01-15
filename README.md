# gsuite2aws

Sync groups and users from GSuite to AWS SSO.

## Build

Build the Docker image:

```sh
docker build -t gsuite2aws .
```

## Usage

The following environment variables need to be present:

- `GSUITE_CREDENTIALS`: JSON credentials file contents for GSuite service account.
- `SCIM_ENDPOINT`: AWS SSO SCIM endpoint provided when you enable automatic provisioning.
- `SCIM_ACCESS_TOKEN`: AWS SSO SCIM access token provided when you enable automatic provisioning.

Run the image:

```sh
docker run --rm \
  -e GSUITE_CREDENTIALS \
  -e SCIM_ENDPOINT \
  -e SCIM_ACCESS_TOKEN \
  gsuite2aws \
  admin_email group [group ...]
```

Arguments:

- `admin_email`: Email address of GSuite admin user running the script.
- `group`: Google group specified by group's email address (for example, `mygroup@orgdomain.com`).
