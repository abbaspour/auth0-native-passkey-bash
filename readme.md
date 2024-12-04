# Auth0 Native Passkey in Bash

Shell scripts to perform sign up and login against Auth0's [Native Passkeys API](https://auth0.com/docs/native-passkeys-api). 

## Bootstrap 
```bash
./bootstrap.sh 
```

## Sign Up
```bash
./signup.sh -d custom-domaian.com -c client_id -r db-connection-name -u pk@example.com -k private-key.pem
```

## Login
```bash
./login.sh -d custom-domaian.com -c client_id -r db-connection-name -u pk@example.com -k private-key.pem
```