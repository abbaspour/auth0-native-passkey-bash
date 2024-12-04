# Auth0 Native Passkey in Bash

Shell scripts to perform sign up and login against Auth0's [Native Passkeys API](https://auth0.com/docs/native-passkeys-api). 

## Bootstrap 
```bash
./bootstrap.sh 
```

## Sign Up
```bash
./signup.sh -d domain.com -c client_id -r connection -u pk@example.com 
```

## Login
```bash
./login.sh  -d domain.com -c client_id -r connection -u pk@example.com 
```