#x509 Certificate Check Microservice

If you need to verify a x509 certificate (chain) against a set of 
trusted certificates (the trust store) you can use this microservice.

###Required
This code is developed using:
* Docker version 19.03.13
* Docker-compose 1.24.1

###Development
Run ```make dev``` from the root of the project. A docker will spin up and start
a development server. We use docker hoster for this project so the microservice will
be available on http://certificate-check.local:8080.

The files in internal/src are watched. Any changes will result in a rebuild.
Happy coding!

###Production
This microservice is not yet tested in a production environment. If you want to,
be sure that the service is only available to the other microservices and not the
public.

If you are ready with development. Build the image: ```make image```. Then tag that
image and push it to your own image registry.

###Usage

----------------------------
Send A JSON object to the microservice. You are able to pass a ReferenceTime
property to validate if the subject certificate is/was valid at some other point
in time.
If you do not provide it the current server time will be used.

Check if a certificate is valid now:

```
POST http://certificate-check.local:8080/
Content-Type: application/json

{
"SubjectCertificate": "-----BEGIN CERTIFICATE-----\n7Cg7\n-----END CERTIFICATE-----",
"Truststore": "\n-----BEGIN CERTIFICATE-----\nq+QlAC\n-----END CERTIFICATE-----"
}
```

Check if a certificate was valid in the past:

```
POST http://certificate-check.local:8080/
Content-Type: application/json

{
"SubjectCertificate": "-----BEGIN CERTIFICATE-----\n7Cg7\n-----END CERTIFICATE-----",
"Truststore": "\n-----BEGIN CERTIFICATE-----\nq+QlAC\n-----END CERTIFICATE-----",
"ReferenceTime": "2020-11-26T13:50:12Z"
}
```

Response codes are the primary response message. 
```
204 No Content: the certificate is found to be valid
400 Bad Request: the certificate is invalid. More info available in the body.
```
