# conker-example-app

An example written in Go, demonstrating how to read secrets, read database configuration information, and persistently save files

## Build Image
```shell
cd hack
bash release.sh buildimage
```
The built image is named `conker-example-app:latest`

## Deploy Image
1) Save the image
```shell
docker save conker-example-app:latest >conker-example-app.tar
```
2) Deploy and run

- Configure the container port to `8080` and the external port to `30001`
- Set the environment variable `userId` to the user ID of the secret to be read
- Mount the directory `/data` during deployment

## API Testing
### 1. Get key API

```shell
curl <ip>:30001/api/v1/getsecret
```


