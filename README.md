# Conker: Confidential Docker Engine for TDX

> ⚠️ **Disclaimer**  
> This project is a **prototype/alpha version** and has **not been audited for security**.  
> It is intended for **research and experimentation only** and **must not be used in production**.  
> Use at your own risk.

## Overview

**Conker** is a Confidential Docker Engine designed to run containers inside Intel TDX-based Confidential Virtual Machines (CVMs). It aims to bring containerized workloads into trusted execution environments with minimal changes to existing workflows.

This repository includes:
- A custom container runtime interface for CVMs
- TDX-specific logic to manage measurements and secrets
- Integration hooks for the confidential base image (e.g., `cvm-base:latest`)

## Features

- Launch containers in a TDX-backed CVM
- Support for injecting secrets via confidential channels

## Getting Started

### Requirements

- Intel TDX-enabled host with KVM support
- QEMU with TDX support
- `cvm-base:latest` image built and available locally (see [conker-base repo](https://github.com/iExecBlockchainComputing/conker-base))

### Build

## 1. Set up Conker

```bash
cd hack &&
bash release.sh package-debug &&
sudo rm -rf /opt/cvm/runtime/conker-5/ &&
sudo service conker-5 stop &&
cd package &&
rm -rf initrd-conker-ra-latest-debug &&
unzip initrd-conker-ra-latest-debug.zip &&
cd initrd-conker-ra-latest-debug/ &&
sudo bash install.sh setconf &&
sudo bash install.sh run host
```

Ensure that Conker is running:

```bash
service conker-5 status
```

## 2. Build the secret broker server 

```bash
cd src/secret-broker-server 
docker build --no-cache  -f docker/Dockerfile -t secret-broker-server . 
```

## 3. Build the example app 

```bash
cd example/gotest/hack
bash release.sh buildimage
```

The image name is `conker-example-app:latest`.

Then get the image Id for attestation.

```bash
docker inspect conker-example-app:latest | grep Id
```

Remove the `sha256:` prefix , get the hash value like `ba6acccedd2923aee...`.

## 4.deploy the secret server 

# a. Prepare secret

```bash
mkdir -p $(pwd)/local-secret
echo {\"key\":\"123456\"} > $(pwd)/local-secret/secret.json
```

# b. Get the CVM's measurement from admins and the Docker image's ID in step 2

# c. Run the secret broker server 

```bash
docker run --net=host -v $(pwd)/local-secret:/secret secret-broker-server -m -i 0.0.0.0 -p 3333  -w <CVM's measurement> -v tdx_ecdsa -a nullattester -s /secret/secret.json
```

Example:

```bash
docker run --net=host -v $(pwd)/local-secret:/secret secret-broker-server -m -i 0.0.0.0 -p 3333  -v tdx_ecdsa -a nullattester -s /secret/secret.json -d 5d46e8181aa30e0b217de650b4e26c1f155ad4a7a851d3d06b585173207366f7 -w ad9e5e8b206fd3c17bf550cf5b0892d4e1a8a3ca06720263ba11a4bf8a9a648cc8a82df2ed76f15e1753e9ea8704e326
```

`-w` for set cvm's measurement, for tdx is the hash of rtmr[1]
`-s` for set json format secret, support hot load
`-p` for set server's port 

After running the server, get the server's endpoint called `kmsendpoint` as belows.

## 4. Deploy the app container 

# a. Create a container

# Create a task for the container with this config:

```bash
curl --location --request POST 'http://192.168.122.5:8383/sw/api/v1/container' \
--header 'Authorization: ' \
--header 'Content-Type: application/json' \
--data-raw '{
    "Name": "conker-example-app",
    "ImageInfo": {
        "ImageName": "reckey/conker-example-app:latest",
        "RegisterAuthInfo": {
            "Username": "",
            "Password": ""
        }
    },
    "Ports": [
        {
            "TargetPort": 8080,
            "PublishedPort": 30001
        }
    ],
    "Env": [
        "userId=secret-145.239.161.248:3333"
    ],
    "Mounts": [
        {
            "Type": "volume",
            "Target": "/inner1",
            "Source": "test-api",
            "RW": true
        },
        {
            "Type": "volume",
            "Target": "/inner2",
            "Source": "test-v",
            "RW": true
        }
    ],
    "KmsEndpoints": [
        "145.239.161.248:3333"
    ]
}'
```

In the Container create config:

`ImageName` is the Docker image URL you want to run in the CVM, it always pull from remote register;
`RegisterAuthInfo` is the regiser auth info needed if the image is private;
`Ports` is a set of ports your container wants to expose;
`Env` is a set of environment variables;
`Mounts` is a set of Docker volumes (Warning: the volumes are encrypted and will be deleted when the container is deleted);
`KmsEndpoints` is the endpoint of the secret broker server. 

The conker-example-app is a test server with a restful API to get the secret. 
The platform will do remote attestation from the kmsEndpoints and save the JSON secret as a file named `secret-<kmsEndpoints>.json` in the `/secret` directory.



# b. Get the container task info

```shell
curl --location --request GET 'http://192.168.122.5:8383/sw/api/v1/container' \
--header 'Authorization;' \
--data-raw ''
```

# Response:

```json
{
        "Id": "279966be-3c9c-4e69-99eb-1bc4748406e2",
        "ContainerConf": {
            "Name": "conker-example-app",
            "Env": [
                "userId=secret-10.10.11.109:3333"
            ],
            "ImageInfo": {
                "RegisterAuthInfo": {
                    "Username": "",
                    "Password": ""
                },
                "ImageName": "reckey/conker-example-app:latest"
            },
            "Ports": [
                {
                    "PublishedPort": 30001,
                    "TargetPort": 8080
                }
            ],
            "Mounts": [
                {
                    "Type": "volume",
                    "Source": "test-api",
                    "Target": "/inner"
                },
                {
                    "Type": "volume",
                    "Source": "tes-v",
                    "Target": "/1inner"
                },
                {
                    "Type": "bind",
                    "Source": "/secret",
                    "Target": "/secret",
                    "ReadOnly": true
                },
                {
                    "Type": "bind",
                    "Source": "/workplace/encryptedData/user-cert",
                    "Target": "/cert",
                    "ReadOnly": true
                }
            ],
            "KmsEndpoints": [
                "10.10.11.109:3333"
            ]
        },
        "Status": "Running",
        "IsCancel": false,
        "Events": [
            {
                "Action": "Pulling",
                "Message": "begin to pull image: reckey/conker-example-app:latest",
                "Time": "2024-05-07T11:11:59.158700127+08:00"
            },
            {
                "Action": "Pulled ",
                "Message": "pull image: reckey/conker-example-app:latest successfully\n",
                "Time": "2024-05-07T11:11:59.71069888+08:00"
            },
            {
                "Action": "Attesting",
                "Message": "begin to do remote attestation",
                "Time": "2024-05-07T11:11:59.710868131+08:00"
            },
            {
                "Action": "Attested",
                "Message": "do remote attesting successful",
                "Time": "2024-05-07T11:11:59.988890026+08:00"
            },
            {
                "Action": "Creating",
                "Message": "begin to create container",
                "Time": "2024-05-07T11:11:59.989081077+08:00"
            },
            {
                "Action": "Created",
                "Message": "create container successful: []",
                "Time": "2024-05-07T11:12:00.009323245+08:00"
            },
            {
                "Action": "Starting",
                "Message": "begin to start container",
                "Time": "2024-05-07T11:12:00.009505966+08:00"
            },
            {
                "Action": "Running",
                "Message": "container conker-example-app is running",
                "Time": "2024-05-07T11:12:00.693333285+08:00"
            }
        ],
        "ContainerInspect": {
            "Id": "640c4b3149210264a31c1eb4670e5df24c793649fb7f50a0f006f6e4636e861d",
            "Created": "2024-05-07T03:11:59.992894409Z",
            "Path": "./conker-example-app",
            "Args": [],
            "State": {
                "Status": "running",
                "Running": true,
                "Paused": false,
                "Restarting": false,
                "OOMKilled": false,
                "Dead": false,
                "Pid": 345493,
                "ExitCode": 0,
                "Error": "",
                "StartedAt": "2024-05-07T03:12:00.692658501Z",
                "FinishedAt": "0001-01-01T00:00:00Z"
            },
            "Image": "sha256:5d46e8181aa30e0b217de650b4e26c1f155ad4a7a851d3d06b585173207366f7",
            "HostConfig": {
                "PortBindings": {
                    "8080/tcp": [
                        {
                            "HostIp": "0.0.0.0",
                            "HostPort": "30001"
                        }
                    ]
                },
                "RestartPolicy": {
                    "Name": "always",
                    "MaximumRetryCount": 0
                },  
                "Mounts": [
                    {
                        "Type": "volume",
                        "Source": "test-api",
                        "Target": "/inner"
                    },
                    {
                        "Type": "volume",
                        "Source": "tes-v",
                        "Target": "/1inner"
                    }
                ]
            }, 
            "Config": {
                "ExposedPorts": {
                    "8080/tcp": {}
                },
                "Env": [
                    "userId=secret-10.10.11.109:3333",
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ],
                "Cmd": null,
                "Image": "reckey/conker-example-app:latest",
                "Volumes": null,
                "WorkingDir": "/workplace/app",
                "Entrypoint": [
                    "./conker-example-app"
                ]
            }
        }
    }
```

If you see ContainerInspect.State.Status = Running, it means that your container is running successfully.
Otherwise you can read the events to find errors.

If it's running successfully, you can get the secret like this: 

```
curl --location --request GET 'http://192.168.122.5:30001/api/v1/getsecret'
```

Response with the secret: 

```json
{
    "code": 200,
    "message": "get secret successful",
    "data": "{\"key\":\"123456\"}\n"
}
```

# c. Delete the container

Delete the task and remove all things about your container, such as image and volumes:

```shell 
curl --location --request DELETE 'http://192.168.122.5:8383/sw/api/v1/container' \
--header 'Authorization;' \
--data-raw ''
```

# d. Cancel the container task

Cancel the task when the container is in creating mode:

```shell
curl --location --request POST 'http://<platformIp>:8383/sw/api/v1/container/cancel' \
--header 'Authorization;' \
--data-raw ''
```
