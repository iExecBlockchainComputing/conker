+ build

```bash
docker build --no-cache --build-arg https_proxy=http://*:10080 -f docker/Dockerfile -t secret-broker-server . 
```

+ run 
prepare a secret.json for save secret ,then save in the dir of local-secret. eg

```bash
mkdir -p $pwd/local-secret
echo {\"key\":\"123456\"} > secret.json

```

docker run the server
```bash
docker run --net=host -v $pwd/local-secret:/secret secret-broker-server -m -i 0.0.0.0 -p 3333  -w 7389bc275d456c2cc2708f1ef50cb96d3b5fb03799267fb0e049f536d3e3ba2e -v tdx_ecdsa -a nullattester -s /secret/secret.json -d 50508f769b4805e337b4fd2becb8b71b440a6d123383955c13a8e2bbade00eb4
```

`-w` for set cvm's measurement
`-d` for set docker-image's id 
`-s` for set json format secret, support hot load

