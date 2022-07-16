# Post BigQuery Direct from Raspberry Pi PICO W

## Create GCP service account key

```
pip install rsa

openssl genrsa -traditional 2048 > rsa_private.pem
cat rsa_private.pem | pem-jwk
openssl req -new -x509 -key rsa_private.pem -out cert.pem -days 3600
python third_party/iot-core-micropython/utils/decode_rsa.py
```

Write service_account_private_key.py.

```
private_key = (18601 ... )
```

Upload cert.pem for GCP service account key.

## upload codes

```sh
rshell

# upload
cp -r third_party/micropython-rsa-signing/rsa /pyboard/
cp third_party/iot-core-micropython/third_party/string.py /pyboard/
cp main.py /pyboard/

# execute
repl ~ import main
```
