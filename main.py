import utime
import random
import ujson
import time
import rsa
import machine
import wlan_password
import string
from ubinascii import b2a_base64
import urequests
import network


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(wlan_password.ssid, wlan_password.password)

    # Wait for connect or fail
    max_wait = 10
    while max_wait > 0:
        if wlan.status() < 0 or wlan.status() >= 3:
            break
        max_wait -= 1
        print('waiting for connection...')
        utime.sleep(1)

    # Handle connection error
    if wlan.status() != 3:
        raise RuntimeError('network connection failed')
    else:
        print('connected')
        status = wlan.ifconfig()
        print( 'ip = ' + status[0] )


# TODO to fix
def set_time():
    rtc_time = time.gmtime(get_now_unix())
    setup_0 = rtc_time[0] << 12 | rtc_time[1] << 8 | rtc_time[2]
    setup_1 = (rtc_time[3] % 7) << 24 | rtc_time[4] << 16 | rtc_time[5] << 8 | rtc_time[6]
    machine.mem32[0x4005c004] = setup_0
    machine.mem32[0x4005c008] = setup_1
    machine.mem32[0x4005c00c] |= 0x10

    # print(utime.localtime())
    # rtc = machine.RTC()
    # rtc.datetime(rtc_time)

def get_now_unix()->int:
    data = urequests.get("http://date.jsontest.com/").json()
    return int(data['milliseconds_since_epoch']/1000)


def b42_urlsafe_encode(payload):
    return string.translate(b2a_base64(payload)[:-1].decode('utf-8'),{ ord('+'):'-', ord('/'):'_' })


def create_jwt(private_key: tuple, algorithm: str, token_ttl: int, service_account_email: str):
    print("Creating JWT...")
    private_key = rsa.PrivateKey(*private_key)

    now = get_now_unix()

    claims = {
            'iat': now,
            'exp': now + token_ttl,
            "scope": "https://www.googleapis.com/auth/cloud-platform",
            "aud": "https://oauth2.googleapis.com/token",
            "iss": service_account_email,
    }
    print(claims)

    #This only supports RS256 at this time.
    header = { "alg": algorithm, "typ": "JWT" }
    content = b42_urlsafe_encode(ujson.dumps(header).encode('utf-8'))
    content = content + '.' + b42_urlsafe_encode(ujson.dumps(claims).encode('utf-8'))
    signature = b42_urlsafe_encode(rsa.sign(content,private_key,'SHA-256'))
    return content+ '.' + signature #signed JWT

def request_token(jwt: str) -> str:
    r = urequests.post(
        "https://oauth2.googleapis.com/token",
        data="grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + jwt,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    r.json()
    return r.json["access_token"]

def insert_bq(inser_id: str, data: dict, project_id: str, dataset_id: str, table_id: str, access_token: str):
    payload = {
        "rows": [
        {
          "insertId": inser_id,
          "json": data,
        }
      ],
    }
    json_payload = ujson.dumps(payload)
    headers = {
        "Authorization": "Bearer "+ access_token,
    }
    r = urequests.post(
        "https://bigquery.googleapis.com/bigquery/v2/projects/" + project_id+"/datasets/"+dataset_id+"/tables/"+table_id+"/insertAll",
        data=json_payload,
        headers=headers,
        )
    print(r.text)

import service_account_private_key
connect_wifi()

service_account_email = "test-curl-jwt@nnyn-dev.iam.gserviceaccount.com"
project_id = "nnyn-dev"
dataset_id = "picow_test"
table_id = "picow_test"
set_time()

jwt = create_jwt(service_account_private_key.private_key, "RS256", 3600, service_account_email)
token = request_token(jwt)

data = {
    "id": 100,
    "value": 100,
}

insert_bq(str(random.random()), data, project_id, dataset_id, table_id, token)
