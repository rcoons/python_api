import json, warnings
from LIB import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import global_params as gp
import base64
import re

'''
登录
'''


def login(userinfo):
    user = userinfo
    try:
        warnings.filterwarnings('ignore')
        requests.adapters.DEFAULT_RETRIES = 5
        r = requests.get(url=gp.url_ip + '/capaa/js/encrypt/encrypt.json', verify=False)  # 获取公钥接口
        # 密码加密
        pwd = add_enscypt(json.loads(r.text)['publicKey'], user["password"])
        # 登录
        response = requests.post(url=gp.url_ip + user["login_url"] % (user["username"], pwd), verify=False)
        result = response.request.headers['Cookie']
        cookies = re.split('=|;', result)[1]
        #print(cookies)
        return cookies
    except Exception as e:
        print('登录失败:s%', e)


'''
将公钥加密成私钥
password 为密码
'''


def add_enscypt(publickey, password):
    publickey = b'-----BEGIN PUBLIC KEY-----\n' + bytes(publickey, 'utf8') + b'\n' + b'-----END PUBLIC KEY-----'
    raskey = RSA.import_key(publickey)
    cipher = PKCS1_v1_5.new(raskey)
    # cipher_text = base64.b64encode(cipher.encrypt(password))
    cipher_text = base64.b64encode(cipher.encrypt(bytes(password, 'utf8')))
    pravitekey = str(cipher_text, encoding='utf8').replace('+', '%2B')
    return pravitekey


if __name__ == '__main__':
    login(gp.userinfo)
