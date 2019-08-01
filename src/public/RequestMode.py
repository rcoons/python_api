from LIB import requests
import global_params as gp
import warnings


def api_request(api_url, headers=None, method=None, payload=None):
    warnings.filterwarnings('ignore')
    cookies = gp.cookies
    if method == "POST":
        response = requests.post(url=gp.url_ip + api_url, json=payload, headers=headers, cookies=cookies, verify=False)
        return response

    if method == "GET":
        response = requests.get(url=gp.url_ip + api_url, headers=headers, cookies=cookies, verify=False)
        return response


if __name__ == "__main__":
    api_request("192")
