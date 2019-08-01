# 白名单业务的业务封装
import json
from public.RequestMode import api_request
from public import commen
import global_params as gp

api_dict = commen.get_api("/PolicyManage.json")
api_dict = api_dict["WhiteList"]


class WhitelistWay(object):
    def addruler(self, payload):
        res = api_request(api_dict["increase"]["url"], api_dict["increase"]["header"], api_dict["increase"]["method"],
                          payload)
        res = json.loads(res.content)
        assert res['message'] =="success", "%s,新增白名单失败" % res['message']

    def getlist(self):
        res = api_request(api_dict["whitelist"]["url"], api_dict["whitelist"]["header"],
                          api_dict["whitelist"]["method"])
        res = json.loads(res.content)
        return res

    def clear(self):
        payload = {}
        res = api_request(api_dict["clear"]["url"], api_dict["clear"]["header"], api_dict["clear"]["method"],
                          payload=payload)
        return res

    def state_change(self, state, IDlist):
        payload = {"cmdType": state, "ids": IDlist}
        res = api_request(api_dict["status"]["url"], api_dict["status"]["header"], api_dict["status"]["method"],
                          payload=payload)
        res = json.loads(res.content.decode("utf-8"))
        return res


if __name__ == '__main__':
    test = WhitelistWay()
    res = test.state_change("start",[305])
    print(res)
