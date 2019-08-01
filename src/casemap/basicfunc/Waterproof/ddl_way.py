'''防水坝方法封装'''
import json
from public.RequestMode import api_request
from public import commen
import global_params as gp
from public import dbcon_ssh
from DBLib import sql_execute


class DdlWay(object):
    def shenji_check_risk(self, sqltext, respond, risklevel):
        searchinfo = {
            "kw": '',
            "sqltext": sqltext
        }
        re_str = commen.shenji_check(searchinfo, respond)
        assert sqltext.upper() in re_str, "没有找到%s" % sqltext.upper()
        assert gp.risk_info[risklevel] in re_str, "没有找到%s" % gp.risk_info[risklevel]
        assert respond in re_str, "没有找到%s" % respond

    def setrisk(self, dbid=1, auditLevel=3, status=0, dangerownerId=1):
        payload = {
            "dbid": dbid,
            "assetOwner": "",
            "ownerType": "database account",
            "additionRule": "",
            "auditLevel": auditLevel,
            "status": status,
            "dangerownerId": dangerownerId,
            "part": "danger"
        }
        api_dict = commen.get_api("/DDL.json")
        api_dict = api_dict["riskconfig"]
        try:
            api_request(api_dict['url'] % (
            payload["dbid"], payload["ownerType"], payload["auditLevel"], payload["status"], payload["dangerownerId"],
            payload["part"]), api_dict['header'], api_dict['method'])
        except Exception as e:
            assert e

    def setaccont_action(self, dbid,action):
        api_dict = commen.get_api("/DDL.json")
        api_dict = api_dict["oracle"]["accontmanage"]
        print(api_dict["url"])
        try:
            api_request(api_dict['url'] % (dbid, action), api_dict['header'], api_dict['method'])
        except Exception as e:
            assert e

    def setrole_action(self, dbid,action):
        api_dict = commen.get_api("/DDL.json")
        api_dict = api_dict["oracle"]["rolepermission"]
        print(api_dict["url"])
        try:
            api_request(api_dict['url'] % (dbid, action), api_dict['header'], api_dict['method'])
        except Exception as e:
            assert e

    def setobject_action(self, dbid,action):
        api_dict = commen.get_api("/DDL.json")
        api_dict = api_dict["oracle"]["objectpermission"]
        print(api_dict["url"])
        try:
            api_request(api_dict['url'] % (dbid, action), api_dict['header'], api_dict['method'])
        except Exception as e:
            assert e


if __name__ == "__main__":
    test = DdlWay()
    #test.setrisk(dbid=1, auditLevel=3, status=1, dangerownerId=1)
    test.setaccont_action(1,"1,1,1,1,1")
    test.shenji_check_risk("ALTER AUTHORIZATION ON SCHEMA : : [DB_OWNER] TO [ORCL]","阻断行为",3)