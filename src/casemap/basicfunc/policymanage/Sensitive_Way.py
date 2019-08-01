# 敏感sql的业务封装
import json
from public.RequestMode import api_request
from public import commen
import global_params as gp
from DBLib import sql_execute


class SensitiveWay(object):

    def add_ruler(self, api_dict, payload):
        try:
            response = api_request(api_dict['url'], api_dict['header'], api_dict['method'], payload)
            print(response.content.decode('utf-8'))
            response = json.loads(response.content.decode('utf-8'))
        except Exception as e:
            assert e
        assert response['message'] == api_dict['expected']['message'], "%s,新增失败" % response['message']

    def edit_ruler(self, rulername,dbType="oracle",dbID=1,risk=3,sqlType="fuzzySQL",sql="select\\s*(from|\\s*)\\s+((?!where).)*$",status=1):
        payload = {
        "name": rulername,
        "description": rulername,
        "dbType": dbType,
        "dbId": dbID,
        "riskLevel": risk,
        "status": status,
        "payloadType": sqlType,
        "payloadContent": sql}
        api_dict = commen.get_api("/PolicyManage.json")
        api_dict = api_dict["SensitiveSql"]["edit"]
        try:
            rulename, rulerID = commen.getruler_name("/PolicyManage.json", rulername)
            response = api_request(api_dict['url'] % rulerID, api_dict['header'], api_dict['method'], payload)
            print(response.content.decode('utf-8'))
            response = json.loads(response.content.decode('utf-8'))
        except Exception as e:
            assert e
        assert response['message'] == api_dict['expected']['message'], "%s,编辑失败" % response['message']

    def shenji_check_risk(self, srarch_kw, sqltext, respond, risklevel):
        searchinfo = {
            "kw": srarch_kw,
            "sqltext": sqltext
        }
        re_str = commen.shenji_check(searchinfo, respond)
        assert srarch_kw.upper() in re_str, "没有找到%s" % srarch_kw.upper()
        assert sqltext.upper() in re_str, "没有找到%s" % sqltext.upper()
        assert gp.risk_info[risklevel] in re_str, "没有找到%s" % gp.risk_info[risklevel]
        assert respond in re_str, "没有找到%s" % respond

    def shenji_check_safe(self, srarch_kw, sqltext, respond="通过", risklevel=gp.risk_info[0]):
        searchinfo = {
            "kw": srarch_kw,
            "sqltext": sqltext
        }
        re_str = commen.shenji_check(searchinfo, risklevel)
        assert srarch_kw in re_str, "没有找到%s" % srarch_kw
        assert sqltext.upper() in re_str, "没有找到%s" % sqltext.upper()
        assert respond in re_str, "没有找到%s" % respond
        assert risklevel in re_str, "没有找到%s" % risklevel

    def del_ruler(self, target):
        apidict = commen.get_api("/PolicyManage.json")
        apidict = apidict["SensitiveSql"]["delete"]
        idlist = []
        rulername, rulerID = commen.getruler_name("/PolicyManage.json", target)
        idlist.append(rulerID)
        payload = {}
        payload['action'] = apidict['body']['action']
        payload['sqlFeatureDefenseIdList'] = idlist
        api_request(apidict['url'], apidict['header'], apidict['method'], payload)

    def dbcon_way(self, sqllist, dbtype, isexcept=None):
        dbtype = dbtype.lower()
        if dbtype in ["hive", "dm"]:
            commen.jdbcConnect(dbtype, sqllist, isexcept)
        else:
            sql_execute.exec_select(dbtype, sqllist)


if __name__ == '__main__':
    test = SensitiveWay()
    test.dbcon_way("SELECT * FROM dbtable_6tnf","db2")

