'''敏感sql的测试集'''
import global_params as gp
from public import commen
from public.log import LOG
from casemap.basicfunc.policymanage.Sensitive_Way import SensitiveWay
from public import dbcon_ssh
from config.globalconfig import GlobalConfig
import time


class SensitiveSql(object):
    def __init__(self, name, dbType, dbId,dbType2=GlobalConfig.db_type_['mysql']):
        self.payload = {}
        self.payload["name"] = name
        self.payload["description"] = name
        self.payload["dbType"] = dbType
        self.payload["dbId"] = dbId
        self.dbType2 = dbType2
        self.api_dict = commen.get_api("/PolicyManage.json")

    def sqlrisk_re(self, risklevel, sqllist, respond):
        self.payload["riskLevel"] = risklevel
        self.payload["status"] = 1
        self.payload["payloadType"] = "fuzzySQL"
        self.payload["payloadContent"] = "select\\s*(from|\\s*)\\s+((?!where).)*$"
        self.api_dict = self.api_dict["SensitiveSql"]["increase"]
        self.SensitiveWay = SensitiveWay()
        LOG.info(self.api_dict)
        LOG.info("规则名称：%s" % self.payload["name"])
        LOG.info("当前sql类型：%s" % self.payload["payloadType"])
        LOG.info("新增一条%s类型的sql规则" % self.payload["dbType"])
        self.SensitiveWay.add_ruler(self.api_dict, self.payload)
        time.sleep(10)
        LOG.info("在%s客户端执行该语句" % self.payload["dbType"])
        self.SensitiveWay.dbcon_way(sqllist, self.payload["dbType"])
        LOG.info("在审计查询里面查找，sql语句应被阻断")
        self.SensitiveWay.shenji_check_risk(self.payload["name"], sqllist, respond, risklevel)
        LOG.info("在%s客户端执行该语句" % self.dbType2)
        self.SensitiveWay.dbcon_way(sqllist, self.dbType2)
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)

    def sqlrisk_re_off(self, risklevel, sqllist):
        self.payload["riskLevel"] = risklevel
        self.payload["status"] = 0
        self.payload["payloadType"] = "fuzzySQL"
        self.payload["payloadContent"] = "select\\s*(from|\\s*)\\s+((?!where).)*$"
        self.api_dict = self.api_dict["SensitiveSql"]["increase"]
        self.SensitiveWay = SensitiveWay()
        LOG.info(self.api_dict)
        LOG.info("规则名称：%s" % self.payload["name"])
        LOG.info("当前sql类型：%s" % self.payload["payloadType"])
        LOG.info("新增一条%s类型的sql规则" % self.payload["dbType"])
        self.SensitiveWay.add_ruler(self.api_dict, self.payload)
        time.sleep(10)
        LOG.info("在%s客户端执行该语句" % self.payload["dbType"])
        self.SensitiveWay.dbcon_way(sqllist, self.payload["dbType"])
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)
        LOG.info("在%s客户端执行该语句" % self.dbType2)
        self.SensitiveWay.dbcon_way(sqllist, self.dbType2)
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)

    def sqlrisk_stand(self, risklevel, sqllist, respond):
        self.payload["riskLevel"] = risklevel
        self.payload["status"] = 1
        self.payload["payloadType"] = "standardSQL"
        self.payload["payloadContent"] = sqllist
        self.api_dict = self.api_dict["SensitiveSql"]["increase"]
        self.SensitiveWay = SensitiveWay()
        LOG.info(self.api_dict)
        LOG.info("规则名称：%s" % self.payload["name"])
        LOG.info("当前sql类型：%s" % self.payload["payloadType"])
        LOG.info("新增一条%s类型的sql规则" % self.payload["dbType"])
        self.SensitiveWay.add_ruler(self.api_dict, self.payload)
        time.sleep(10)
        LOG.info("在%s客户端执行该语句" % self.payload["dbType"])
        self.SensitiveWay.dbcon_way(sqllist, self.payload["dbType"])
        LOG.info("在审计查询里面查找，sql语句应被阻断")
        self.SensitiveWay.shenji_check_risk(self.payload["name"], sqllist, respond, risklevel)
        LOG.info("在%s客户端执行该语句" % self.dbType2)
        self.SensitiveWay.dbcon_way(sqllist, self.dbType2)
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)

    def sqlrisk_stand_off(self, risklevel, sqllist):
        self.payload["riskLevel"] = risklevel
        self.payload["status"] = 0
        self.payload["payloadType"] = "standardSQL"
        self.payload["payloadContent"] = sqllist
        self.api_dict = self.api_dict["SensitiveSql"]["increase"]
        self.SensitiveWay = SensitiveWay()
        LOG.info(self.api_dict)
        LOG.info("规则名称：%s" % self.payload["name"])
        LOG.info("当前sql类型：%s" % self.payload["payloadType"])
        LOG.info("新增一条%s类型的sql规则" % self.payload["dbType"])
        self.SensitiveWay.add_ruler(self.api_dict, self.payload)
        time.sleep(10)
        LOG.info("在%s客户端执行该语句" % self.payload["dbType"])
        self.SensitiveWay.dbcon_way(sqllist, self.payload["dbType"])
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)
        LOG.info("在%s客户端执行该语句" % self.dbType2)
        self.SensitiveWay.dbcon_way(sqllist, self.dbType2)
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)

    def sqlrisk_temp(self, risklevel, sqllist, respond):
        self.payload["riskLevel"] = risklevel
        self.payload["status"] = 1
        self.payload["payloadType"] = "templateSQL"
        self.payload["payloadContent"] = sqllist
        self.api_dict = self.api_dict["SensitiveSql"]["increase"]
        self.SensitiveWay = SensitiveWay()
        LOG.info(self.api_dict)
        LOG.info("规则名称：%s" % self.payload["name"])
        LOG.info("当前sql类型：%s" % self.payload["payloadType"])
        LOG.info("新增一条%s类型的sql规则" % self.payload["dbType"])
        self.SensitiveWay.add_ruler(self.api_dict, self.payload)
        time.sleep(10)
        LOG.info("在%s客户端执行该语句" % self.payload["dbType"])
        self.SensitiveWay.dbcon_way(sqllist, self.payload["dbType"])
        LOG.info("在审计查询里面查找，sql语句应被阻断")
        self.SensitiveWay.shenji_check_risk(self.payload["name"], sqllist, respond, risklevel)
        LOG.info("在%s客户端执行该语句" % self.dbType2)
        self.SensitiveWay.dbcon_way(sqllist, self.dbType2)
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)

    def sqlrisk_temp_off(self, risklevel, sqllist):
        self.payload["riskLevel"] = risklevel
        self.payload["status"] = 0
        self.payload["payloadType"] = "templateSQL"
        self.payload["payloadContent"] = sqllist
        self.api_dict = self.api_dict["SensitiveSql"]["increase"]
        self.SensitiveWay = SensitiveWay()
        LOG.info(self.api_dict)
        LOG.info("规则名称：%s" % self.payload["name"])
        LOG.info("当前sql类型：%s" % self.payload["payloadType"])
        LOG.info("新增一条%s类型的sql规则" % self.payload["dbType"])
        self.SensitiveWay.add_ruler(self.api_dict, self.payload)
        time.sleep(10)
        LOG.info("在%s客户端执行该语句" % self.payload["dbType"])
        self.SensitiveWay.dbcon_way(sqllist, self.payload["dbType"])
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)
        LOG.info("在%s客户端执行该语句" % self.dbType2)
        self.SensitiveWay.dbcon_way(sqllist, self.dbType2)
        LOG.info("在审计查询里面查找，sql语句应不被阻断")
        self.SensitiveWay.shenji_check_safe("业务全审计", sqllist)


if __name__ == '__main__':
    payload = {}
    test = SensitiveSql("oracle125", "sqlserver", 1)
    test.sqlrisk_re(gp.risk_level["risk_high"], "SELECT * FROM P1_5", gp.respond["阻断"])
