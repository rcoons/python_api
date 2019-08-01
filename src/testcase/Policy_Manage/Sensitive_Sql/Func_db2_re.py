########################################################################################################################
# FUNC:敏感sql新增db2类型
# author：liupengju
# description: 1.新增-自定义规则，payload类型为模糊sql-正则表达式
#              2.选择db2类型数据库，风险等级分别为高，中，低，极高，状态启用
# 预期结果：
# 1.在db2的客户端执行sql语句，执行sql语句被阻断（低风险不被阻断），有审计，显示风险等级，匹配到自定义规则
# 2.其他类型数据库执行该语句，正常通行不匹配到，不被阻断
########################################################################################################################
import unittest
from casemap.Sensitive_Case import SensitiveSql
from public.log import LOG, logger
import global_params as gp
from config.globalconfig import GlobalConfig
from public import commen
from casemap.basicfunc.policymanage.Sensitive_Way import SensitiveWay
from casemap.basicfunc.policymanage import dbservice


class DB2SqlRe(unittest.TestCase):
    def setUp(self):
        self.sqllist = commen.PutsqlNum()
        self.ruler_name = commen.PutsqlName("db2_")
        LOG.info("规则名称：%s" % self.ruler_name)
        LOG.info("SQL语句：%s" % self.sqllist)
        self.sensql = SensitiveSql(self.ruler_name, GlobalConfig.db_type_['DB2'],
                                   dbservice.select_dbservice_byname(gp.run_db["db2"]))
        self.sensitiveway = SensitiveWay()

    @logger('敏感db2类型低风险')
    def test_db2_re_risk1(self):
        '''敏感db2类型低风险'''
        self.sensql.sqlrisk_re(gp.risk_level['risk_low'], self.sqllist, gp.risk_info[1])

    @logger('敏感db2类型中风险')
    def test_db2_re_risk2(self):
        '''敏感db2类型中风险'''
        self.sensql.sqlrisk_re(gp.risk_level['risk_mid'], self.sqllist, gp.risk_info[2])

    @logger('敏感db2类型高风险')
    def test_db2_re_risk3(self):
        '''敏感db2类型高风险'''
        self.sensql.sqlrisk_re(gp.risk_level['risk_high'], self.sqllist, gp.risk_info[3])

    @logger('敏感db2类型极高风险')
    def test_db2_re_risk4(self):
        '''敏感db2类型极高风险'''
        self.sensql.sqlrisk_re(gp.risk_level['risk_higher'], self.sqllist, gp.risk_info[4])

    def tearDown(self):
        LOG.info("删除新增sql规则")
        self.sensitiveway.del_ruler(self.ruler_name)
