########################################################################################################################
# FUNC:敏感sql新增hive类型
# author：liupengju
# description: 1.新增-自定义规则，payload类型为模糊sql-正则表达式
#              2.选择hive类型数据库，风险等级分别为高，中，低，极高，状态禁用
# 预期结果：
# 1.在hive的客户端执行sql语句，执行sql语句被阻断（低风险不被阻断），有审计，显示风险等级，匹配到自定义规则
# 2.其他类型数据库执行该语句，正常通行不匹配到，不被阻断
########################################################################################################################
import unittest
from casemap.Sensitive_Case import SensitiveSql
from public.log import LOG, logger
import global_params as gp
from config.globalconfig import GlobalConfig
from public import commen
from casemap.basicfunc.policymanage import dbservice
from casemap.basicfunc.policymanage.Sensitive_Way import SensitiveWay
from DBLib import sql_execute


class HiveSqlReOff(unittest.TestCase):
    def setUp(self):
        self.dbtable = commen.PutsqlName("dbtable_")
        self.sqllist = "SELECT * FROM " + self.dbtable
        self.ruler_name = commen.PutsqlName("hive_")
        LOG.info("规则名称：%s" % self.ruler_name)
        LOG.info("SQL语句：%s" % self.sqllist)
        self.sensql = SensitiveSql(self.ruler_name, GlobalConfig.db_type_['hive'],
                                   dbservice.select_dbservice_byname(gp.run_db['hive']))
        self.sensitiveway = SensitiveWay()

    @logger('敏感hive类型低风险禁用')
    def test_hive_re_off_risk1(self):
        '''敏感hive类型低风险禁用'''
        self.sensql.sqlrisk_re_off(gp.risk_level['risk_low'], self.sqllist)

    @logger('敏感hive类型中风险禁用')
    def test_hive_re_off_risk2(self):
        '''敏感hive类型中风险禁用'''
        self.sensql.sqlrisk_re_off(gp.risk_level['risk_mid'], self.sqllist)

    @logger('敏感hive类型高风险禁用')
    def test_hive_re_off_risk3(self):
        '''敏感hive类型高风险禁用'''
        self.sensql.sqlrisk_re_off(gp.risk_level['risk_high'], self.sqllist)

    @logger('敏感hive类型极高风险禁用')
    def test_hive_re_off_risk4(self):
        '''敏感hive类型极高风险禁用'''
        self.sensql.sqlrisk_re_off(gp.risk_level['risk_higher'], self.sqllist)

    def tearDown(self):
        LOG.info("删除新增sql规则")
        self.sensitiveway.del_ruler(self.ruler_name)
