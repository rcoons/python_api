'''
模块：漏洞特征库
功能sql注入规则是否生效校验
author:xujianzhong
'''
import unittest, time
from public import commen

from casemap.basicfunc.policymanage import sqlinject
from public.log import LOG, logger
from casemap import Virtualpatch_Case, SqlInject_Case, DBSecurityconf_Case
from casemap.basicfunc.policymanage import dbservice
import global_params as gp

'''
开始：关闭sql特征库规则，开启虚拟补丁规则
结束：开启sql特征库规则，关闭虚拟补丁规则
'''


class Virtual_check_rule(unittest.TestCase):
    sqlinject_dict = sqlinject.sqlinject_dict  # 获取参数配置
    db_dict = dbservice.dbservice_dict['createdbserver']['body']
    param = sqlinject_dict['add_diy_rule']['param']
    rule = ['[自定义规则-漏洞风险]', '业务全审计']
    sql = None
    name = None

    @classmethod
    def setUpClass(cls):
        for name in gp.dbnamelist():
            DBSecurityconf_Case.update_switch(featuresStatus=0, virStatus=1, name=name)
        time.sleep(30)

    def setUp(self):
        self.sql = commen.PutsqlName('SELECT * FROM TABLE')
        self.name = commen.PutsqlName('')

    @logger('漏洞特征库-通用类型数据库，风险等级为低，状态启用')
    def test_virtual_all_low_start_0(self):
        '''漏洞特征库-通用类型数据库，oracle-风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='oracle',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])

    @logger('漏洞特征库-通用类型数据库，风险等级为低，状态启用')
    def test_virtual_all_low_start_1(self):
        '''漏洞特征库-通用类型数据库，mysql-风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='mysql',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])

    @logger('漏洞特征库-通用类型数据库，风险等级为低，状态启用')
    def test_virtual_all_low_start_2(self):
        '''漏洞特征库-通用类型数据库，sqlserver-风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='sqlserver',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])

    # @logger('漏洞特征库-通用类型数据库，风险等级为低，状态启用')
    # def test_virtual_all_low_start_3(self):
    #     '''漏洞特征库-通用类型数据库，db2-风险等级为低，状态启用'''
    #     Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
    #                                               name=self.name,
    #                                               risk_level=self.param['riskLevel'][1],
    #                                               status=self.param['vpStatus'][2],
    #                                               ruleType=self.param['ruleType']['漏洞特征库'],
    #                                               dbtype='db2',
    #                                               sql=self.sql,
    #                                               rulename=self.rule[0] + self.name,
    #                                               cn_risk_level=self.param['风险级别']['低'],
    #                                               cn_res_behavior=self.param['响应行为']['告警'])

    @logger('漏洞特征库-通用类型数据库，风险等级为低，状态启用')
    def test_virtual_all_low_start_4(self):
        '''漏洞特征库-通用类型数据库，gbase_s83-风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='gbase_s83',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
    def test_virtual_all_low_start_5(self):
        '''漏洞特征库-通用类型数据库，dm-风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='dm',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
    def test_virtual_all_low_start_6(self):
        '''漏洞特征库-通用类型数据库，dm-风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='hive',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
    @logger('漏洞特征库-通用类型数据库，风险等级为中，状态启用')
    def test_virtual_all_middle_start_0(self):
        '''漏洞特征库-通用类型数据库，oracle-风险等级为中，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='oracle',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为中，状态启用')
    def test_virtual_all_middle_start_1(self):
        '''漏洞特征库-通用类型数据库，mysql-风险等级为中，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='mysql',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为中，状态启用')
    def test_virtual_all_middle_start_2(self):
        '''漏洞特征库-通用类型数据库，sqlserver-风险等级为中，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='sqlserver',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
    # def test_virtual_all_middle_start_3(self):
    #     '''漏洞特征库-通用类型数据库，db2-风险等级为中，状态启用'''
    #     Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
    #                                               name=self.name,
    #                                               risk_level=self.param['riskLevel'][2],
    #                                               status=self.param['vpStatus'][2],
    #                                               ruleType=self.param['ruleType']['漏洞特征库'],
    #                                               dbtype='db2',
    #                                               sql=self.sql,
    #                                               rulename=self.rule[0] + self.name,
    #                                               cn_risk_level=self.param['风险级别']['中'],
    #                                               cn_res_behavior=self.param['响应行为']['阻断行为'])
    def test_virtual_all_middle_start_4(self):
        '''漏洞特征库-通用类型数据库，gbase_s83-风险等级为中，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='gbase_s83',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
    def test_virtual_all_middle_start_5(self):
        '''漏洞特征库-通用类型数据库，hive-风险等级为中，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='hive',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
    def test_virtual_all_middle_start_6(self):
        '''漏洞特征库-通用类型数据库，dm-风险等级为中，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='dm',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为高，状态启用')
    def test_virtual_all_high_start_0(self):
        '''漏洞特征库-通用类型数据库，oracle-风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='oracle',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为高，状态启用')
    def test_virtual_all_high_start_1(self):
        '''漏洞特征库-通用类型数据库，mysql-风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='mysql',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为高，状态启用')
    def test_virtual_all_high_start_2(self):
        '''漏洞特征库-通用类型数据库，sqlserver-风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='sqlserver',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    # @logger('漏洞特征库-通用类型数据库，风险等级为高，状态启用')
    # def test_virtual_all_high_start_3(self):
    #     '''漏洞特征库-通用类型数据库，db2-风险等级为高，状态启用'''
    #     Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
    #                                               name=self.name,
    #                                               risk_level=self.param['riskLevel'][3],
    #                                               status=self.param['vpStatus'][2],
    #                                               ruleType=self.param['ruleType']['漏洞特征库'],
    #                                               dbtype='db2',
    #                                               sql=self.sql,
    #                                               rulename=self.rule[0] + self.name,
    #                                               cn_risk_level=self.param['风险级别']['高'],
    #                                               cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为高，状态启用')
    def test_virtual_all_high_start_4(self):
        '''漏洞特征库-通用类型数据库，dm-风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='dm',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为高，状态启用')
    def test_virtual_all_high_start_5(self):
        '''漏洞特征库-通用类型数据库，hive-风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='hive',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为高，状态启用')
    def test_virtual_all_high_start_6(self):
        '''漏洞特征库-通用类型数据库，gbase_s83-风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='gbase_s83',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为极高，状态启用')
    def test_virtual_all_Veryhigh_start_0(self):
        '''漏洞特征库-通用类型数据库，oracle-风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='oracle',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为极高，状态启用')
    def test_virtual_all_Veryhigh_start_1(self):
        '''漏洞特征库-通用类型数据库，mysql-风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='mysql',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为极高，状态启用')
    def test_virtual_all_Veryhigh_start_2(self):
        '''漏洞特征库-通用类型数据库，sqlserver-风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='sqlserver',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    # @logger('漏洞特征库-通用类型数据库，风险等级为极高，状态启用')
    # def test_virtual_all_Veryhigh_start_3(self):
    #     '''漏洞特征库-通用类型数据库，db2-风险等级为极高，状态启用'''
    #     Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
    #                                               name=self.name,
    #                                               risk_level=self.param['riskLevel'][4],
    #                                               status=self.param['vpStatus'][2],
    #                                               ruleType=self.param['ruleType']['漏洞特征库'],
    #                                               dbtype='db2',
    #                                               sql=self.sql,
    #                                               rulename=self.rule[0] + self.name,
    #                                               cn_risk_level=self.param['风险级别']['极高'],
    #                                               cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为极高，状态启用')
    def test_virtual_all_Veryhigh_start_4(self):
        '''漏洞特征库-通用类型数据库，dm-风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='dm',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为极高，状态启用')
    def test_virtual_all_Veryhigh_start_5(self):
        '''漏洞特征库-通用类型数据库，hive-风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='hive',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-通用类型数据库，风险等级为极高，状态启用')
    def test_virtual_all_Veryhigh_start_6(self):
        '''漏洞特征库-通用类型数据库，gbase_s83-风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=1,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='gbase_s83',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('漏洞特征库-oracle类型数据库，风险等级为低，状态启用')
    def test_virtual_oracle_low_start(self):
        '''漏洞特征库-oracle类型数据库，风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='oracle',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-oracle类型数据库，风险等级为中，状态启用')
    def test_virtual_oracle_middle_start(self):
        '''漏洞特征库-oracle类型数据库，风险等级为中，状态启用'''

        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='oracle',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-oracle类型数据库，风险等级为高，状态启用')
    def test_virtual_oracle_high_start(self):
        '''漏洞特征库-oracle类型数据库，风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='oracle',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-oracle类型数据库，风险等级为极高，状态启用')
    def test_virtual_oracle_Veryhigh_start(self):
        '''漏洞特征库-oracle类型数据库，风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='oracle',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-mysql类型数据库，风险等级为低，状态启用')
    def test_virtual_mysql_low_start(self):
        '''漏洞特征库-mysql类型数据库，风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='mysql',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-mysql类型数据库，风险等级为中，状态启用')
    def test_virtual_mysql_middle_start(self):
        '''漏洞特征库-mysql类型数据库，风险等级为中，状态启用'''

        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='mysql',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-mysql类型数据库，风险等级为高，状态启用')
    def test_virtual_mysql_high_start(self):
        '''漏洞特征库-mysql类型数据库，风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='mysql',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-mysql类型数据库，风险等级为极高，状态启用')
    def test_virtual_mysql_Veryhigh_start(self):
        '''漏洞特征库-mysql类型数据库，风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='mysql',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-sqlserver类型数据库，风险等级为低，状态启用')
    def test_virtual_sqlserver_low_start(self):
        '''漏洞特征库-sqlserver类型数据库，风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='sqlserver',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-sqlserver类型数据库，风险等级为中，状态启用')
    def test_virtual_sqlserver_middle_start(self):
        '''漏洞特征库-sqlserver类型数据库，风险等级为中，状态启用'''

        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='sqlserver',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-sqlserver类型数据库，风险等级为高，状态启用')
    def test_virtual_sqlserver_high_start(self):
        '''漏洞特征库-sqlserver类型数据库，风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='sqlserver',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-sqlserver类型数据库，风险等级为极高，状态启用')
    def test_virtual_sqlserver_Veryhigh_start(self):
        '''漏洞特征库-sqlserver类型数据库，风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='sqlserver',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    # @logger('漏洞特征库-db2类型数据库，风险等级为低，状态启用')
    # def test_virtual_db2_low_start(self):
    #     '''漏洞特征库-db2类型数据库，风险等级为低，状态启用'''
    #     Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
    #                                               name=self.name,
    #                                               risk_level=self.param['riskLevel'][1],
    #                                               status=self.param['vpStatus'][2],
    #                                               ruleType=self.param['ruleType']['漏洞特征库'],
    #                                               dbtype='db2',
    #                                               sql=self.sql,
    #                                               rulename=self.rule[0] + self.name,
    #                                               cn_risk_level=self.param['风险级别']['低'],
    #                                               cn_res_behavior=self.param['响应行为']['告警'])
    #     SqlInject_Case.execsql_rule(dbtype='mysql',
    #                                 sql=self.sql,
    #                                 rulename=self.rule[1],
    #                                 cn_risk_level=self.param['风险级别']['安全'],
    #                                 cn_res_behavior=self.param['响应行为']['通过'])
    #
    # @logger('漏洞特征库-db2类型数据库，风险等级为中，状态启用')
    # def test_virtual_db2_middle_start(self):
    #     '''漏洞特征库-db2类型数据库，风险等级为中，状态启用'''
    #
    #     Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
    #                                               name=self.name,
    #                                               risk_level=self.param['riskLevel'][2],
    #                                               status=self.param['vpStatus'][2],
    #                                               ruleType=self.param['ruleType']['漏洞特征库'],
    #                                               dbtype='db2',
    #                                               sql=self.sql,
    #                                               rulename=self.rule[0] + self.name,
    #                                               cn_risk_level=self.param['风险级别']['中'],
    #                                               cn_res_behavior=self.param['响应行为']['阻断行为'])
    #     SqlInject_Case.execsql_rule(dbtype='mysql',
    #                                 sql=self.sql,
    #                                 rulename=self.rule[1],
    #                                 cn_risk_level=self.param['风险级别']['安全'],
    #                                 cn_res_behavior=self.param['响应行为']['通过'])
    #
    # @logger('漏洞特征库-db2类型数据库，风险等级为高，状态启用')
    # def test_virtual_db2_high_start(self):
    #     '''漏洞特征库-db2类型数据库，风险等级为高，状态启用'''
    #     Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
    #                                               name=self.name,
    #                                               risk_level=self.param['riskLevel'][3],
    #                                               status=self.param['vpStatus'][2],
    #                                               ruleType=self.param['ruleType']['漏洞特征库'],
    #                                               dbtype='db2',
    #                                               sql=self.sql,
    #                                               rulename=self.rule[0] + self.name,
    #                                               cn_risk_level=self.param['风险级别']['高'],
    #                                               cn_res_behavior=self.param['响应行为']['阻断行为'])
    #     SqlInject_Case.execsql_rule(dbtype='mysql',
    #                                 sql=self.sql,
    #                                 rulename=self.rule[1],
    #                                 cn_risk_level=self.param['风险级别']['安全'],
    #                                 cn_res_behavior=self.param['响应行为']['通过'])
    #
    # @logger('漏洞特征库-db2类型数据库，风险等级为极高，状态启用')
    # def test_virtual_db2_Veryhigh_start(self):
    #     '''漏洞特征库-db2类型数据库，风险等级为极高，状态启用'''
    #     Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
    #                                               name=self.name,
    #                                               risk_level=self.param['riskLevel'][4],
    #                                               status=self.param['vpStatus'][2],
    #                                               ruleType=self.param['ruleType']['漏洞特征库'],
    #                                               dbtype='db2',
    #                                               sql=self.sql,
    #                                               rulename=self.rule[0] + self.name,
    #                                               cn_risk_level=self.param['风险级别']['极高'],
    #                                               cn_res_behavior=self.param['响应行为']['阻断行为'])
    #     SqlInject_Case.execsql_rule(dbtype='mysql',
    #                                 sql=self.sql,
    #                                 rulename=self.rule[1],
    #                                 cn_risk_level=self.param['风险级别']['安全'],
    #                                 cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-gbase类型数据库，风险等级为低，状态启用')
    def test_virtual_gbase_low_start(self):
        '''漏洞特征库-gbase类型数据库，风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='gbase_s83',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-gbase类型数据库，风险等级为中，状态启用')
    def test_virtual_gbase_middle_start(self):
        '''漏洞特征库-gbase类型数据库，风险等级为中，状态启用'''

        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='gbase_s83',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-gbase类型数据库，风险等级为高，状态启用')
    def test_virtual_gbase_high_start(self):
        '''漏洞特征库-gbase类型数据库，风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='gbase_s83',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-gbase类型数据库，风险等级为极高，状态启用')
    def test_virtual_gbase_Veryhigh_start(self):
        '''漏洞特征库-gbase类型数据库，风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='gbase_s83',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-dm类型数据库，风险等级为低，状态启用')
    def test_virtual_dm_low_start(self):
        '''漏洞特征库-dm类型数据库，风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='dm',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-dm类型数据库，风险等级为中，状态启用')
    def test_virtual_dm_middle_start(self):
        '''漏洞特征库-dm类型数据库，风险等级为中，状态启用'''

        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='dm',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-dm类型数据库，风险等级为高，状态启用')
    def test_virtual_dm_high_start(self):
        '''漏洞特征库-dm类型数据库，风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='dm',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-dm类型数据库，风险等级为极高，状态启用')
    def test_virtual_dm_Veryhigh_start(self):
        '''漏洞特征库-dm类型数据库，风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='dm',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-hive类型数据库，风险等级为低，状态启用')
    def test_virtual_hive_low_start(self):
        '''漏洞特征库-hive类型数据库，风险等级为低，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][1],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='hive',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['低'],
                                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-hive类型数据库，风险等级为中，状态启用')
    def test_virtual_hive_middle_start(self):
        '''漏洞特征库-hive类型数据库，风险等级为中，状态启用'''

        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][2],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='hive',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['中'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-hive类型数据库，风险等级为高，状态启用')
    def test_virtual_hive_high_start(self):
        '''漏洞特征库-hive类型数据库，风险等级为高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][3],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='hive',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('漏洞特征库-hive类型数据库，风险等级为极高，状态启用')
    def test_virtual_hive_Veryhigh_start(self):
        '''漏洞特征库-hive类型数据库，风险等级为极高，状态启用'''
        Virtualpatch_Case.virtualpatch_check_rule(isAll=2,
                                                  name=self.name,
                                                  risk_level=self.param['riskLevel'][4],
                                                  status=self.param['vpStatus'][2],
                                                  ruleType=self.param['ruleType']['漏洞特征库'],
                                                  dbtype='hive',
                                                  sql=self.sql,
                                                  rulename=self.rule[0] + self.name,
                                                  cn_risk_level=self.param['风险级别']['极高'],
                                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    def tearDown(self):
        LOG.info('启用验证成功，等待删除。。。')
        Virtualpatch_Case.virtualpatch_del_rule(name=self.name)

    @classmethod
    def tearDownClass(cls):
        for name in gp.dbnamelist():
            DBSecurityconf_Case.update_switch(featuresStatus=1, virStatus=0, name=name)
        time.sleep(30)
