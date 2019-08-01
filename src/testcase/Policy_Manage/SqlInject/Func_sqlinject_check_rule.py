'''
模块：sql注入特征库
功能sql注入规则是否生效校验
author:xujianzhong
'''
import unittest, time
from public import commen

from casemap.basicfunc.policymanage import sqlinject, dbservice
from public.log import LOG, logger
from casemap import SqlInject_Case
from casemap import DBService_Case,DBSecurityconf_Case
from casemap.basicfunc.policymanage import dbservice
import global_params as gp

class SqlInject_check_rule(unittest.TestCase):
    sqlinject_dict = sqlinject.sqlinject_dict  # 获取参数配置
    db_dict = dbservice.dbservice_dict['createdbserver']['body']
    param = sqlinject_dict['add_diy_rule']['param']
    rule = ['[自定义规则-SQL注入]', '业务全审计']
    sql = None
    name = None
    table_name = None

    @classmethod
    def setUpClass(cls):
        for name in gp.dbnamelist():
            DBSecurityconf_Case.update_switch(featuresStatus=1, virStatus=0, name=name)
        time.sleep(30)

    def setUp(self):
        self.table_name = commen.PutsqlName('TABLE')
        self.sql = 'SELECT * FROM ' + self.table_name
        self.name = commen.PutsqlName('')

    @logger('sql注入特征库-通用类型数据库，风险等级为低，状态启用')
    def test_sqlinject_all_low_start(self):
        '''sql注入特征库-通用类型数据库，风险等级为低，状态启用'''

        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=1,name=self.name, risk_level=self.param['riskLevel'][1],
                                  status=self.param['vpStatus'][2], dbtype='oracle', sql=self.sql,
                                  rulename=rulename, cn_risk_level=self.param['风险级别']['低'],
                                  cn_res_behavior=self.param['响应行为']['告警'])

    @logger('sql注入特征库-通用类型数据库，风险等级为中，状态启用')
    def test_sqlinject_all_middle_start(self):
        '''sql注入特征库-通用类型数据库，风险等级为中，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=1,name=self.name, risk_level=self.param['riskLevel'][2],
                                  status=self.param['vpStatus'][2], dbtype='oracle', sql=self.sql,
                                  rulename=rulename, cn_risk_level=self.param['风险级别']['中'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('sql注入特征库-通用类型数据库，风险等级为高，状态启用')
    def test_sqlinject_all_high_start(self):
        '''sql注入特征库-通用类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=1,name=self.name, risk_level=self.param['riskLevel'][3],
                                  status=self.param['vpStatus'][2], dbtype='oracle', sql=self.sql,
                                  rulename=rulename, cn_risk_level=self.param['风险级别']['高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('sql注入特征库-通用类型数据库，风险等级为极高，状态启用')
    def test_sqlinject_all_Veryhigh_start(self):
        '''sql注入特征库-通用类型数据库，风险等级为极高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=1,name=self.name, risk_level=self.param['riskLevel'][4],
                                  status=self.param['vpStatus'][2], dbtype='oracle', sql=self.sql,
                                  rulename=rulename, cn_risk_level=self.param['风险级别']['极高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])

    @logger('sql注入特征库-oracle类型数据库，风险等级为低，状态启用')
    def test_sqlinject_oracle_low_start(self):
        '''sql注入特征库-oracle类型数据库，风险等级为低，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][1],
                                  status=self.param['vpStatus'][2],
                                  dbtype='oracle',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['低'],
                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-oracle类型数据库，风险等级为中，状态启用')
    def test_sqlinject_oracle_middle_start(self):
        '''sql注入特征库-oracle类型数据库，风险等级为中，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][2],
                                  status=self.param['vpStatus'][2],
                                  dbtype='oracle',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['中'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-oracle类型数据库，风险等级为高，状态启用')
    def test_sqlinject_oracle_high_start(self):
        '''sql注入特征库-oracle类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][3],
                                  status=self.param['vpStatus'][2],
                                  dbtype='oracle',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-oracle类型数据库，风险等级为极高，状态启用')
    def test_sqlinject_oracle_Veryhigh_start(self):
        '''sql注入特征库-oracle类型数据库，风险等级为极高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][4],
                                  status=self.param['vpStatus'][2],
                                  dbtype='oracle',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['极高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-mysql类型数据库，风险等级为低，状态启用')
    def test_sqlinject_mysql_low_start(self):
        '''sql注入特征库-mysql类型数据库，风险等级为低，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][1],
                                  status=self.param['vpStatus'][2],
                                  dbtype='mysql',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['低'],
                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-mysql类型数据库，风险等级为中，状态启用')
    def test_sqlinject_mysql_middle_start(self):
        '''sql注入特征库-mysql类型数据库，风险等级为中，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][2],
                                  status=self.param['vpStatus'][2],
                                  dbtype='mysql',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['中'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-mysql类型数据库，风险等级为高，状态启用')
    def test_sqlinject_mysql_high_start(self):
        '''sql注入特征库-mysql类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][3],
                                  status=self.param['vpStatus'][2],
                                  dbtype='mysql',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-mysql类型数据库，风险等级为极高，状态启用')
    def test_sqlinject_mysql_veryhigh_start(self):
        '''sql注入特征库-mysql类型数据库，风险等级为极高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][4],
                                  status=self.param['vpStatus'][2],
                                  dbtype='mysql',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['极高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-sqlserver类型数据库，风险等级为低，状态启用')
    def test_sqlinject_sqlserver_low_start(self):
        '''sql注入特征库-sqlserver类型数据库，风险等级为低，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][1],
                                  status=self.param['vpStatus'][2],
                                  dbtype='sqlserver',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['低'],
                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-sqlserver类型数据库，风险等级为中，状态启用')
    def test_sqlinject_sqlserver_middle_start(self):
        '''sql注入特征库-sqlserver类型数据库，风险等级为中，状态启用'''

        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][2],
                                  status=self.param['vpStatus'][2],
                                  dbtype='sqlserver',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['中'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-sqlserver类型数据库，风险等级为高，状态启用')
    def test_sqlinject_sqlserver_high_start(self):
        '''sql注入特征库-sqlserver类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][3],
                                  status=self.param['vpStatus'][2],
                                  dbtype='sqlserver',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-sqlserver类型数据库，风险等级为极高，状态启用')
    def test_sqlinject_sqlserver_veryhigh_start(self):
        '''sql注入特征库-sqlserver类型数据库，风险等级为极高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][4],
                                  status=self.param['vpStatus'][2],
                                  dbtype='sqlserver',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['极高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-db2类型数据库，风险等级为低，状态启用')
    def test_sqlinject_db2_low_start(self):
        '''sql注入特征库-db2类型数据库，风险等级为低，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][1],
                                  status=self.param['vpStatus'][2],
                                  dbtype='db2',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['低'],
                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-db2类型数据库，风险等级为中，状态启用')
    def test_sqlinject_db2_middle_start(self):
        '''sql注入特征库-db2类型数据库，风险等级为中，状态启用'''

        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][2],
                                  status=self.param['vpStatus'][2],
                                  dbtype='db2',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['中'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-db2类型数据库，风险等级为高，状态启用')
    def test_sqlinject_db2_high_start(self):
        '''sql注入特征库-db2类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][3],
                                  status=self.param['vpStatus'][2],
                                  dbtype='db2',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-db2类型数据库，风险等级为极高，状态启用')
    def test_sqlinject_db2_veryhigh_start(self):
        '''sql注入特征库-db2类型数据库，风险等级为极高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2,name=self.name,
                                  risk_level=self.param['riskLevel'][4],
                                  status=self.param['vpStatus'][2],
                                  dbtype='db2',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['极高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-gbase类型数据库，风险等级为低，状态启用')
    def test_sqlinject_gbase_low_start(self):
        '''sql注入特征库-gbase_s83类型数据库，风险等级为低，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][1],
                                  status=self.param['vpStatus'][2],
                                  dbtype='gbase_s83',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['低'],
                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-gbase类型数据库，风险等级为中，状态启用')
    def test_sqlinject_gbase_middle_start(self):
        '''sql注入特征库-gbase类型数据库，风险等级为中，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][2],
                                  status=self.param['vpStatus'][2],
                                  dbtype='gbase_s83',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['中'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-gbase类型数据库，风险等级为高，状态启用')
    def test_sqlinject_gbase_high_start(self):
        '''sql注入特征库-gbase类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][3],
                                  status=self.param['vpStatus'][2],
                                  dbtype='gbase_s83',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-gbase类型数据库，风险等级为极高，状态启用')
    def test_sqlinject_gbase_veryhigh_start(self):
        '''sql注入特征库-gbase类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][4],
                                  status=self.param['vpStatus'][2],
                                  dbtype='gbase_s83',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['极高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='sqlserver',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-hive类型数据库，风险等级为低，状态启用')
    def test_sqlinject_hive_low_start(self):
        '''sql注入特征库-hive类型数据库，风险等级为低，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][1],
                                  status=self.param['vpStatus'][2],
                                  dbtype='hive',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['低'],
                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-hive类型数据库，风险等级为中，状态启用')
    def test_sqlinject_hive_middle_start(self):
        '''sql注入特征库-hive类型数据库，风险等级为中，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][2],
                                  status=self.param['vpStatus'][2],
                                  dbtype='hive',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['中'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-hive类型数据库，风险等级为高，状态启用')
    def test_sqlinject_hive_high_start(self):
        '''sql注入特征库-hive类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][3],
                                  status=self.param['vpStatus'][2],
                                  dbtype='hive',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-hive类型数据库，风险等级为极高，状态启用')
    def test_sqlinject_hive_veryhigh_start(self):
        '''sql注入特征库-hive类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][4],
                                  status=self.param['vpStatus'][2],
                                  dbtype='hive',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['极高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='oracle',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-dm类型数据库，风险等级为低，状态启用')
    def test_sqlinject_dm_low_start(self):
        '''sql注入特征库-dm类型数据库，风险等级为低，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][1],
                                  status=self.param['vpStatus'][2],
                                  dbtype='dm',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['低'],
                                  cn_res_behavior=self.param['响应行为']['告警'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-dm类型数据库，风险等级为中，状态启用')
    def test_sqlinject_dm_middle_start(self):
        '''sql注入特征库-dm类型数据库，风险等级为中，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][2],
                                  status=self.param['vpStatus'][2],
                                  dbtype='dm',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['中'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-dm类型数据库，风险等级为高，状态启用')
    def test_sqlinject_dm_high_start(self):
        '''sql注入特征库-dm类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][3],
                                  status=self.param['vpStatus'][2],
                                  dbtype='dm',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    @logger('sql注入特征库-dm类型数据库，风险等级为极高，状态启用')
    def test_sqlinject_dm_veryhigh_start(self):
        '''sql注入特征库-dm类型数据库，风险等级为高，状态启用'''
        rulename = self.rule[0] + self.name
        SqlInject_Case.check_rule(isAll=2, name=self.name,
                                  risk_level=self.param['riskLevel'][4],
                                  status=self.param['vpStatus'][2],
                                  dbtype='dm',
                                  sql=self.sql,
                                  rulename=rulename,
                                  cn_risk_level=self.param['风险级别']['极高'],
                                  cn_res_behavior=self.param['响应行为']['阻断行为'])
        SqlInject_Case.execsql_rule(dbtype='mysql',
                                    sql=self.sql,
                                    rulename=self.rule[1],
                                    cn_risk_level=self.param['风险级别']['安全'],
                                    cn_res_behavior=self.param['响应行为']['通过'])

    def tearDown(self):
        LOG.info('启用验证成功，等待删除。。。')
        SqlInject_Case.sqlinject_del_rule(name=self.name)
