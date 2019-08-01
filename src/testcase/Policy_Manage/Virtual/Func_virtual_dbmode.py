'''
范围：数据库服务模式切换，验证规则
author：xujianzhong
'''
import unittest, time

from casemap.basicfunc.policymanage import dbservice, sqlinject
from public.log import LOG, logger
from casemap import DBService_Case,DBSecurityconf_Case
from DBLib import sql_execute
from public import commen
import global_params as gp

db_dict = dbservice.dbservice_dict  # 获取配置
sqlinject_dict = sqlinject.sqlinject_dict
param = sqlinject_dict['add_diy_rule']['param']
oracle_dict = db_dict['updatedbserver']['body']['Linuxoracle12c']

class SqlInject_switch(unittest.TestCase):
    '''
    关闭sql注入特征库按钮，开启漏洞特征库
    '''

    @classmethod
    def setUpClass(cls):
        for name in gp.dbnamelist():
            DBSecurityconf_Case.update_switch(featuresStatus=0, virStatus=1, name=name)
        time.sleep(30)

    @logger('漏洞特征库oracle学习模式')
    def test_virtual_oracle_learn(self):
        '''漏洞特征库oracle学习模式'''
        key = commen.PutsqlName('DUAL')
        sql = "SELECT XDB.DBMS_XMLSCHEMA.GENERATESCHEMA ('a', 'ABCD' || chr(212)||chr(100)||chr(201)||chr(01)chr(32)||'echo ARE YOU SURE? >c:\\Unbreakable.txt') FROM %s" % (
            key)
        DBService_Case.update_runmode(dbname=oracle_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['学习'])
        time.sleep(15)
        LOG.info('oracle切换模式学习。。。')
        sql_execute.exec_select(dbtype='oracle', sql=sql)
        sqlinject.check_sql(rulename='[漏洞风险]ORACLE DBMS绕过登录访问控制漏洞', sql=key, risk_level=param['风险级别']['极高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('漏洞特征库oracle模拟模式')
    def test_virtual_oracle_simulate(self):
        '''漏洞特征库oracle模拟模式'''
        key = commen.PutsqlName('DUAL')
        sql = "SELECT XDB.DBMS_XMLSCHEMA.GENERATESCHEMA ('a', 'ABCD' || chr(212)||chr(100)||chr(201)||chr(01)chr(32)||'echo ARE YOU SURE? >c:\\Unbreakable.txt') FROM %s" % (
        key)
        DBService_Case.update_runmode(dbname=oracle_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['模拟'])
        time.sleep(15)
        LOG.info('oracle切换模式模拟。。。')
        sql_execute.exec_select(dbtype='oracle', sql=sql)
        sqlinject.check_sql(rulename='[漏洞风险]ORACLE DBMS绕过登录访问控制漏洞', sql=key, risk_level=param['风险级别']['极高'],
                            res_behavior=param['响应行为']['模拟阻断'])


    @classmethod
    def tearDownClass(cls):
        DBService_Case.update_runmode(dbname=oracle_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['正式'])
        for name in gp.dbnamelist():
            DBSecurityconf_Case.update_switch(featuresStatus=1, virStatus=0, name=name)
        time.sleep(30)