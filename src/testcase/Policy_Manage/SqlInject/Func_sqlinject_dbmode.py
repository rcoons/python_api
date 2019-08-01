'''
范围：数据库服务模式切换，验证规则
author：xujianzhong
'''
import unittest,time

from casemap.basicfunc.policymanage import dbservice, sqlinject
from public.log import LOG, logger
from casemap import DBService_Case,DBSecurityconf_Case
from DBLib import sql_execute
from public import commen
import global_params as gp
db_dict = dbservice.dbservice_dict  # 获取配置
sqlinject_dict = sqlinject.sqlinject_dict
param = sqlinject_dict['add_diy_rule']['param']
oracle_dict = db_dict['updatedbserver']['body'][gp.run_db['oracle']]
mysql_dict = db_dict['updatedbserver']['body'][gp.run_db['mysql']]
sqlserver_dict = db_dict['updatedbserver']['body'][gp.run_db['sqlserver']]
gbase_dict=db_dict['updatedbserver']['body'][gp.run_db['gbase']]
db2_dict=db_dict['updatedbserver']['body'][gp.run_db['db2']]
hive_dict=db_dict['updatedbserver']['body'][gp.run_db['hive']]
dm_dict=db_dict['updatedbserver']['body'][gp.run_db['dm']]

class SqlInject_switch(unittest.TestCase):

    @logger('sql注入特征库oracle学习模式')
    def test_sqlinject_oracle_learn(self):
        '''sql注入特征库oracle学习模式'''
        sql = 'select * from * where %s=1 or 1=1' % (commen.PutsqlName('password'))
        DBService_Case.update_runmode(dbname=oracle_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['学习'])
        time.sleep(10)
        LOG.info('oracle切换模式学习。。。')
        sql_execute.exec_select(dbtype='oracle', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]基于布尔值的数字OR盲注', sql=sql, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库oracle模拟模式')
    def test_sqlinject_oracle_simulate(self):
        '''sql注入特征库oracle模拟模式'''
        sql = 'select * from * where %s=1 or 1=1' % (commen.PutsqlName('password'))
        DBService_Case.update_runmode(dbname=oracle_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['模拟'])
        time.sleep(10)
        LOG.info('oracle切换模式模拟。。。')
        sql_execute.exec_select(dbtype='oracle', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]基于布尔值的数字OR盲注', sql=sql, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库mysql学习模式')
    def test_sqlinject_mysql_learn(self):
        '''sql注入特征库mysql学习模式'''
        sel_sql=commen.PutsqlName('users')
        sql='select * from '+sel_sql+' where user="admin" union select aaa from bbb #'
        DBService_Case.update_runmode(dbname=mysql_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['学习'])
        time.sleep(10)
        LOG.info('mysql切换模式学习。。。')
        sql_execute.exec_select(dbtype='mysql', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]SELECT FROM LIMIT 注入', sql=sel_sql, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库mysql模拟模式')
    def test_sqlinject_mysql_simulate(self):
        '''sql注入特征库mysql模拟模式'''
        sel_sql = commen.PutsqlName('users')
        sql = 'select * from ' + sel_sql + ' where user="admin" union select aaa from bbb #'
        DBService_Case.update_runmode(dbname=mysql_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['模拟'])
        time.sleep(10)
        LOG.info('mysql切换模式模拟。。。')
        sql_execute.exec_select(dbtype='mysql', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]SELECT FROM LIMIT 注入', sql=sel_sql, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库sqlserver学习模式')
    def test_sqlinject_sqlserver_learn(self):
        '''sql注入特征库sqlserver学习模式'''
        sql = 'select * from %s group by id having 1=1' % (commen.PutsqlName('users'))
        DBService_Case.update_runmode(dbname=sqlserver_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['学习'])
        time.sleep(10)
        LOG.info('sqlserver切换模式学习。。。')
        sql_execute.exec_select(dbtype='sqlserver', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]HAVING数字型永真注入', sql=sql, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库sqlserver模拟模式')
    def test_sqlinject_sqlserver_simulate(self):
        '''sql注入特征库sqlserver模拟模式'''
        sql = 'select * from %s group by id having 1=1' % (commen.PutsqlName('users'))
        DBService_Case.update_runmode(dbname=sqlserver_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['模拟'])
        time.sleep(10)
        LOG.info('sqlserver切换模式模拟。。。')
        sql_execute.exec_select(dbtype='sqlserver', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]HAVING数字型永真注入', sql=sql, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库db2学习模式')
    def test_sqlinject_db2_learn(self):
        '''sql注入特征库db2学习模式'''
        sql = 'select * from %s where username="test" or 1=1' % (commen.PutsqlName('user_role_privs'))
        DBService_Case.update_runmode(dbname=db2_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['学习'])
        time.sleep(10)
        LOG.info('db2切换模式学习。。。')
        sql_execute.exec_select(dbtype='db2', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]基于布尔值的数字OR盲注', sql=sql, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库db2模拟模式')
    def test_sqlinject_db2_simulate(self):
        '''sql注入特征库db2模拟模式'''
        sql='select * from %s where username="test" or 1=1'%(commen.PutsqlName('user_role_privs'))
        DBService_Case.update_runmode(dbname=db2_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['模拟'])
        time.sleep(10)
        LOG.info('db2切换模式模拟。。。')
        sql_execute.exec_select(dbtype='db2', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]基于布尔值的数字OR盲注', sql=sql, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库gbase学习模式')
    def test_sqlinject_gbase_learn(self):
        '''sql注入特征库gbase学习模式'''
        key = commen.PutsqlName('user_role_privs')
        sql = 'select * from %s where username="test" or 1=1' % (key)
        DBService_Case.update_runmode(dbname=gbase_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['学习'])
        time.sleep(10)
        LOG.info('gbase切换模式学习。。。')
        sql_execute.exec_select(dbtype='gbase_s83', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]基于布尔值的数字OR盲注', sql=key, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @logger('sql注入特征库gbase模拟模式')
    def test_sqlinject_gbase_simulate(self):
        '''sql注入特征库gbase模拟模式'''
        key=commen.PutsqlName('user_role_privs')
        sql='select * from %s where username="test" or 1=1'%(key)
        DBService_Case.update_runmode(dbname=gbase_dict['objName'],
                                      runmode=db_dict['updatedbserver']['runmode']['模拟'])
        time.sleep(10)
        LOG.info('gbase切换模式模拟。。。')
        sql_execute.exec_select(dbtype='gbase_s83', sql=sql)
        sqlinject.check_sql(rulename='[SQL注入]基于布尔值的数字OR盲注', sql=key, risk_level=param['风险级别']['高'],
                            res_behavior=param['响应行为']['模拟阻断'])

    @classmethod
    def tearDownClass(cls):
        for name in gp.dbnamelist():
            DBService_Case.update_runmode(dbname=name,
                                      runmode=db_dict['updatedbserver']['runmode']['正式'])
