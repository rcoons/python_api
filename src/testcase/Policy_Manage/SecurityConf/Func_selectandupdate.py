'''
模块：安全防御设置
功能：查询、阈值控制、访问频次控制
author:xujianzhong
'''
import unittest

from public.log import logger
from casemap.basicfunc.policymanage import dbsecurityconf
from casemap.basicfunc.policymanage import sqlinject
import global_params as gp
from casemap import DBSecurityconf_Case

class SecurityConf_base(unittest.TestCase):
    sqlinject_dict = sqlinject.sqlinject_dict  # 获取参数配置
    param = sqlinject_dict['add_diy_rule']['param']

    @logger('安全防御设置-名称查询')
    def test_select_byname(self):
        '''安全防御设置-名称查询'''
        dbsecurityconf.select(dbname=gp.run_db['oracle'])

    @logger('安全防御设置-sql注入特征库停用状态查询')
    def test_select_byfeaturesStatus_stop(self):
        '''安全防御设置-sql注入特征库停用状态查询'''
        dbsecurityconf.select(featuresStatus=0)

    @logger('安全防御设置-sql注入特征库启用状态查询')
    def test_select_byfeaturesStatus_start(self):
        '''安全防御设置-sql注入特征库启用状态查询'''
        dbsecurityconf.select(featuresStatus=1)

    @logger('安全防御设置-虚拟补丁停用状态查询')
    def test_select_byvirStatus_stop(self):
        '''安全防御设置-虚拟补丁停用状态查询'''
        dbsecurityconf.select(virStatus=0)

    @logger('安全防御设置-虚拟补丁启用状态查询')
    def test_select_byvirStatus_start(self):
        '''安全防御设置-虚拟补丁启用状态查询'''
        dbsecurityconf.select(virStatus=1)

    @logger('安全防御设置-获取信息列表')
    def test_nopage(self):
        '''安全防御设置-获取信息列表'''
        dbsecurityconf.nopage()

    # @logger('安全防御设置-访问频次控制')
    # def test_access(self):
    #     DBSecurityconf_Case.update_access(name='Linuxmysql5_6',
    #                                       cyc='min',  # 每分
    #                                       rate=10,  # 频次
    #                                       riskLevel=self.param['riskLevel'][3],  # 风险级别
    #                                       audit=3,  # 审计级别
    #                                       action=1)  # 阻断
    #     dbsecurityconf.access(dbtype='mysql', rulename='[访问频次限制]', cn_res_behavior='', cn_risk_level='')

    @logger('安全防御设置-阈值控制')
    def test_returnCount_0(self):
        '''安全防御设置-阈值控制-风险低-告警-审计级别中'''
        dbsecurityconf.update_returnCount(name=gp.run_db['mysql'], action=5, rate=100, riskLevel=1, audit=2)

        dbsecurityconf.returnCount(dbtype='mysql', au=1, rate=100, rulename='[返回行限制]', cn_risk_level='风险级别：低',
                                   cn_res_behavior='响应行为：告警',audit='中')
    @logger('安全防御设置-阈值控制')
    def test_returnCount_1(self):
        '''安全防御设置-阈值控制-风险中-告警-审计级别低'''
        dbsecurityconf.update_returnCount(name=gp.run_db['mysql'], action=5, rate=100, riskLevel=2, audit=1)

        dbsecurityconf.returnCount(dbtype='mysql', au=1, rate=100, rulename='[返回行限制]', cn_risk_level='风险级别：中',
                                   cn_res_behavior='响应行为：告警',audit='低')
    @logger('安全防御设置-阈值控制')
    def test_returnCount_2(self):
        '''安全防御设置-阈值控制-风险高-告警-审计级别极高'''
        dbsecurityconf.update_returnCount(name=gp.run_db['mysql'], action=5, rate=100, riskLevel=3, audit=4)

        dbsecurityconf.returnCount(dbtype='mysql', au=1, rate=100, rulename='[返回行限制]', cn_risk_level='风险级别：高',
                                   cn_res_behavior='响应行为：告警',audit='极高')
    @classmethod
    def tearDownClass(cls):
        DBSecurityconf_Case.update_switch(featuresStatus=1, virStatus=0, name=gp.run_db['mysql'])