'''
模块：漏洞特征库
功能sql注入新增、修改、查询、删除、启用、停用、查看
author:xujianzhong
'''
import unittest

from casemap.basicfunc.policymanage import sqlinject, virtualpatch
from public.log import LOG, logger
from casemap import Virtualpatch_Case


class Virtualpatch_base(unittest.TestCase):
    sqlinject_dict = sqlinject.sqlinject_dict  # 获取参数配置
    param = sqlinject_dict['add_diy_rule']['param']

    @logger('漏洞特征库查询-低风险')
    def test_virtual_sel_low(self):
        '''漏洞特征库查询-低风险'''
        Virtualpatch_Case.virtual_select(byparam=self.param['riskLevel'][0], param=self.param['riskLevel'][1])
        LOG.info('漏洞特征库查询-低风险--成功')

    @logger('漏洞特征库查询-中风险')
    def test_virtual_sel_middle(self):
        '''漏洞特征库查询-中风险'''
        Virtualpatch_Case.virtual_select(byparam=self.param['riskLevel'][0], param=self.param['riskLevel'][2])
        LOG.info('漏洞特征库查询-中风险--成功')

    @logger('漏洞特征库查询-高风险')
    def test_virtual_sel_high(self):
        '''漏洞特征库查询-高风险'''
        Virtualpatch_Case.virtual_select(byparam=self.param['riskLevel'][0], param=self.param['riskLevel'][3])
        LOG.info('漏洞特征库查询-高风险--成功')

    @logger('漏洞特征库查询-极高风险')
    def test_virtual_sel_superhigh(self):
        '''漏洞特征库查询-极高风险'''
        Virtualpatch_Case.virtual_select(byparam=self.param['riskLevel'][0], param=self.param['riskLevel'][4])
        LOG.info('漏洞特征库查询-极高风险--成功')

    @logger('漏洞特征库查询-停用')
    def test_virtual_sel_stop(self):
        '''漏洞特征库查询-停用'''
        Virtualpatch_Case.virtual_select(byparam=self.param['vpStatus'][0], param=self.param['vpStatus'][1])
        LOG.info('漏洞特征库查询-停用--成功')

    @logger('漏洞特征库查询-启用')
    def test_virtual_sel_start(self):
        '''漏洞特征库查询-启用'''
        Virtualpatch_Case.virtual_select(byparam=self.param['vpStatus'][0], param=self.param['vpStatus'][2])
        LOG.info('漏洞特征库查询-启用--成功')
