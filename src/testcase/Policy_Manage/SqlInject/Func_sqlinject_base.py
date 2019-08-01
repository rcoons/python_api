'''
模块：sql注入特征库
功能sql注入新增、修改、查询、删除、启用、停用、查看
author:xujianzhong
'''
import unittest

from casemap.basicfunc.policymanage import sqlinject
from public.log import LOG, logger
from casemap import SqlInject_Case
from public import commen


class SqlInject_base(unittest.TestCase):
    sqlinject_dict = sqlinject.sqlinject_dict  # 获取参数配置
    param = sqlinject_dict['add_diy_rule']['param']
    name=None
    def setUp(self):
        self.name = commen.PutsqlName('')

    @logger('sql注入特征库新增规则')
    def test_sqlinject_add(self):
        '''sql注入特征库新增规则'''
        SqlInject_Case.sqlinject_add(name=self.name)
        LOG.info('sql注入特征库新增---成功')
        SqlInject_Case.sqlinject_del_rule(name=self.name)

    @logger('sql注入特征库查询-低风险')
    def test_sqlinject_sel_low(self):
        '''sql注入特征库查询-低风险'''
        SqlInject_Case.sqlinject_select(byparam=self.param['riskLevel'][0], param=self.param['riskLevel'][1])
        LOG.info('sql注入特征库查询-低风险--成功')

    @logger('sql注入特征库查询-中风险')
    def test_sqlinject_sel_middle(self):
        '''sql注入特征库查询-中风险'''
        SqlInject_Case.sqlinject_select(byparam=self.param['riskLevel'][0], param=self.param['riskLevel'][2])
        LOG.info('sql注入特征库查询-中风险--成功')

    @logger('sql注入特征库查询-高风险')
    def test_sqlinject_sel_high(self):
        '''sql注入特征库查询-高风险'''
        SqlInject_Case.sqlinject_select(byparam=self.param['riskLevel'][0], param=self.param['riskLevel'][3])
        LOG.info('sql注入特征库查询-高风险--成功')

    @logger('sql注入特征库查询-极高风险')
    def test_sqlinject_sel_superhigh(self):
        '''sql注入特征库查询-极高风险'''
        SqlInject_Case.sqlinject_select(byparam=self.param['riskLevel'][0], param=self.param['riskLevel'][4])
        LOG.info('sql注入特征库查询-极高风险--成功')

    @logger('sql注入特征库查询-停用')
    def test_sqlinject_sel_superhigh(self):
        '''sql注入特征库查询-停用'''
        SqlInject_Case.sqlinject_select(byparam=self.param['vpStatus'][0], param=self.param['vpStatus'][1])
        LOG.info('sql注入特征库查询-停用--成功')

    @logger('sql注入特征库查询-启用')
    def test_sqlinject_sel_superhigh(self):
        '''sql注入特征库查询-启用'''
        SqlInject_Case.sqlinject_select(byparam=self.param['vpStatus'][0], param=self.param['vpStatus'][2])
        LOG.info('sql注入特征库查询-启用--成功')

    @logger('sql注入特征库-启用')
    def test_sqlinject_sel_start(self):
        '''sql注入特征库查询-启用'''
        id = SqlInject_Case.sqlinject_add(name=self.name, status=self.param['vpStatus'][1])  # 新增-查询
        LOG.info('开始启用。。。')
        SqlInject_Case.sqlinject_startORstop_rule(operate='start', id=id, param=self.name)  # 启用
        LOG.info('启用结束。。。')
        SqlInject_Case.sqlinject_del_rule(name=self.name)


    @logger('sql注入特征库-停用')
    def test_sqlinject_sel_stop(self):
        '''sql注入特征库-停用'''
        id = SqlInject_Case.sqlinject_add(name=self.name, status=self.param['vpStatus'][2])  # 新增-查询
        LOG.info('开始停用。。。')
        SqlInject_Case.sqlinject_startORstop_rule(operate='stop', id=id, param=self.name)  # 停用
        LOG.info('停用结束。。。')
        SqlInject_Case.sqlinject_del_rule(name=self.name)


    @logger('sql注入特征库查看')
    def test_sqlinject_view(self):
        '''sql注入特征库-查看'''
        id=SqlInject_Case.sqlinject_add(name=self.name)  # 新增-查询
        SqlInject_Case.view_rule(name=self.name, id=id)  # 查看
        SqlInject_Case.sqlinject_del_rule(name=self.name)  # 删除
        LOG.info('sql注入特征库查看规则--成功')

    @logger('sql注入特征库编辑')
    def test_sqlinject_update(self):
        '''sql注入特征库规则-编辑'''
        name = sqlinject.sqlinject_dict['update_diy_rule']['body']['chsName']
        id = SqlInject_Case.sqlinject_add(name=name)  # 新增-查询
        SqlInject_Case.update_rule(id=id)             # 编辑
        LOG.info('启用验证成功，等待删除。。。')
        SqlInject_Case.sqlinject_del_rule(name=name)




