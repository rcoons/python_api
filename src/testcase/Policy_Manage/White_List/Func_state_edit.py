# FUNC:sql白名单状态切换
# author：liupengju
# description: 1.新增若干条sql白名单
#              2.单条或者多条白名单状态切换
# 预期结果：
# 1.白名单列表里有新建的白名单
# 2.状态切换成功
########################################################################################################################
import global_params as gp
from public.log import LOG, logger
from casemap.Whitelist_Case import WhitelistCase
from casemap.basicfunc.policymanage.Whitelist_Way import WhitelistWay
from casemap.basicfunc.policymanage import dbservice
import unittest


class SelectSql(unittest.TestCase):
    def setUp(self):
        self.whitecase = WhitelistCase(dbservice.select_dbservice_byname(gp.run_db['oracle']), gp.app_dict["oracle"])
        self.whitelist = WhitelistWay()

    @logger('单条白名单状态切换')
    def test_select_oraclesql_one(self):
        '''单条白名单状态切换'''
        self.whitecase.whitelist_batch(num=1)

    @logger('单条白名单状态切换')
    def test_select_oraclesql_more(self):
        '''单条白名单状态切换'''
        self.whitecase.whitelist_batch(num=5)

    def tearDown(self):
        LOG.info("清空白名单")
        self.whitelist.clear()
