from casemap import Virtualpatch_Case, SqlInject_Case, DBSecurityconf_Case
from public import commen
import time
import global_params as gp
import unittest

namelist = gp.dbnamelist()


class Configdb1(unittest.TestCase):

    def test_setconfig(self):
        '''数据库配置：关掉sql特征库'''
        print(namelist)
        for name in namelist:
            DBSecurityconf_Case.update_switch(featuresStatus=0, virStatus=0, name=name)
        time.sleep(30)
