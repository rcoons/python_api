'''
模块：sql注入特征库
author:xujianzhong
'''
from public.RequestMode import api_request
import json
from public.log import LOG
from public.commen import get_api


class Virtualpatch(object):
    def __init__(self):
        self.param_dict = get_api(apifile='\PolicyManage.json')['Virtualpatch']



    '''
    搜索
    byparam：byname、byrisklevel、bystatus，名称、风险等级、启（停）状态
    param：具体参数
    '''

    def select_rule(self, byparam,param):
        try:
            Param=self.param_dict['select_diy_rule']
            response = api_request(api_url=Param['urlParam'][byparam] % param,
                                   headers=Param['header'],
                                   method=Param['method'])
            return response
        except Exception as e:
            LOG.info(e)



