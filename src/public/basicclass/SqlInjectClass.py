'''
模块：sql注入特征库
author:xujianzhong
'''
from public.RequestMode import api_request
import json
from public.log import LOG
from public import commen


class SqlInject(object):
    def __init__(self):
        self.param_dict = commen.get_api(apifile='\PolicyManage.json')['SqlInject']


    '''
    新增
    '''

    def diy_rule_add(self, dbType=None, name=None, risk_level=None, status=None, ruleType=None):
        param=self.param_dict['add_diy_rule']
        if dbType != None :
            if dbType=="dm":
                param['body']['dbType'] = "dameng"
            else:
                param['body']['dbType'] = dbType
        if name != None:
            param['body']['chsName'] = name
        if risk_level != None:
            param['body']['riskLevel'] = risk_level
        if ruleType != None:
            param['body']['ruleType'] = ruleType
        if status != None:
            param['body']['vpStatus'] = status
        try:
            response = api_request(api_url=param['url'],
                                   headers=param['header'],
                                   method=param['method'],
                                   payload=param['body'])
            return response
        except Exception as e:
            LOG.info(e)

    '''
    操作：删除、启用、禁用,
    operate:操作类型，分别为start、stop、delete
    id：自定义规则id
    '''

    def operate_rule(self, operate, id):
        try:
            self.param_dict['mutiOperate_diy_rule']['body'][operate]['ids'].append(id)
            param=self.param_dict['mutiOperate_diy_rule']
            response = api_request(api_url=param['url'],
                                   headers=param['header'],
                                   method=param['method'],
                                   payload=param['body'][operate])
            return response
        except Exception as e:
            LOG.info(e)
        pass

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


    '''
    编辑
    '''

    def update_rule(self, id):
        try:
            param=self.param_dict['update_diy_rule']
            response = api_request(api_url=param['url']+str(id),
                                   headers=param['header'],
                                   method=param['method'],
                                   payload=param['body'])
            return response
        except Exception as e:
            LOG.info(e)

    '''
    查看
    '''
    def view_rule(self,id):
        try:
            param = self.param_dict['view_diy_rule']
            response = api_request(api_url=param['url'] + str(id),
                                   headers=param['header'],
                                   method=param['method'])
            return response
        except Exception as e:
            LOG.info(e)