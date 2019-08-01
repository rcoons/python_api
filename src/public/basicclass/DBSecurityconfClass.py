'''
模块：数据库安全配置
author:xujianzhong
'''
from public.RequestMode import api_request
from public import commen
from public.log import LOG


class DBSecurityconfig(object):
    def __init__(self):
        self.param_dict = commen.get_api(apifile='\PolicyManage.json')['dbSecurityconfig']

    def update(self, dispose=None, featuresStatus=None, virStatus=None, id=None, dataMaskStatusOM=None):
        try:
            if dispose != None:
                self.param_dict['update']['body']['rule']['dispose'] = dispose
            if featuresStatus != None:
                self.param_dict['update']['body']['featuresStatus'] = featuresStatus
            if dataMaskStatusOM != None:
                self.param_dict['update']['body']['dataMaskStatusOM'] = dataMaskStatusOM
            if virStatus != None:
                self.param_dict['update']['body']['virStatus'] = virStatus
            self.param_dict['update']['body']['dbIds'][0] = int(id)
            response = api_request(api_url=self.param_dict['update']['url'],
                                   headers=self.param_dict['update']['header'],
                                   method=self.param_dict['update']['method'],
                                   payload=self.param_dict['update']['body'])
            return response
        except Exception as e:
            LOG.info(e)

    '''
    访问频次控制
    '''

    def update_access(self, id=None, action=None, cyc=None, rate=None, riskLevel=None, audit=None):
        self.param_dict['update']['body']['dbIds'][0] = int(id)
        self.param_dict['update']['body']['access']['status'] = 1
        if action != None:
            self.param_dict['update']['body']['access']['action'] = action
        if cyc!= None:
            self.param_dict['update']['body']['access']['cyc'] = cyc
        if rate != None:
            self.param_dict['update']['body']['access']['rate'] = rate
        if riskLevel != None:
            self.param_dict['update']['body']['access']['riskLevel'] = riskLevel
        if audit != None:
            self.param_dict['update']['body']['access']['audit'] = audit
        response = api_request(api_url=self.param_dict['update']['url'],
                               headers=self.param_dict['update']['header'],
                               method=self.param_dict['update']['method'],
                               payload=self.param_dict['update']['body'])
        return response

    '''
    查询
    '''

    def select(self, dbname=None, featuresStatus=None, virStatus=None):
        response = None
        try:
            if dbname != None and featuresStatus == None and virStatus == None:
                response = api_request(api_url=self.param_dict['select']['uri']['dbname'] + dbname,
                                       method=self.param_dict['select']['method'])
            if featuresStatus != None and dbname == None and virStatus == None:
                response = api_request(api_url=self.param_dict['select']['uri']['featuresStatus'] + str(featuresStatus),
                                       method=self.param_dict['select']['method'])
            if virStatus != None and featuresStatus == None and dbname == None:
                response = api_request(api_url=self.param_dict['select']['uri']['virStatus'] + str(virStatus),
                                       method=self.param_dict['select']['method'])

            return response
        except Exception as e:
            LOG.info(e)

    def nopage(self):
        try:
            response = api_request(api_url=self.param_dict['nopage']['uri'],
                                   method=self.param_dict['nopage']['method'])
            return response
        except Exception as e:
            LOG.info(e)
    '''
    访问频次控制
    '''

    def update_returnCount(self, id=None, action=None, rate=None, riskLevel=None, audit=None,status=None):
        self.param_dict['update']['body']['dbIds'][0] = int(id)
        if status == None:
            self.param_dict['update']['body']['returnCount']['status'] = 1
        if action != None:
            self.param_dict['update']['body']['returnCount']['action'] = action
        if rate != None:
            self.param_dict['update']['body']['returnCount']['rate'] = rate
        if riskLevel != None:
            self.param_dict['update']['body']['returnCount']['riskLevel'] = riskLevel
        if audit != None:
            self.param_dict['update']['body']['returnCount']['audit'] = audit
        response = api_request(api_url=self.param_dict['update']['url'],
                               headers=self.param_dict['update']['header'],
                               method=self.param_dict['update']['method'],
                               payload=self.param_dict['update']['body'])
        return response