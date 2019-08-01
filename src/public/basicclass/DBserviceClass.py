
'''
模块：数据库服务
author:xujianzhong
'''
from public.RequestMode import api_request
from public import commen
from public.log import LOG

class DBservice(object):
    def __init__(self):
        self.param_dict = commen.get_api(apifile='\DatabaseService.json')
    '''
    查询
    '''
    def select_dbservice(self,byparam,value):
        try:
            param=self.param_dict['selectdbserver']
            response = api_request(api_url=param['urlParam'][byparam]%value, headers=param['header'],
                                   method=param['method'])
            return response
        except Exception as e:
            LOG.info(e)

    def update_dbservice(self,dbname=None,id=None,runmode=None):
        try:
            param = self.param_dict['updatedbserver']
            if runmode!=None:
                param['body'][dbname]['runMode']=runmode
            response = api_request(api_url=param['url']+str(id), headers=param['header'],
                                   method=param['method'],payload=param['body'][dbname])
            return response
        except Exception as e:
            LOG.info(e)


    def create_dbservice(self,name):
        try:
            param=self.param_dict['createdbserver']
            response = api_request(api_url=param['url'], headers=param['header'],
                                   method=param['method'],payload=param['body'][name])
            return response
        except Exception as e:
            LOG.info(e)

    def startOrstop_dbservice(self,id,mode):
        try:
            param=self.param_dict['startOrstopdbservice']
            param['body']['ids'].append(id)
            if mode==0:
                param['body']['cmd']='stop'
            elif mode==1:
                param['body']['cmd'] = 'start'
            else:
                LOG.info('失败--启动或停止参数错误')
            response = api_request(api_url=param['url'], headers=param['header'],
                                   method=param['method'],payload=param['body'])
            return response
        except Exception as e:
            LOG.info(e)
