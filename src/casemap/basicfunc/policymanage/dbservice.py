'''

author：xujianzhong
'''

from public.basicclass import DBserviceClass
from public import commen


dbservice_dict = commen.get_api(apifile='\DatabaseService.json')  # 加载参数,文件名称前加\


def select_dbservice_byname(name):
    '''
    根据名称查询id
    :param name:数据库保护对象名称
    '''
    obj = DBserviceClass.DBservice()  # 创建数据库服务对象
    response=obj.select_dbservice(byparam='byname',value=name)
    result=commen.load(response.text)
    assert len(result['data']['items']) == 1 and result['data']['items'][0]['objName'] == name, '错误:响应结果比对失败'+response.text
    return result['data']['items'][0]['objId']

def select_dbservice_bynullname(name):
    '''
    根据名称查询id
    :param name:数据库保护对象名称
    '''
    obj = DBserviceClass.DBservice()  # 创建数据库服务对象
    response=obj.select_dbservice(byparam='byname',value=name)
    result=commen.load(response.text)
    return len(result['data']['items'])

def update_service(dbname,id,runmode):
    obj = DBserviceClass.DBservice()
    response = obj.update_dbservice(dbname=dbname,runmode=runmode,id=id)
    result = commen.load(response.text)
    assert result==dbservice_dict['updatedbserver']['expected'],'错误:响应结果比对失败'+response.text

def create_dbservice(name):
    obj = DBserviceClass.DBservice()
    response = obj.create_dbservice(name)
    result = commen.load(response.text)
    assert result == dbservice_dict['createdbserver']['expected'], '错误:响应结果比对失败' + response.text


def startOrstop_dbservice(id,mode):
    obj =DBserviceClass.DBservice()
    response=obj.startOrstop_dbservice(id,mode)
    result = commen.load(response.text)
    assert result == dbservice_dict['startOrstopdbservice']['expected'], '错误:响应结果比对失败' + response.text


if __name__=='__main__':
    id=select_dbservice_byname(name='sql240_214')
    print(id)
