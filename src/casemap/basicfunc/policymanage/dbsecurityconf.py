from public.basicclass import DBSecurityconfClass
from public.commen import get_api, load,PutsqlName
from public import log
from casemap.basicfunc.policymanage import sqlinject
from DBLib import Connection
import time

dbservice_dict = get_api(apifile='\PolicyManage.json')  # 加载参数,文件名称前加\
namelist=get_api(apifile='\PolicyManage.json')['Virtualpatch']['namelist']

def update_switch(dispose=None, featuresStatus=None, virStatus=None, id=None, dataMaskStatusOM=None):
    '''
    :param dispose:强制白名单
    :param featuresStatus: SQL注入特征库开关
    :param virStatus: 虚拟补丁开关
    :param id: 数据库id
    :param dataMaskStatusOM: 运维脱敏
    '''

    obj = DBSecurityconfClass.DBSecurityconfig()  # 创建数据库服务对象
    response = obj.update(dispose=dispose, featuresStatus=featuresStatus, virStatus=virStatus, id=id,
                          dataMaskStatusOM=dataMaskStatusOM)
    result = load(response.text)
    assert dbservice_dict['dbSecurityconfig']['update']['expected'] == result, '错误:响应结果比对失败' + response.text


def update_access(name=None, action=None, cyc=None, rate=None, riskLevel=None, audit=None):
    obj = DBSecurityconfClass.DBSecurityconfig()  # 创建数据库服务对象
    res = obj.select(dbname=name)
    id = load(res.text)['data']['items'][0]['objId']
    response = obj.update_access(id, action, cyc, rate, riskLevel, audit)
    result = load(response.text)
    assert dbservice_dict['dbSecurityconfig']['update']['expected'] == result, '错误:响应结果比对失败' + response.text


def select(dbname=None, featuresStatus=None, virStatus=None):
    obj = DBSecurityconfClass.DBSecurityconfig()  # 创建数据库服务对象
    response = obj.select(dbname, featuresStatus, virStatus)
    result = load(response.text)
    rs = result['data']['items']
    r = True
    if dbname != None:
        if len(rs) != 1 or rs[0]['dbserverDisplayName'] != dbname:
            r = False
    if featuresStatus != None:
        for i in rs:
            if i['featuresStatus'] != featuresStatus:
                r = False
                break
    if virStatus != None:
        for i in rs:
            if i['virStatus'] != virStatus:
                r = False
                break
    assert r, '错误:响应结果比对失败' + response.text


def nopage():
    obj = DBSecurityconfClass.DBSecurityconfig()  # 创建数据库服务对象
    response = obj.nopage()
    result = load(response.text)
    rs = True
    for i in result['dbservers']:
        if i['dbserverDisplayName'] not in namelist:
            rs = False
            break
    assert rs, '错误:响应结果比对失败' + response.text


def access(dbtype,rulename,cn_risk_level,cn_res_behavior):
    sqllist = []
    obj=Connection.Connnect()
    obj.dbconnect(dbtype)
    for i in range(1, 12):
        sql = 'select * from %s' % (PutsqlName(''))
        sqllist.append(sql)
        obj.exec(sql)
    obj.close()
    for i in sqllist:
        if sqllist.index(i)<11:
            cn_risk_level='风险级别：安全'
            cn_res_behavior='响应行为：通过'
            sqlinject.check_sql(rulename=' ', sql=sqllist.index(i), risk_level=cn_risk_level,
                                res_behavior=cn_res_behavior)
        else:
            sqlinject.check_sql(rulename, sqllist.index(i), cn_risk_level,
                                cn_res_behavior)

def update_returnCount(name=None, action=None, rate=None, riskLevel=None, audit=None,status=None):
    obj = DBSecurityconfClass.DBSecurityconfig()  # 创建数据库服务对象
    log.LOG.info('查询数据库id')
    res = obj.select(dbname=name)
    id = load(res.text)['data']['items'][0]['dbserverId']
    log.LOG.info('编辑防御规则')
    response = obj.update_returnCount(id, action, rate, riskLevel, audit,status)
    result = load(response.text)
    assert dbservice_dict['dbSecurityconfig']['update']['expected'] == result, '错误:响应结果比对失败' + response.text
    time.sleep(10)

def returnCount(dbtype,au,rate,rulename,cn_risk_level,cn_res_behavior,audit):
    obj = Connection.Connnect()
    obj.dbconnect(dbtype)
    tabname=PutsqlName('')
    sql='select * from '+tabname
    obj.exec('create table '+tabname+'(id INT)')
    if au==None:
        for i in range(0,rate//2):
            obj.exec('insert into %s VALUES (2)'%(tabname))
        obj.exec(sql)
        obj.exec('drop table ' + tabname)
        obj.close()
        sqlinject.check_sql(rulename=' ', sql=sql, risk_level='风险级别：安全',
                            res_behavior='响应行为：通过')
    else:
        for i in range(0,rate+10):
            obj.exec('insert into %s VALUES (2)' % (tabname))
        obj.exec(sql)
        obj.exec('drop table ' + tabname)
        obj.close()
        sqlinject.check_sql(rulename, sql, cn_risk_level,
                                cn_res_behavior,audit)






if __name__ == '__main__':
    update_access(name='mysql', action=1, cyc='min', rate=10, riskLevel=3, audit=3)
