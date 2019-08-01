from casemap.basicfunc.policymanage import virtualpatch
from casemap.basicfunc.policymanage import sqlinject
from public.log import LOG
import time
from DBLib import sql_execute
from public import commen

sqlinject_dict = sqlinject.sqlinject_dict  # 获取参数配置


def virtual_add(dbType=None, name=None, risk_level=None, status=None, ruleType=None):
    '''漏洞特征库新增'''
    LOG.info('开始新增...')
    sqlinject.sqlinject_add(dbType=dbType, name=name, risk_level=risk_level, status=status, ruleType=ruleType)
    LOG.info('新增结束，开始查询...')
    time.sleep(2)
    id = virtualpatch.virtual_select(byparam='byname', param=name)
    # print(id)
    LOG.info('查询结果正确')
    return id


def virtual_select(byparam, param):
    '''
    查询
    '''
    LOG.info('开始查询。。。')
    virtualpatch.virtual_select(byparam=byparam, param=param)
    LOG.info('结束查询！')


def virtualpatch_del_rule(name):
    '''
    删除
    '''

    LOG.info('开始删除。。。')
    id = virtualpatch.virtual_select(byparam='byname', param=name)
    sqlinject.operate_rule(operate='delete', id=id)
    LOG.info('删除结束，开始查询。。。')
    virtualpatch.virtual_select_bynullname(byparam='byname', param=name)
    LOG.info('删除成功')


def virtualpatch_check_rule(isAll=None, name=None, risk_level=None, status=None, ruleType=None, dbtype=None, sql=None,
                            rulename=None, cn_risk_level=None, cn_res_behavior=None):
    if isAll == 1:
        virtual_add(name=name, risk_level=risk_level, status=status, ruleType=ruleType)
    elif isAll==2:
        virtual_add(dbType=dbtype,name=name, risk_level=risk_level, status=status, ruleType=ruleType)
    time.sleep(10)
    LOG.info('%s执行sql。。。' % (dbtype))
    if dbtype in ['hive', 'dm']:
        commen.jdbcConnect(dbtype, sql, isexcept=None)
    else:
        sql_execute.exec_select(dbtype, sql)
    sqlinject.check_sql(rulename.upper(), sql, cn_risk_level,
                        cn_res_behavior)

