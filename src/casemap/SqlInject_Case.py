'''
模块：sql注入特征库
功能sql注入新增、修改、查询、删除
'''

from casemap.basicfunc.policymanage import sqlinject
from public.log import LOG
from DBLib import sql_execute
import time
from public import commen
sqlinject_dict = sqlinject.sqlinject_dict  # 获取参数配置


def sqlinject_add(dbType=None, name=None, risk_level=None, status=None, ruleType=None):
    '''sql注入特征库新增'''
    LOG.info('开始新增...')
    sqlinject.sqlinject_add(dbType=dbType, name=name, risk_level=risk_level, status=status, ruleType=ruleType)
    LOG.info('新增结束，开始查询...')
    id = sqlinject.sqlinject_select(byparam='byname', param=name)
    LOG.info('查询结果正确')
    return id


def sqlinject_select(byparam, param):
    '''
    查询
    '''
    LOG.info('开始查询。。。')
    sqlinject.sqlinject_select(byparam=byparam, param=param)
    LOG.info('结束查询！')


def sqlinject_startORstop_rule(operate, id, param):
    '''
    启（停）用
    '''
    # LOG.info('开始启（停）用。。。')
    sqlinject.operate_rule(operate=operate, id=id)
    sqlinject.sqlinject_select(byparam='byname', param=param)
    # LOG.info('启（停）用结束，验证是否生效。。。')


def sqlinject_del_rule(name):
    '''
    删除
    '''

    LOG.info('开始删除。。。')
    id = sqlinject.sqlinject_select(byparam='byname', param=name)
    sqlinject.operate_rule(operate='delete', id=id)
    LOG.info('删除结束，开始查询。。。')
    sqlinject.sqlinject_select_bynullname(byparam='byname', param=name)
    LOG.info('删除成功')


def view_rule(name, id):
    '''
    查看
    :param id:自定义规则id
    '''
    LOG.info('开始查看。。。')
    sqlinject.view_rule(name=name, id=id)
    LOG.info('查看结束。。。')


def update_rule(id):
    LOG.info('开始编辑。。。')
    sqlinject.update_rule(id=id)
    LOG.info('编辑结束。。。')


# def sqlinject_Test_set(param_dict):
#     # 添加规则
#     sqlinject_add(dbType=param_dict['dbtype'], name=param_dict['name'], risk_level=param_dict['risk_level'],
#                   status=param_dict['status'])
#     time.sleep(10)
#     sqlexec_rulecheck(param_dict)
#
#
# def sqlexec_rulecheck(param_dict):
#     # 执行sql
#     sql_execute.exec_select(dbtype=param_dict['dbtype'], sql=param_dict['sql'])
#     # 检验
#     sqlinject.check_sql(rulename=param_dict['check_name'].upper(), sql=param_dict['sql'],
#                         risk_level=param_dict['check_risk_level'],
#                         res_behavior=param_dict['res_behavior'])


'''添加sql注入规则，执行sql'''
def check_rule(isAll,name,risk_level,status,dbtype,sql,rulename,cn_risk_level,cn_res_behavior):
    if isAll==1:
        sqlinject_add(name=name, risk_level=risk_level,status=status)
    elif isAll:
        sqlinject_add(dbType=dbtype,name=name, risk_level=risk_level, status=status)
    time.sleep(10)
    LOG.info('%s执行sql。。。'%(dbtype))
    if dbtype in ['hive','dm']:

        commen.jdbcConnect(dbtype,sql,isexcept=None)
    else:
        sql_execute.exec_select(dbtype, sql)
    sqlinject.check_sql(rulename.upper(), sql, cn_risk_level,
                        cn_res_behavior)

'''执行sql'''
def execsql_rule(dbtype,sql,rulename,cn_risk_level,cn_res_behavior):
    LOG.info('%s执行sql。。。' % (dbtype))
    if dbtype in ['hive','dm']:
        sql='"%s"'%(sql)
        commen.jdbcConnect(dbtype,sql,isexcept=None)
    else:
        sql_execute.exec_select(dbtype, sql)
    sqlinject.check_sql(rulename.upper(),sql,cn_risk_level,
                        cn_res_behavior)