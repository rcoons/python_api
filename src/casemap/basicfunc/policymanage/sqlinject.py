'''

'''
import copy
from public.basicclass import SqlInjectClass
from public import commen
from public.log import LOG

sqlinject_dict =commen.get_api(apifile='\PolicyManage.json')['SqlInject']  # 加载参数,文件名称前加\



def sqlinject_add(dbType=None,name=None,risk_level=None,status=None,ruleType=None):
    '''
    sql注入特征库新增自定义规则
    '''
    obj = SqlInjectClass.SqlInject()  # 创建sql注入对象
    param_dict = copy.deepcopy(sqlinject_dict['add_diy_rule'])
    response = obj.diy_rule_add(dbType=dbType,name=name,risk_level=risk_level,status=status,ruleType=ruleType)
    result = commen.load(response.text)
    assert result == param_dict['expected'], '错误:响应结果比对失败'+response.text



def sqlinject_select(byparam,param):
    '''
    sql注入条件查询
    '''
    obj = SqlInjectClass.SqlInject()  # 创建sql注入对象
    response = obj.select_rule(byparam=byparam,param=param)
    rs=True
    result = commen.load(response.text)
    if byparam=='byname':
        assert len(result['items']) == 1 and result['items'][0]['chsName']==param, '错误:响应结果比对失败'+response.text
        return result['items'][0]['id']
    if byparam=='byrisklevel':
        for item in result['items']:
            if item['riskLevel']!=param:
                rs = False
                break
        assert rs,'错误:响应结果比对失败'+response.text
    if byparam=='bystatus':
        for item in result['items']:
            if item['vpStatus']!=param:
                rs = False
                break
        assert rs,'错误:响应结果比对失败'+response.text


def sqlinject_select_bynullname(byparam,param):
    '''
        名称不存在-查询规则
    '''
    obj = SqlInjectClass.SqlInject()  # 创建sql注入对象
    response = obj.select_rule(byparam=byparam, param=param)
    result=commen.load(response.text)
    assert len(result['items']) == 0 , '错误:响应结果比对失败'+response.text


def operate_rule(operate,id):
    '''
    操作规则
    :param id:  规则唯一id
    operate:操作类型
    '''
    obj = SqlInjectClass.SqlInject()  # 创建sql注入对象
    del_dict=sqlinject_dict['mutiOperate_diy_rule']
    response=obj.operate_rule(operate=operate,id=id)
    result = commen.load(response.text)
    assert result == del_dict['expected'][operate], '错误:响应结果比对失败'+response.text


def view_rule(name,id):
    '''
    查看
    :param id: 规则id
    '''
    obj = SqlInjectClass.SqlInject()  # 创建sql注入对象
    add_dict = sqlinject_dict['add_diy_rule']['body']
    add_dict['chsName']=name
    add_dict.pop('content')
    response=obj.view_rule(id=id)
    rs=True
    for k in add_dict:
        if str(add_dict[k]) not in response.text:
            rs = False
            break
    assert rs , '错误:响应结果比对失败' + response.text


def update_rule(id):
    obj = SqlInjectClass.SqlInject()  # 创建sql注入对象
    update_dict=sqlinject_dict['update_diy_rule']
    response = obj.update_rule(id=id)
    result = commen.load(response.text)
    assert result == update_dict['expected'], '错误:响应结果比对失败' + response.text
    update_dict['body'].pop('content')
    view_response=obj.view_rule(id=id)
    rs=True
    for k in update_dict['body']:
        if str(update_dict['body'][k]) not in view_response.text:
            # print(view_response.text)
            # print(str(update_dict['body'][k]))
            rs = False
            break
    assert rs, '错误:查看结果修改结果失败' + view_response.text


def check_sql(rulename=None,sql=None,risk_level=None,res_behavior=None,audit=None):
    check_dict = {"kw": '', "sqltext": sql}
    LOG.info(sql)
    rs_html = commen.shenji_check(searchinfo=check_dict, target=rulename.upper())
    assert res_behavior in rs_html,'响应行为匹配失败'
    assert risk_level in rs_html,'风险等级匹配失败'
    if audit is not None:
        assert audit in rs_html,'审计级别匹配失败'

if __name__=='__main__':
    check_sql(rulename='_业务全审计', sql='SELECT * FROM TABLERGC5', risk_level='风险级别：安全', res_behavior='响应行为：通过')
