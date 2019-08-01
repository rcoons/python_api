'''

'''


from public.basicclass import VirtualpatchClass
from public.commen import load


def virtual_select(byparam,param):
    '''
    sql注入条件查询
    '''
    obj = VirtualpatchClass.Virtualpatch()  # 创建sql注入对象
    response = obj.select_rule(byparam=byparam,param=param)
    rs=True
    result = load(response.text)
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


def virtual_select_bynullname(byparam,param):
    '''
        名称不存在-查询规则
    '''
    obj =  VirtualpatchClass.Virtualpatch()  # 创建sql注入对象
    response = obj.select_rule(byparam=byparam, param=param)
    result=load(response.text)
    assert len(result['items']) == 0 , '错误:响应结果比对失败'+response.text





# if __name__=='__main__':
    # check_sql(rulename='_业务全审计', sql='SELECT * FROM TABLERGC5', risk_level='风险级别：安全', res_behavior='响应行为：通过')
