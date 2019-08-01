'''
模块：安全防御
功能：开关编辑
'''

from casemap.basicfunc.policymanage import dbsecurityconf, dbservice
from public.log import LOG




def update_switch(dispose=None, featuresStatus=None, virStatus=None, name=None, dataMaskStatusOM=None):
    id = dbservice.select_dbservice_byname(name=name)
    LOG.info('编辑开关开始。。。')
    dbsecurityconf.update_switch(dispose=dispose, featuresStatus=featuresStatus, virStatus=virStatus, id=id,
                                 dataMaskStatusOM=dataMaskStatusOM)
    LOG.info('编辑开关开始结束。。。')


def update_access(name, action, cyc, rate, riskLevel, audit):
    LOG.info('编辑开关开始。。。')
    dbsecurityconf.update_access(name, action, cyc, rate, riskLevel, audit)
    LOG.info('编辑开关开始结束。。。')





if __name__ == '__main__':
    update_access(name='mysql', action=3, cyc='min', rate=10, riskLevel=3, audit=3)
