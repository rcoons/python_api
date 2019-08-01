from casemap.basicfunc.policymanage import dbservice
from public.log import LOG
import time
import global_params as gp

def update_runmode(dbname, runmode):
    '''
    编辑数据库模式
    :param dbname:数据库名称
    '''
    id = dbservice.select_dbservice_byname(dbname)
    LOG.info('开始编辑。。。')
    dbservice.update_service(dbname, id, runmode)
    LOG.info('编辑结束。。。')


def create_DB(dbnameList):
    for name in dbnameList:
        num = dbservice.select_dbservice_bynullname(name)
        if num == 0:
            LOG.info('开始创建%s数据库服务。。。' % (name))
            dbservice.create_dbservice(name)
            LOG.info('开始启用%s数据库服务。。。' % (name))
            id = dbservice.select_dbservice_byname(name)
            dbservice.startOrstop_dbservice(id, mode=1)
            LOG.info('启用%s数据库服务成功' % (name))
        else:
            LOG.info(name + '数据库服务已存在')
    time.sleep(30)

if __name__ == '__main__':

    dbnameList = []
    for k,v in gp.run_db.items():
        dbnameList.append(v)
    create_DB(dbnameList)
