'''白名单的测试集'''
import global_params as gp
from public import commen
from public.log import LOG
from casemap.basicfunc.policymanage.Whitelist_Way import WhitelistWay


class WhitelistCase(object):
    def __init__(self, dbid,app):
        self.dbid = dbid
        self.app = app
        self.whitelistway = WhitelistWay()

    def whitelist_batch(self, num):
        LOG.info("新增oracle白名单")
        for i in range(0, num):
            sqllist = commen.PutsqlNum()
            LOG.info("SQL语句：%s" % sqllist)
            payload = {"sqlText": sqllist,
                        "sqlTextFormatted": sqllist,
                        "dbtype": 1,
                        "dbserverId": self.dbid,
                        "app": self.app}

            self.whitelistway.addruler(payload)
            LOG.info("查看白名单是否有该语句记录")
            res = self.whitelistway.getlist()
            res = res['items']
            for list1 in res:
                if list1['sqlText'] == sqllist:
                    whitenameID = list1['id']
                    LOG.info("白名单的ID为：%s" % whitenameID)
                    gp.ID_list.append(whitenameID)
                break
            else:
                LOG.info("没有此条记录")
        LOG.info("状态启用")
        res = self.whitelistway.state_change("stop", gp.ID_list)
        print(res)
        assert res["msg"] == "状态更新成功！", "%s状态更新失败" % res["msg"]
        LOG.info("状态停用")
        res = self.whitelistway.state_change("start", gp.ID_list)
        assert res["msg"] == "状态更新成功！", "%s状态更新失败" % res["msg"]


