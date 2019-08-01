'''
数据库连接
'''

from LIB import pymysql,psycopg2
import pyodbc, ibm_db_dbi
import cx_Oracle
from public import commen
import global_params as gp


# 加载参数,文件名称前加\

oracle = gp.run_db['oracle']
mysql = gp.run_db['mysql']
db2 = gp.run_db['db2']
gbase = gp.run_db['gbase']
sqlserver = gp.run_db['sqlserver']
# postgresql=gp.run_db['postgresql']


class Connnect(object):
    def __init__(self):
        self._conn = None
        db_dict = commen.get_api(apifile='\DatabaseService.json')['connectDB']
        self.oracle_dict = {
            'ip': db_dict[oracle][gp.isproxy]['ip'], 'port': db_dict[oracle][gp.isproxy]['port'],
            'user': db_dict[oracle]['username'], 'password': db_dict[oracle]['password'],
            'instanceName': db_dict[oracle]['instanceName']}

        self.mysql_dict = {
            'ip': db_dict[mysql][gp.isproxy]['ip'], 'port': db_dict[mysql][gp.isproxy]['port'],
            'user': db_dict[mysql]['username'], 'password': db_dict[mysql]['password'],
            'db': db_dict[mysql]['db']
        }
        self.gbase_dict = {
            'ip': db_dict[gbase][gp.isproxy]['ip'], 'port': db_dict[gbase][gp.isproxy]['port'],
            'user': db_dict[gbase]['username'], 'password': db_dict[gbase]['password'],
            'db': db_dict[gbase]['db']
        }
        self.sqlserver_dict = {
            'ip': db_dict[sqlserver][gp.isproxy]['ip'] + ',' + str(db_dict[sqlserver][gp.isproxy]['port']),
            'user': db_dict[sqlserver]['username'],
            'password': db_dict[sqlserver]['password'],
            'db': db_dict[sqlserver]['db']
        }
        self.db2_dict = {
            'ip': db_dict[db2][gp.isproxy]['ip'],
            'port': db_dict[db2][gp.isproxy]['port'],
            'user': db_dict[db2]['username'],
            'password': db_dict[db2]['password'],
            'db': db_dict[db2]['db']
        }

    def dbconnect(self, dbtype):
        dbtype = dbtype.lower()
        conn=None
        if dbtype == 'mysql':
            conn = pymysql.connect(host=self.mysql_dict['ip'], port=int(self.mysql_dict['port']),
                                   user=self.mysql_dict['user'],
                                   passwd=self.mysql_dict['password'], db=self.mysql_dict['db'], charset="utf8")


        elif dbtype in ['sqlserver', "sql server"]:
            conn = pyodbc.connect(DRIVER='{SQL Server}', SERVER=self.sqlserver_dict['ip'],
                                  DATABASE=self.sqlserver_dict['db'],
                                  UID=self.sqlserver_dict['user'],
                                  PWD=self.sqlserver_dict['password'])


        elif dbtype == 'oracle':
            information = self.oracle_dict['user'] + '/' + self.oracle_dict['password'] + '@' + self.oracle_dict[
                'ip'] + ':' + \
                          str(self.oracle_dict['port']) + '/' + self.oracle_dict['instanceName']
            # print(information)
            conn = cx_Oracle.connect(information)
            # if conn:
            #     print('yesyeys')

        elif dbtype == 'db2':
            conn = ibm_db_dbi.connect("PORT=%s;PROTOCOL=TCPIP;" % (str(self.db2_dict['port'])),
                                      host=self.db2_dict['ip'], database=self.db2_dict['db'],
                                      user=self.db2_dict['user'], password=self.db2_dict['password'])

        elif dbtype in ['gbase_8s83', 'gbase_s83']:
            conn = pymysql.connect(host=self.gbase_dict['ip'], port=self.gbase_dict['port'],
                                   user=self.gbase_dict['user'],
                                   passwd=self.gbase_dict['password'], db=self.gbase_dict['db'], charset="utf8")

        elif dbtype =='pg':
            conn = psycopg2.connect(database='', user='system', password='krms',
                                    host='192.168.238.217', port='54321')

        self._conn = conn
    def query(self, sql=None, isexcept=None):
        rs = []
        # 获取游标
        if self._conn:
            cur = \
                self._conn.cursor()  # 创建游标
            if cur:
                try:
                    cur.execute(sql)  # 执行sql语句
                    rs = cur.fetchall()  # 一次性返回所有结果集
                    cur.close()  # 删除游标
                    return rs
                except Exception as e:
                    # print(e)
                    pass
                    # rs=isException(isexcept, e)
                    # assert rs,'阻断响应码错误'

        else:
            print('连接失败')
            return rs

    def exec(self, sql):
        if self._conn:
            cur = self._conn.cursor()
            cur.execute(sql)
            cur.close()  # 删除游标
            self._conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()


if __name__ == '__main__':
    # namelist=['oracle','mysql','gbase_s83','sqlserver']
    # for i in namelist:
    #     obj = Connnect()
    #     obj.dbconnect(dbtype=i)
    #     if obj._conn:
    #         print(obj._conn)
    #     else:
    #         print(i+'连接不上')
    #     obj.close()
    obj = Connnect()
    obj.dbconnect(dbtype='sqlserver')
    # obj.exec("DECLARE EKVTED NUM NUMBERBEGIN SELECT COUNT ( 1 ) INTO NUM FROM USER_TABLES WHERE TABLE_NAME = UPPER ( '中文表' ) IF NUM > 0 THEN EXECUTE IMMEDIATE 'DROP TABLE 中文表' END IFEN")
    if obj._conn:
        print('yes')
        obj._conn.close()
    # conn = psycopg2.connect(database='kingbasees_instance1', user='system', password='krms', host='192.168.238.217', port='54321')







