'''
执行select sql语句
'''

from DBLib import Connection


def exec_select(dbtype, sql):
    obj = Connection.Connnect()  # 创建对象
    obj.dbconnect(dbtype)  # 创建数据库连接对象
    rs = obj.query(sql)  # 执行sql查询

    obj.close()  # 关闭数据库连接对象
    return rs


def db2_create_table(dbtype, table_name):
    obj = Connection.Connnect()  # 创建对象
    obj.dbconnect(dbtype)  # 创建数据库连接对象
    obj.exec('CREATE TABLE DB2INST6.%s(NUM INT)' % (table_name.upper()))  # 建表
    obj.close()


def db2_drop_table(dbtype, table_name):
    obj = Connection.Connnect()  # 创建对象
    obj.dbconnect(dbtype)  # 创建数据库连接对象
    obj.exec('DROP TABLE DB2INST6.%s' % (table_name.upper()))  # 删表
    obj.close()


if __name__ == '__main__':
    # sql=commen.PutsqlName('SELECT *  FROM T1')
    # db_dict = dbservice.dbservice_dict['createdbserver']['body']
    exec_select(dbtype='sqlserver', sql='SELECT *  FROM T1')
