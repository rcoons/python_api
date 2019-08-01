import paramiko
import time
import winrm
import os
import global_params as gp
from casemap.basicfunc.policymanage import dbservice


os.environ['NLS_LANG'] = 'AMERICAN_AMERICA.AL32UTF8'


def Win_winrm(con_dict, sql):
    ip = con_dict['BywayIP']
    username = con_dict['username']
    passwd = con_dict['passwd']
    gStrConnection = con_dict['gStrConnection']
    try:
        win = winrm.Session('http://%s:5985/wsman' % ip, auth=(username, passwd))
        # r= win.run_cmd('echo select * from test.Person.Person;|osql -S WIN7-PC\SQLSERVER2012 -U sa -P hzmc321#\r\n')

        sql_test = "echo %s;|osql %s\r\n" % (sql, gStrConnection)
        win.run_cmd(sql_test)
        time.sleep(2)
        win.run_cmd('net stop iphlpsvc\r\n')  # net stop iphlpsvc 是关闭iphlpsvc服务

    except Exception as e:
        print('%s Error' % ip)
        print(e)
        return False


def ssh_con(con_dict, sql, dbtype):
    ip = con_dict['BywayIP']
    username = con_dict['username']
    passwd = con_dict['passwd']
    gStrConnection = con_dict['gStrConnection']
    try:
        # 建立ssh连接，连接至服务器后台
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, 22, username, passwd, timeout=5)
        if (dbtype == "Oracle"):
            stdin, stdout, stderr = ssh.exec_command(
                '''su - oracle -c"echo '%s;'|sqlplus -s '%s'"''' % (sql, gStrConnection))
        elif (dbtype == "MySQL"):
            stdin, stdout, stderr = ssh.exec_command('''echo "%s;"|mysql %s''' % (sql, gStrConnection))

        # 读取结果
        time.sleep(4)
        result = stdout.readlines()
        time.sleep(1)
        ssh.close()
    except Exception as e:
        print('%s Error' % ip)
        print(e)
        return False


def sql_ops(con_dict, sql, dbtype):
    if (dbtype == "Sql Server"):
        Win_winrm(con_dict, sql)
    else:
        ssh_con(con_dict, sql, dbtype)


if __name__ == '__main__':
    # print(Win_winrm(DBConfig.sqlserver_dict, "select * from table"))
    print(sql_ops(dbservice.select_dbservice_byname(gp.run_db["oracle"]), "SELECT * FROM P123", "Oracle"))
