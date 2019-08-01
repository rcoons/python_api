import json
import global_params as gp
import paramiko
import time
import random
import os
from public import RequestMode as RM
from public.log import LOG


def get_api(apifile):
    curPath = os.path.abspath(os.path.dirname(__file__))
    rootPath = curPath[:curPath.find("src\\") + len("src\\")]  # 获取项目的根路径
    dataPath = os.path.abspath(rootPath + 'config\\')  # 获取interface_all.xlsx文件的路径
    docdir = dataPath + apifile
    fp = open(docdir, 'r', encoding='utf-8')
    Api_dict = json.load(fp)
    fp.close()
    return Api_dict


# 获取日志
def get_configlog(ruler_name, con_dict=gp.log_dict):
    ip = con_dict['IP']
    username = con_dict['username']
    passwd = con_dict['passwd']
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, 8320, username, passwd, timeout=5)
        stdin, stdout, stderr = ssh.exec_command("tail -n 10000 /data/logs/gateway.log | grep '%s'" % ruler_name)
        result = stdout.readlines()
        ssh.close()
        return str(result)
    except Exception as e:
        print('%s Error' % ip)
        print(e)
        return False


# 检查sql规则设置是否生效
# temp：设置的规则名称
def config_check(temp, time_out=30):
    conter = 0
    while conter < time_out:
        res = get_configlog(temp)
        if temp in res:
            return res
            break
        else:
            conter += 1
            time.sleep(1)


# 获取敏感规则列表规则名称及对应id
def getruler_name(apifile, target):
    apidict = get_api(apifile)
    apidict = apidict["SensitiveSql"]["rulerlist"]
    response = RM.api_request(apidict["url"], apidict["header"], apidict["method"])
    response = json.loads(response.content)
    sqllist = response['data']['items']
    for line in sqllist:
        if (line['name'] == target):
            return line['name'], line['id']


# 审计结果检查
def shenji_check(searchinfo, target, time_out=30):
    Api_dict = get_api("\Shenji_Api.json")
    payload = Api_dict['search']['body']
    payload['kw'] = searchinfo['kw']
    payload['sqltext'] = searchinfo['sqltext']
    cont = 0
    while cont < time_out:
        response = RM.api_request(Api_dict['search']['url'] % (payload['kw'], payload['sqltext']),
                                  Api_dict['search']['header'],
                                  Api_dict['search']['method'])
        re_str = str(response.content.decode('utf-8'))
        #print(re_str)
        if target in re_str:
            return re_str
            break
        else:
            time.sleep(1)
            cont += 1


def load(text):
    try:
        result = json.loads(text)
        return result
    except Exception as e:
        LOG.info('异常:响应结果非json格式')
        LOG.info(e)


# 随机生成一个规则名称
def PutsqlName(dbtype):
    seeds = "1234567890abcdefhigklmnopqrstuvwxyz"
    random_str = []
    for i in range(4):
        random_str.append(random.choice(seeds))
    return dbtype + "".join(random_str)


# 随机生成一组数字
def PutsqlNum():
    sqltext = gp.sqltext
    seeds = "1234567890"
    random_str = []
    for i in range(3):
        random_str.append(random.choice(seeds))
    return sqltext + "_" + "".join(random_str)


# 敏感sql身份信息授权验证
def author_check(rulerID, target):
    Api_dict = get_api("/PolicyManage.json")
    Api_dict = Api_dict["SensitiveSql"]["getauthor"]
    res = RM.api_request(Api_dict["url"] % rulerID, Api_dict["header"], Api_dict["method"])
    res = json.loads(res.content)['data']['sqlFeatureDefenseAuthorizationList']
    for line in res:
        if (line['alias'] == target):
            return line['alias']
        break


def isException(isexcept,e):
    if isexcept == '阻断':
        for i in ['-551', '9527', '9528', '9529', '12345']:
            if i in str(e):
                return True


def jdbcConnect(dbtype,sql,isexcept):
    sql='"%s"'%(sql)
    db_dict = get_api(apifile='\DatabaseService.json')['connectDB']
    curPath = os.path.abspath(os.path.dirname(__file__))
    rootPath = curPath[:curPath.find("src\\") + len("src\\")]
    jarpath=None
    url=None
    dt=None
    if dbtype=='hive':
        hive = gp.run_db['hive']
        dt = {
            'ip': db_dict[hive][gp.isproxy]['ip'],
            'port': db_dict[hive][gp.isproxy]['port'],
            'user': db_dict[hive]['username'],
            "passpwd":db_dict[hive]['password']
        }
        jarpath=rootPath+'\\LIB\\hive.jar'
        url='jdbc:hive2://%s:%s/default'%(dt['ip'],dt['port'])
    elif dbtype=='dm':
        dm = gp.run_db['dm']
        dt = {
            'ip': db_dict[dm][gp.isproxy]['ip'],
            'port': db_dict[dm][gp.isproxy]['port'],
            'user': db_dict[dm]['username'],
            "passpwd": db_dict[dm]['password']
        }
        jarpath = rootPath + '\\LIB\\dm2.jar'
        url = 'jdbc:dm://%s:%s/default' % (dt['ip'], dt['port'])
    # elif dbtype=='kingbase':
    #     dm = gp.run_db['kingbase']
    #     # dt = {
    #
    #     #     'ip': db_dict[kingbase][gp.isproxy]['ip'],
    #     #     'port': db_dict[kingbase][gp.isproxy]['port'],
    #     #     'user': db_dict[kingbase]['username'],
    #     #     "passpwd": db_dict[kingbase]['password']
    #     # }
    #     url = 'jdbc:kingbase://%s:%s/%s' % (dt['ip'], dt['port'],dt['database'])
    d = os.popen("java -jar %s %s %s %s %s"%(jarpath,url,dt['user'],dt['passpwd'],sql))
    # e=d.read()
    # rs=isException(isexcept,e)
    print(d.read())



if __name__ == '__main__':
    # Api_dict = get_api("\PolicyManage.json")
    # print(Api_dict)
    # name, id = getruler_name("\PolicyManage.json", "DBMS_CORE_INTERNAL")
    # print(name, id)
    # serchinfo1 = {
    #     "kw": "SQLSERVER_00GI",
    #     "sqltext": "SELECT * FROM P1_183"
    # }
    # re = shenji_check(serchinfo1, "SQLSERVER_00GI")
    # print(re)
    jdbcConnect('oracle','"select * from zop;"',isexcept=None)
    # curPath = os.path.abspath(os.path.dirname(__file__))
    # rootPath = curPath[:curPath.find("src\\") + len("src\\")]
    # jarpath = rootPath + 'LIB\\hive15.jar'
    # print(jarpath)
