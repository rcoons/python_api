from public.login import login

url_ip = "https://192.168.51.145"

# 项目信息
Prj_name = "融合"
# 用户登录信息
userinfo = {
    "username": 'admin',
    "password": "hzmcAdmin",
    "login_url": '/capaa/j_spring_security_check?hid=&val=&j_username=%s&val=&j_password=%s&'
                 'verCode=AV7Q&PIN=&login_style='
}
# cookie获取
cookies = {'JSESSIONID': login(userinfo)}
# 日志服务器
log_dict = {
    "IP": "192.168.51.145",
    "username": "clog",
    "passwd": "Aqcp@Mc666"
}
# 风险等级
risk_level = {
    "risk_low": 1,
    "risk_mid": 2,
    "risk_high": 3,
    "risk_higher": 4
}
# 响应行为
respond = {
    "通过": "通过",
    "阻断": "阻断行为",
    "告警": "告警"
}
# 风险等级信息
risk_info = {
    0: "风险级别：安全",
    1: "风险级别：低",
    2: "风险级别：中",
    3: "风险级别：高",
    4: "风险级别：极高"
}
# 数据库类型
dbID = {
    "oracle": 1,
    "mysql": 2,
    "sqlserver": 3
}
# sql语句
sqltext = "select * from p1"
# 数据库名称
dbname_dict = {
    "oracle": "LINUXORACLE12C",
    "mysql": ""
}
# 身份授权代号
authorrization = {
    "OSQL-32": [1027],
    "SQLPLUS": [1091],
    "NULL": [1017]
}
#数据库对应的应用名称
app_dict = {
    "oracle": "SQLPLUS",
    "mysql": "MYSQL",
    "sqlserver": "OSQL-32"
}
# 规则id列表
ID_list = []
#数据库连接方式
dbcon_way = {
    "byway": 0,
    "direct": 1
}

#反向代理->1，透明代理->0
isproxy='1'

#每种数据库具体链接
run_db = {
    "oracle":'Linuxoracle12c',
    "mysql":'Linuxmysql5_6',
    # "db2":'DB2_97_CENTOS',DB2_97_AIX
    "db2":'DB2_97_AIX',
    # "db2":'db2_10_1',
    "gbase":'gbase_8s83',
    "sqlserver":'sqlserver2016',
    "hive":"hive84",
    "dm":"dm43"
}
def dbnamelist():
    namelist=[]
    for k,v in run_db.items():
        namelist.append(v)
    return namelist
