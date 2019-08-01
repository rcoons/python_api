import sys
class GlobalConfig:
    cookie_ = ""
    cur_dir_ = sys.path[0]
    dbservice_ = {}#数据库服务
    rest_api_ = {}
    risk_sql_ = {}
    '''数据库类型'''
    db_type_ = {
        "oracle": "Oracle",
        "mysql": "MySQL",
        "sqlserver": "Sql Server",
        "DB2": "DB2",
        "gbase": "gbase_8s83",
        "hive": "hive",
        "dm": "DM"
    }
