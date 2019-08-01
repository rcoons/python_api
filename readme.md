### 1.需安装的模块

#### 1.1 winrm模块

****在windows的命令窗口输入****

```
pip install pywinrm
```

****然后到python的安装目录下的site—packages文件里面，看看有没有winrm文件和xmltodict.py文件****
#### 1.2 pyodbc模块

****在windows的命令窗口输入****

```
pip install pyodbc
```
#### 1.3 cx_Oracle模块

****在windows的命令窗口输入****

```
pip install cx_Oracle
```

### 2. 执行alltest需要传入的参数

```
python All_Test.py  "testcase/" Func_*.py"  融合接口自动化测试报告
```
****第一个参数是执行脚本路径****

****第二个参数是需要执行的自动化脚本****

****第三个参数是生成的测试报告名称****

### 3.hive连接
```
安装hive连接库
pip install sasl
pip install thrift
pip install thrift-sasl
pip install PyHive
安装sasl时会报错，windows环境需要安装visualcppbuildtools full.exe文件(可远程192.168.240.88（admin/123456）,C:\soft_pakage目录下有该文件，
)
然后pip安装sasl时需要指定其与python以及操作系统位数版本，例如python3.6,windows64位对应的是sasl-0.2.1-cp36-cp36m-win_amd64.whl
下载sasl-0.2.1-cp36-cp36m-win_amd64.whl（可远程192.168.240.88（admin/123456），C:\soft_install\python\Scripts目录下有该文件），放到python的scripts目录下，cmd切换到其目录，
最后pip install sasl-0.2.1-cp36-cp36m-win_amd64.whl
```

