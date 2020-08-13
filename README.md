# vbulletin5 rce漏洞检测工具



# 0x00 概述

201909 vbulletion5(5.0.0-5.5.4)爆出rce漏洞（CVE-2019-16759），利用文件ajax/render/widget_php和post参数widgetConfig[code]可直接远程代码执行。

20200811，网上爆出CVE-2019-16759补丁可被绕过，利用ajax/render/widget_tabbedcontainer_tab_panel和构造post参数subWidgets[0][config][code]可直接远程代码执行。

本工具支持单url检测，cmdshell，get web shell(写入一句话木马)，批量检测，批量getshell。

目标shodan指纹：http.favicon.hash:-601665621


## 0x01 需求

python3

pip3 install -r requirements.txt



## 0x02 快速开始

使用帮助: python3 vbulletin_rce.py -h




单url漏洞检测: python vbulletin5-rce.py -u "http://www.xxx.com/"



cmdshell: python vbulletin5-rce.py -u "http://www.xxx.com/" --cmdshell


单url getshell: python vbulletin5-rce.py -u "http://www.xxx.com/" --getshell


批量检测: python vbulletin5-rce.py -f urls.txt



批量getshhell: python vbulletin5-rce.py -f urls.txt --getshell


getshell默认使用的是shell目录下的behinder.php(冰蝎默认shell)可食用-shell参数设置自定义shell文件

## 0x03 反馈


gmail：[adeljck@gmail.com](mailto:adeljck@gmail.com)

qq：[crack@xsafe.org](mailto:crack@xsafe.org)