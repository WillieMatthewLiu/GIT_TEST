#-*- coding:utf-8 -*-
'''
Created on 2017年5月11日

@author: zqzhang
'''
#coding:gb2312
import sys
import datetime
import time
import smtplib
import MySQLdb
from smtplib import SMTP_SSL
from email.mime.multipart import MIMEMultipart  
from email.mime.text import MIMEText
from email.header import Header

class CMysql:
    #成员变量
    db = ''
    cursor = ''

    #构造函数
    def __init__(self, host='192.168.0.2', user='admin', passwd='admin123!@#', database='gapdb'):
        # 打开数据库连接
        self.db = MySQLdb.connect(host, user, passwd, database)
        # 使用cursor()方法获取操作游标 
        self.cursor = self.db.cursor()

    #析构函数
    def __del__(self):
        # 关闭数据库连接
        self.db.close()

    def select_recodes(self, sql):
        ret = ''
        try:
            # 使用execute方法执行SQL语句
            self.cursor.execute(sql)
            # 获取所有记录列表
            index = self.cursor.description
            num = len(index)
            #获取表头
            for i in range(num):
                    if i != num-1:
                        ret += index[i][0]
                        ret += ','
                    else:
                        ret += index[i][0]
            ret += '\n'
            #获取内容
            results = self.cursor.fetchall()
            for res in results:
                for i in range(num):
                    if i != num-1:
                        ret += str(res[i])
                        ret += ','
                    else:
                        ret += str(res[i])
                ret += '\n'
        except:
            print "Error: unable to execute sql"
            return ret
        return ret

    def select_count(self, sql):
        results = ''
        count = 0
        try:
            # 使用execute方法执行SQL语句
            self.cursor.execute(sql)
            results = self.cursor.fetchone()
            count = results[0]
        except:
            print "Error: unable to execute sql"
            return count
        return count


class CReport:
    #创建定期报告的正文
    def create_periodic_mailtext(self, periodic, logs):
        mailtext = ''
        periodic = str(periodic)
        days = {'1':1, '2':7, '3':30}
        headline = {'1':'每日定期报告\n', '2':'每周定期报告\n', '3':'每月定期报告\n'}
        logdict = {'op':'操作日志', 'sys':'系统日志', 'eventaudit':'事件审计日志', 'accessaudit':'访问审计日志', 'sesson':'会话统计日志'}
        tabledict = {'op':'operationlogs', 'sys':'syslogs', 'eventaudit':'eventauditlogs', 'accessaudit':'accessauditlogs', 'sesson':'sessionlogs'}
        mailtext += headline[periodic]
        sql = 'select count(*) from {0} where createdtime>date_sub(now(),interval {1} day)'
        mysql = CMysql()
        for l in logs.split(','):
            count = mysql.select_count(sql.format(tabledict[l], days[periodic]))
            mailtext += logdict[l]
            mailtext += ':%s个,请查看附件\n'%(count)
        return mailtext

    #创建定期报告的附件
    def create_periodic_mailatt(self, periodic, log, total):
        att = ''
        days = {'1':1, '2':7, '3':30}
        tabledict = {'op':'operationlogs', 'sys':'syslogs', 'eventaudit':'eventauditlogs', 'accessaudit':'accessauditlogs', 'sesson':'sessionlogs'}
        sql = 'select * from {0} where createdtime>date_sub(now(),interval {1} day) order by id desc LIMIT {2}'.format(tabledict[log], days[periodic], total)
        mysql = CMysql()
        content = mysql.select_recodes(sql)
        att = MIMEText(content, 'base64', 'utf-8')
        att["Content-Type"] = 'application/octet-stream'
        att["Content-Disposition"] = 'attachment; filename="%s.csv"'%(tabledict[log]+time.strftime('%Y-%m-%d_%H:%M:%S',time.localtime(time.time())))
        return att

    #创建及时告警邮件的正文
    def create_timely_mailtext(self, seconds, modules, level):
        mailtext = ''
        headline = '及时告警信息(间隔{0}秒)\n'.format(seconds)
        logdict = {'sys':'系统事件', 'accessaudit':'访问事件'}
        tabledict = {'sys':'syslogs', 'accessaudit':'accessauditlogs'}
        mailtext += headline
        sql = 'select count(*) from {0} where level <={1} and createdtime>date_sub(now(),interval {2} second)'
        mysql = CMysql()
        for l in modules.split(','):
            count = mysql.select_count(sql.format(tabledict[l], level, seconds))
            mailtext += logdict[l]
            mailtext += ':%s个,请查看附件\n'%(count)
        return mailtext

    #创建及时告警邮件的附件
    def create_timely_mailatt(self, seconds, module, level, total):
        att = ''
        moduledict = {'sys':'syslogs', 'accessaudit':'accessauditlogs'}
        sql = 'select * from {0} where level <={1} and createdtime>date_sub(now(),interval {2} second) order by id desc LIMIT {3}'.format(moduledict[module], level, seconds, total)
        mysql = CMysql()
        content = mysql.select_recodes(sql)
        att = MIMEText(content, 'base64', 'utf-8')
        att["Content-Type"] = 'application/octet-stream'
        att["Content-Disposition"] = 'attachment; filename="%s.csv"'%(moduledict[module]+time.strftime('%Y-%m-%d_%H:%M:%S',time.localtime(time.time())))
        return att

    #获取及时告警信息的数量
    def get_alarmlog_count(self, seconds, modules, level):
        count = 0
        tabledict = {'sys':'syslogs', 'accessaudit':'accessauditlogs'}
        sql = 'select count(*) from {0} where level <={1} and createdtime>date_sub(now(),interval {2} second)'
        mysql = CMysql()
        for l in modules.split(','):
            ret = mysql.select_count(sql.format(tabledict[l], level, seconds))
            count += int(ret)
        return count

    #发送定期报告
    def send_periodic_report(self, periodic, logs, maildst, reportsend, reportuser, reportpassword):  
        subject = 'gap report'

        if int(periodic)==1:
            subject += '[每日定期报告]'
        elif int(periodic)==2:    
            subject += '[每周定期报告]'
        elif int(periodic)==3:    
            subject += '[每月定期报告]'
        else:  
            return
        
        #创建文本信息
        mailtext = self.create_periodic_mailtext(periodic, logs)
        msg = MIMEMultipart('related')
        msgcontent =  MIMEText(mailtext,'plain','utf-8')
        msg.attach(msgcontent)
        #创建附件
        lognum = len(logs.split(','))
        eachtotal = 1000/lognum
        for l in logs.split(','):
            att = self.create_periodic_mailatt(periodic, l, eachtotal)
            msg.attach(att)

        sender = reportuser
        receiver1 = maildst
        username = reportuser
        password = reportpassword

        msg['Subject'] = Header(subject, 'utf-8')
        msg['from'] =sender
        msg['to'] = receiver1
        msg["Accept-Language"]="zh-CN"
        msg["Accept-Charset"]="ISO-8859-1,utf-8"

        smtp = SMTP_SSL(reportsend)
        smtp.ehlo(reportsend);
        smtp.login(username, password)
        smtp.sendmail(sender, receiver1, msg.as_string())
        smtp.quit()

    #发送及时告警
    def send_timely_alarm(self, seconds, modules, level, maildst, reportsend, reportuser, reportpassword):  
        subject = 'gap report[及时告警信息(间隔{0}秒)]'.format(seconds)
        #没有告警信息，则不用频率发送空的邮件
        alarmlog = self.get_alarmlog_count(seconds, modules, level)
        if alarmlog == 0:
            return

        #创建文本信息
        mailtext = self.create_timely_mailtext(seconds, modules, level)
        msg = MIMEMultipart('related')
        msgcontent =  MIMEText(mailtext,'plain','utf-8')
        msg.attach(msgcontent)
        #创建附件
        lognum = len(modules.split(','))
        eachtotal = 1000/lognum
        for m in modules.split(','):
            att = self.create_timely_mailatt(seconds, m, level, eachtotal)
            msg.attach(att)

        sender = reportuser
        receiver1 = maildst
        username = reportuser
        password = reportpassword

        msg['Subject'] = Header(subject, 'utf-8')
        msg['from'] =sender
        msg['to'] = receiver1
        msg["Accept-Language"]="zh-CN"
        msg["Accept-Charset"]="ISO-8859-1,utf-8"

        smtp = SMTP_SSL(reportsend)
        smtp.ehlo(reportsend);
        smtp.login(username, password)
        smtp.sendmail(sender, receiver1, msg.as_string())
        smtp.quit()

def usage():
        print 'python {0} --periodic-report --periodic WORD --logs WORD --smtpserver WORD --smtpuser WORD --smtppasswd WORD --destmail WORD'.format(sys.argv[0])
        print 'python {0} --timely-report --modules WORD --level WORD --frequency WORD --smtpserver WORD --smtpuser WORD --smtppasswd WORD --destmail WORD'.format(sys.argv[0])

def main():
        if len(sys.argv) != 14 and len(sys.argv) != 16:
            usage()
            return -1

        if sys.argv[1] == '--periodic-report':
            report = CReport()
            report.send_periodic_report(sys.argv[3],sys.argv[5],sys.argv[13], sys.argv[7], sys.argv[9],sys.argv[11])

        elif sys.argv[1] == '--timely-report':
            report = CReport()
            report.send_timely_alarm(sys.argv[7], sys.argv[3], sys.argv[5],sys.argv[15], sys.argv[9], sys.argv[11],sys.argv[13])

        return 0

if __name__ == '__main__':
        ret = main()
        exit(ret)
