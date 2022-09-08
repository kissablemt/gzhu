import http.cookiejar
import json
import os
import random
import re
import sys
import time
import traceback
import urllib
import execjs
import urllib3
from lxml import etree
from requests_html import HTMLSession

urllib3.disable_warnings()

def str_enc(data: str, first_key: str, second_key: str, third_key: str) -> str:
    """抓包中, login12-new.js 第172行调用了此函数, 直接把该函数js文件保存下来,
       然后使用execjs模块调用

    Args:
        data (str): f"{username}{password}{lt}"
        first_key (str): 默认, 1
        second_key (str): 默认, 2
        third_key (str): 默认, 3

    Returns:
        str: rsa, 用于登录提交的data之一
    """
    with open("des.js", "r") as f:
        des_js = execjs.compile(f.read())
    res = des_js.call("strEnc", data, first_key, second_key, third_key)

    return res

class GZHU:
    def __init__(self, username: str, password: str, proxies: dict={}, cookiejar_path: str="cookiejar.txt") -> None:
        self.username = username
        self.password = password
        self.proxies = proxies
        
        self.sess = HTMLSession()
        self.cookiejar_path = cookiejar_path

    def req(self, url, method="get", params=None, data=None, allow_redirects=True, timeout=10, headers={}, wait=True, wait_time=0):
        if wait:
            if wait_time > 0:
                time.sleep(wait_time)
            else:
                time.sleep(0.15 + random.random())
        h_ = headers
        headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/98.0.4758.82 Safari/537.36 Edg/98.0.1108.51",
        }
        headers.update(h_)
        cookies = {}
        if method == "get" or method == "post":
            return getattr(self.sess, method)(
                url=url,
                params=params,
                data=data,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=allow_redirects,
                verify=False,
                proxies=self.proxies, # 使用代理
            )
        else:
            raise Exception("Requests method error")
    
    def is_login(self) -> bool:
        """检测登录

        Returns:
            bool: _description_
        """
        resp = self.req("https://newmy.gzhu.edu.cn/up/view?m=up#act=portal/viewhome")
        return self.username in resp.text

    def login(self) -> bool:
        """登录

        Returns:
            bool: 是否登录成功
        """
        # 加载cookiejar
        if os.path.exists(self.cookiejar_path):
            cookiejar = http.cookiejar.LWPCookieJar()
            cookiejar.load(self.cookiejar_path, ignore_discard=True, ignore_expires=True)
            self.sess.cookies = cookiejar
        else:
            self.sess.cookies = http.cookiejar.LWPCookieJar(filename=self.cookiejar_path)

        # using cookiejar
        if self.is_login():
            print("Using cookiejar")
            return True

        # cookies失效或不使用, 使用账号密码登录
        login_url = "https://newcas.gzhu.edu.cn/cas/login?service=https://newmy.gzhu.edu.cn/up/view?m=up"
        resp = self.req(login_url)
        lt = etree.HTML(resp.text).xpath('//*[@id="lt"]/@value')[0]
        execution = etree.HTML(resp.text).xpath('//*[@name="execution"]/@value')[0]
        rsa = str_enc(f"{self.username}{self.password}{lt}", "1", "2", "3") # 抓包中, login12-new.js 第172行调用了此函数, 参数是这样的
        data = { # 抓包加逆向所得
            "rsa": rsa,
            "ul": len(self.username),
            "pl": len(self.password),
            "lt": lt,
            "execution": execution,
            "_eventId": "submit",
        }
        resp = self.req(login_url, method="post", data=data)
        if self.username in resp.text:
            # os.remove(self.cookiejar_path)
            self.sess.cookies.save(filename=self.cookiejar_path, ignore_discard=True, ignore_expires=True)
            print("Using password")
            return True
        return False

    def logout(self) -> bool:
        """退出登录, 基本没用, cookies实际上没有失效, 还能再用
        Returns:
            bool: 是否成功退出
        """
        logout_url = "https://newcas.gzhu.edu.cn/cas/login?service=https://newmy.gzhu.edu.cn/up/logout"
        resp = self.req(logout_url)
        resp = self.req(url="https://newmy.gzhu.edu.cn/up/view?m=up#act=portal/viewhome") # 访问主页, 检测是否退出成功
        return self.username not in resp.text

    def clear_cookies(self) -> None:
        if os.path.exists(self.cookiejar_path):
            os.remove(self.cookiejar_path)

def yqtb(user: GZHU) -> bool:
    """疫情填报 自动打卡
        接口是抓包加前端逆向获得
        流程接口: 
            1. /start GET => workflowId, csrfToken, idc, release
            2. /preview POST(workflowId, csrfToken, rand, width) => {"errno":0, "ecode":"SUCCEED", "error":""Succeed.", entities:[{ ... }]} 具体抓包重新看
            3. /start POST(idc, release, csrfToken, formData, lang) => {...} 具体抓包重新看
            4. /render GET => stepId, instanceId, csrfToken
            5. /render POST(stepId, instanceId, admin, rand, width, lang, csrfToken) => {...} 获取到旧的填报记录, 修改其中部分就能提交
            6. /doAction POST(stepId, actionId, formData, timestamp, rand, boundFields, csrfToken, lang, remark, nextUsers) => 打卡结果 {"errno":0,"ecode":"SUCCEED","error":"打卡成功","entities":[{...}]}
    Args:
        user (GZHU): 已登录的广大账号

    Returns:
        bool: 是否打卡成功
    """
    try:
        #检测是否登录到健康系统
        if "已完成" not in user.req("https://yqtb.gzhu.edu.cn/taskcenter/workflow/index").text:
            print("Clear cookiejar and login again...")
            user.clear_cookies()
            user.login()

        # 1. /start GET
        start_resp = user.req("https://yqtb.gzhu.edu.cn/infoplus/form/XNYQSB/start")
        csrfToken_in_start_resp = re.compile('<meta itemscope="csrfToken" content="(.*)">').findall(start_resp.text)[0]
        print("[OKAY] /start GET")


        # 2. /preview POST
        data = {
            "workflowId": re.compile('workflowId = "(.*)";').findall(start_resp.text)[0], # from /start GET
            "csrfToken": csrfToken_in_start_resp, # from /start GET
            "rand": random.random() * 999, # from /start GET, Math.random() * 999
            "width": 1200, # 宽度, 随便都可以
        }
        preview_resp_post = user.req("https://yqtb.gzhu.edu.cn/infoplus/interface/preview", method="post", data=data)
        print("[OKAY] /preview POST")


        # 3. /start POST, 获取render url
        data = {
            "idc": re.compile('idc: "(.*)",').findall(start_resp.text)[0], # from /start GET
            "release": re.compile('release: "(.*)",').findall(start_resp.text)[0], # from /start GET
            "csrfToken": csrfToken_in_start_resp, # from /start GET
            "formData": preview_resp_post.json()["entities"][0]["data"], # /preview 返回的json体能找到
            "lang": "zh",
        }
        data = urllib.parse.urlencode(data) # "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        start_resp_post = user.req("https://yqtb.gzhu.edu.cn/infoplus/interface/start", method="post", data=data, headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
        render_url = start_resp_post.json()["entities"][0] # very important
        print(f"[OKAY] /start POST => {render_url}")


        # 4. 先从 /render GET 获取信息
        render_resp = user.req(render_url)
        print("[OKAY] /render GET")


        # 5. /render POST, 一定要添加Referer, 不然报错{"errno":10000,"ecode":"EXCEPTION","error":"Missing header 'Referer' of type [java.lang.Long]","entities":[]}
        stepId = re.compile('formStepId = (.*);').findall(render_resp.text)[0]
        csrfToken_in_render_resp = re.compile('<meta itemscope="csrfToken" content="(.*)">').findall(render_resp.text)[0]
        data = { # render.min.js 找 load: function
            "stepId": stepId, # from /render GET
            "instanceId": re.compile('instanceId = "(.*)";').findall(render_resp.text)[0], # from /render GET
            "admin": False,
            "rand": random.random() * 999, # from /render GET, Math.random() * 999
            "width": 1200, # 宽度, 随便都可以
            "lang": "zh",
            "csrfToken": csrfToken_in_render_resp, # from /render GET
        }
        render_resp_post = user.req("https://yqtb.gzhu.edu.cn/infoplus/interface/render", method="post", data=data, headers={"Referer": render_url})
        print("[OKAY] /render POST")
        
        
        # 旧的疫情填报记录
        qk_form = render_resp_post.json()["entities"][0]["data"]

        # 开始填报!!! 在网页查看未填写的项的field是什么, 直接改qk_form就行
        qk_form["fieldJBXXdrsfwc"] = "2" # 当日是否外出, "2" 代表没有外出
        qk_form["fieldYQJLsfjcqtbl"] = "2" # 是否接触过半个月内有疫情重点地区旅居史的人员, "2"代表没有接触
        qk_form["fieldJKMsfwlm"] = "1" # 健康码是否为绿码, "1"代表为绿码
        qk_form["fieldCXXXsftjhb"] = "2" # 半个月内是否到过国内疫情重点地区, "2"代表否
        qk_form["fieldCNS"] = True # 本人承诺对上述填报内容真实性负责，如有不实，本人愿意承担一切责任

        # /listNextStepsUsers , 与/doAction 不知道啥区别, 测试可以跳过

        # 6. /doAction POST
        data = {
            "stepId": stepId, # from /render GET
            "actionId": 1,
            "formData":  qk_form,
            "timestamp": int(time.time()),
            "rand": random.random() * 999,
            "boundFields": ",".join(render_resp_post.json()["entities"][0]["fields"].keys()),
            "csrfToken": csrfToken_in_render_resp, # from /render GET
            "lang": "zh",
            "remark": "",
            "nextUsers": {},
        }
        data = urllib.parse.urlencode(data) # "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        doAction_resp = user.req("https://yqtb.gzhu.edu.cn/infoplus/interface/doAction", method="post", data=data, headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "Referer": render_url})
        print("[OKAY] /doAction POST")

        if doAction_resp.json()["error"] == "打卡成功":
            return True
    except:
        traceback.print_tb(sys.exc_info()[2])
        user.clear_cookies() # 打卡失败时, 清除登录cookies

    return False
