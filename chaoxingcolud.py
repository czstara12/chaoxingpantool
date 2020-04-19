import base64
import re
from io import BytesIO
import tkinter as tk
import requests
from PIL import Image, ImageTk
import http.cookiejar
#import os
import sys


class chaoxingaccount:
    def __init__(self):
        self.sess = requests.session()
        self.loadcookie()
        self.username = ''
        self.password = ''
        r = self.sess.get('http://pan-yz.chaoxing.com')
        while r.url != 'http://pan-yz.chaoxing.com/':
            r = self.login()
        self.enc = self.getenc(r)
        self.rootid = self.getrootid(r)

    def login(self):
        i = self.sess.get('https://passport2.chaoxing.com/num/code')
        img = Image.open(BytesIO(i.content))
        LoginWindow = tk.Tk()
        imgtk = ImageTk.PhotoImage(img)
        LoginWindow.geometry('380x200')
        LoginWindow.title('请登陆')
        tk.Label(LoginWindow, text='用户名:').place(x=10, y=10)
        tk.Label(LoginWindow, text='密码:').place(x=10, y=50)
        tk.Label(LoginWindow, text='验证码:').place(x=10, y=90)

        # 用户名
        var_usr_name = tk.StringVar()
        var_usr_name.set(self.username)
        entry_usr_name = tk.Entry(LoginWindow, textvariable=var_usr_name, font=('Arial', 14))
        entry_usr_name.place(x=120, y=10)
        # 用户密码
        var_usr_pwd = tk.StringVar()
        var_usr_pwd.set(self.password)
        entry_usr_pwd = tk.Entry(LoginWindow, textvariable=var_usr_pwd, font=('Arial', 14), show='*')
        entry_usr_pwd.place(x=120, y=50)
        # 验证码
        var_code = tk.StringVar()
        entry_code = tk.Entry(LoginWindow, textvariable=var_code, font=('Arial', 14), width=4)
        entry_code.place(x=120, y=90)

        img_code = tk.Label(LoginWindow, image=imgtk)
        img_code.place(x=200, y=80)
        data = {}

        def submit():
            nonlocal data
            data = {'refer_0x001': 'http%3A%2F%2Fpan-yz.chaoxing.com%2F',
                    'pid': '-1',
                    'pidName': '',
                    'fid': '-1',
                    'fidName': '',
                    'allowJoin': '0',
                    'isCheckNumCode': '1',
                    'f': '0',
                    'productid': '',
                    't': 'true',
                    'uname': var_usr_name.get(),
                    'password': base64.b64encode(var_usr_pwd.get().encode()),
                    'numcode': var_code.get(),
                    'verCode': ''}
            self.username = var_usr_name.get()
            self.password = var_usr_pwd.get()
            LoginWindow.destroy()

        loginButton = tk.Button(LoginWindow, text='提交', command=submit)
        loginButton.place(x=150, y=130)
        LoginWindow.mainloop()

        r = self.sess.post('https://passport2.chaoxing.com/login?refer=http%3A%2F%2Fpan-yz.chaoxing.com%2F', data)
        # 实例化一个LWPcookiejar对象
        new_cookie_jar = http.cookiejar.LWPCookieJar(sys.argv[0][:sys.argv[0].rfind('\\') + 1] + 'cookies.txt')
        # 将转换成字典格式的RequestsCookieJar（这里我用字典推导手动转的）保存到LWPcookiejar中
        requests.utils.cookiejar_from_dict({c.name: c.value for c in self.sess.cookies}, new_cookie_jar)
        # 保存到本地文件
        new_cookie_jar.save(sys.argv[0][:sys.argv[0].rfind('\\') + 1] + 'cookies.txt', ignore_discard=True,
                            ignore_expires=True)
        return r

    def loadcookie(self):
        load_cookiejar = http.cookiejar.LWPCookieJar()
        # 从文件中加载cookies(LWP格式)
        try:
            load_cookiejar.load(sys.argv[0][:sys.argv[0].rfind('\\') + 1] + 'cookies.txt', ignore_discard=True,
                                ignore_expires=True)
        except:
            return

        # 工具方法转换成字典
        load_cookies = requests.utils.dict_from_cookiejar(load_cookiejar)
        # 工具方法将字典转换成RequestsCookieJar，赋值给session的cookies.
        self.sess.cookies = requests.utils.cookiejar_from_dict(load_cookies)

    def newfolder(self, name=None, dir=None):
        data = {
            'parentId': '',
            'name': '',
            'selectDlid': 'onlyme',
            'newfileid': '0',
        }
        if None == name:
            data['name'] = 'Figer_bed'
        if None == dir:
            data['parentId'] = self.rootid
        return self.sess.post(r'http://pan-yz.chaoxing.com/opt/newRootfolder', data)

    def getrootid(self, r):
        rootdir_cp = re.compile(r'var _rootdir = ".*";')
        # self.rootdir = rootdir_cp.findall(r.text)
        return rootdir_cp.findall(r.text)[0][16:-2]  # self.rootdir[0][16: -2]

    def getenc(self, r):
        enc_cp = re.compile(r'var enc =".*"')
        # enc = enc_cp.findall(r.text)
        # self.enc = enc[0][10: -1]
        return enc_cp.findall(r.text)[0][10:-1]  # self.enc

    def rootdirlist(self):
        return self.dirlist(self.rootid)

    def uploadfile(self, filefolderid, localfilepath):
        pdata = {
            'folderId': filefolderid,
            # 'size': str(os.path.getsize(r'D:\Pictures\miku\75204083_p0.png'))
        }
        files = {'file': open(localfilepath, 'rb')}
        return self.sess.post('http://pan-yz.chaoxing.com/opt/upload', pdata, files=files)

    def dirlist(self, id):
        params1 = {
            'puid': '0',
            'shareid': '0',
            'parentId': id,
            'page': '1',
            'size': '99999',
            'enc': self.enc
        }
        return self.sess.get('http://pan-yz.chaoxing.com/opt/listres', params=params1)


if __name__ == '__main__':
    account1 = chaoxingaccount()
    li = account1.rootdirlist().json()['list']
    for tmp in li:
        if 'Figer_bed' == tmp['name']:
            flid = tmp['id']
            break
    if 'flid' not in vars():
        nre = account1.newfolder()
        flid = nre.json()['data']['id']
    #teststr = ['0', r"D:\Pictures\1d5a072e7b76e3538d166ee867fc0c8007d5d964.png"]
    for file in sys.argv[1:]:
        if file[0:3] == 'http':
            print(file)
            continue
        account1.uploadfile(flid, file)
        fi = account1.dirlist(flid).json()['list'][0]
        rr = account1.sess.post(r'http://pan-yz.chaoxing.com/download/downloadfile',
                                {'fleid': fi['id'], 'puid': str(fi['puid'])})
        print(rr.url)
        a = 0
        # print(r'http://pan-yz.chaoxing.com/download/downloadfile?fleid=' + fi['id'] + '&puid=' + str(fi['puid']))
