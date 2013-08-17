#!/usr/bin/env python

import os
import re
import webapp2
import jinja2
import hmac
import time

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

from google.appengine.ext import db

from user import User
from page import Page

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    SECRET = 'imsosecret'
    def hash_str(self,s):
        return hmac.new(self.SECRET,s).hexdigest()

    def make_secure_val(self,val):
        return '%s|%s' % (val, self.hash_str(val))

    def check_secure_val(self,secure_val):
        val = secure_val.split('|')[0]
        if secure_val == self.make_secure_val(val):
            return val

    def set_secure_cookie(self, name, val):
        cookie_val = self.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
            
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and self.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))
    
    def logout(self):
        self.response.headers.add_header('Set-Cookie','user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))    



class SignupHandler(Handler):
  
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PWD_RE = re.compile("^.{3,20}$")
    EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")
    
    def valid_username(self, username):
        return self.USER_RE.match(username)

    def valid_password(self, password):
        return self.PWD_RE.match(password)

    def valid_email(self, email):
        return self.EMAIL_RE.match(email)
    
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.render('signup.html', next_url = next_url)

    def post(self):
        error = False
        
        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login'):
            next_url = '/'
        
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
	    
        params = dict(username=username, email=email)
        
        if not self.valid_username(username):
            error = True
            params['username_error'] = "That's not a valid username."
        if User.by_username(username):
            error = True
            params['username_error'] = "username in use."
        if not self.valid_password(password):
            error = True
            params['password_error'] = "That's not a valid password."
        if password != verify:
            error = True
            params['verify_error'] = "Your passwords didn't match."
        if email != "":
            if not self.valid_email(email):
                error = True
                params['email_error'] = "That's not a valid email."

        if not error:
            u = User.register(username=username, password=password, email=email)
            u.put()
            self.login(u)
            self.redirect(next_url)
        else:
            self.render('signup.html', **params)



class LoginHandler(Handler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.render('login.html')

    def post(self):
        
        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login'):
            next_url = '/'
    
        username = self.request.get("username")
        password = self.request.get("password")
         
        u,e = User.login(username,password)        

        if u:
            self.login(u)
            self.redirect(next_url)
        else:    
            self.render('login.html', *e)



class LogoutHandler(Handler):
    def get(self):
        self.logout()
        self.redirect('/signup')   


    
class PageHandler(Handler):
    def get(self, url):
        
        v = self.request.get('v')
        p = None
        
        if v:
            if v.isdigit():
                p = Page.get_by_id(int(v))
            
            if not p:
                self.error(404)
                return     
        else:
            p = Page.all().filter('url =', url).order("-created").get()
        
        if p:
            self.render('page.html', page = p, user=self.user)
        else:
            self.redirect('/_edit'+url) 
            
            
            
class EditHandler(Handler):
    def get(self, url):
        if not self.user:
            self.redirect('/login')
        
        v = self.request.get('v')
        p = None
        
        if v:
            if v.isdigit():
                p = Page.get_by_id(int(v))
            
            if not p:
                self.error(404)
                return     
        else:
            p = Page.all().filter('url =', url).order("-created").get()
            
        self.render('edit.html', page=p, user=self.user)
        
    def post(self, url):
        content = self.request.get("content")
        new_page = Page(url=url, content=content)
        new_page.put()
        time.sleep(0.1) # wait for db to avoid race condition
        self.redirect(url)  
        


class HistoryPageHandler(Handler):
    def get(self, url):
        p = Page.all().filter('url =', url).get()
        if p:
            h = Page.all().filter('url =', url).order('-created').fetch(15)
            self.render('history.html', history = h, user=self.user)
        else:
            self.redirect('/_edit'+url) 
            


PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/_history' + PAGE_RE, HistoryPageHandler),
                               ('/_edit' + PAGE_RE, EditHandler),
                               (PAGE_RE, PageHandler)],
                               debug=True)



