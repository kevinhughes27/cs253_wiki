from google.appengine.ext import db

class Page(db.Model):
    url = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
