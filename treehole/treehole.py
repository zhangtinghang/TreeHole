import time
import json
import os
import sys
import base64
import re

import pymongo
import shortuuid

from bson.objectid import ObjectId
from flask import Flask, request, make_response
from flask_restful import Resource, Api, reqparse
from flask_tokenauth import TokenAuth, TokenManager

# 数据库初始化
with open('ssl.txt', 'r') as f:
    ssl = f.read()
client = pymongo.MongoClient(ssl)
print('数据库连接成功:' + str(client))
db = client.treehole
userData = db.userData
announcement = db.announcement

app = Flask(__name__)
api = Api(app)
secret_key = 'VQepsD6W7ZZYvLMWgHVFMk'
token_auth = TokenAuth(secret_key=secret_key)
token_manager = TokenManager(secret_key=secret_key)
permDict = {0: 'user', 1: 'class', 2: 'profession', 3: 'department', 4: 'college', 5: 'university', -1: 'system'}


@api.representation('application/json')
def output_json(data, code, headers=None):
    resp = make_response(json.dumps(data), code)
    resp.headers.extend(headers or {'Access-Control-Allow-Origin': '*'})
    return resp


# 数据库操作
class DBOp(object):
    # 通过username查找用户并返回userdata
    def sUsername(self, username):
        userdata = userData.find_one({'username': {'$regex': username, '$options': 'i'}})
        return userdata


# 认证,需要改善算法
class Token(object):
    def get_token(self, username):
        token = token_manager.generate(username, 2592000)
        return token


class Verify(object):
    # token验证
    @token_auth.verify_token
    def verify_token(self, token):
        self.username = token_manager.verify(token)
        if self.username is None:
            self.error = 'token已过期'
            return False

        self.userdata = DBOp().sUsername(self.username)
        if self.userdata is not None:
            return True
        return False

    # 通常验证，用于登录获取token
    def verify_normal(self, username, password):
        self.userdata = DBOp().sUsername(username)
        if self.userdata is None:
            self.error = '用户名错误'
            return False
        elif self.userdata['password'] == password:
            return True
        else:
            self.error = '密码错误'
            return False

    # 权限验证，用于限制用户操作
    def verify_perm(self, type):
        if self.userdata['permission'][permDict[type]]:  # 普通用户权限验证
            return True
        elif self.userdata['admin'] >= type or self.userdata['admin'] == -1:  # 管理员用户权限验证
            return True
        self.error = '权限不足'
        return False


# 消息
class Message(object):
    @staticmethod
    def message_add(object_id, username):
        userData.update({'username': username},
                        {'$push': {'Information.message': {'$each': object_id, '$position': 0}}})

    @staticmethod
    def message_del(object_id, username):
        userData.update({'username': username},
                        {"$pull": {"Information.message": object_id}})

    @staticmethod
    def message_clear(username):
        userData.update({'username': username},
                        {'$set': {"Information.message": []}})


# 登录注册
class Login(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username')
        parser.add_argument('password')

        args = parser.parse_args()
        username = args['username']
        password = args['password']
        # 认证
        verify = Verify()
        if verify.verify_normal(username, password):
            token = Token()
            success = {'success': True,
                       'token': token.get_token(username).decode()}
            return success
        else:
            failure = {'success': False, 'error': verify.error}
            return failure


class Register(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username')
        parser.add_argument('password')
        parser.add_argument('problem_id', type=int)
        parser.add_argument('answer')

        args = parser.parse_args()
        username = args['username']
        if username is None:
            failure = {'success': False,
                       'error': '用户名不得为空'}
            return failure
        password = args['password']
        if password is None:
            failure = {'success': False,
                       'error': '密码不得为空'}
            return failure
        problem_id = args['problem_id']
        if problem_id is None:
            failure = {'success': False,
                       'error': '问题不得为空'}
            return failure
        answer = args['answer']
        if answer is None:
            failure = {'success': False,
                       'error': '答案不得为空'}
            return failure

        if DBOp().sUsername(username) is None:  # 判断是否重名
            newUser = {'username': username,
                       'password': password,
                       'problem_id': problem_id,
                       'answer': answer,
                       'Information': {'avatar': 1,
                                       'nickname': 'none',
                                       'following': [],
                                       'followed': [],
                                       'treehole': [],
                                       'blacklist': [],
                                       'message': []
                                       },
                       'permission': {'user': True},
                       'admin': 0
                       }
            userData.insert(newUser)
            token = Token()
            success = {'success': True,
                       'token': token.get_token(username).decode()}
            return success
        else:
            failure = {'success': False,
                       'error': '用户名已被注册'}
            return failure


class RegisterUsername(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('username')

        args = parser.parse_args()
        username = args['username']
        if DBOp().sUsername(username) is None:
            success = {'success': True}
            return success
        else:
            failure = {'success': False,
                       'error': '用户名已被注册'}
            return failure


# 用户信息
class GetUser(Resource):
    def get(self):
        # 验证
        token = request.args.get('token')
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        # 返回信息
        information = verify.userdata['Information']
        information['id'] = str(verify.userdata['_id'])
        information['username'] = str(verify.userdata['username'])
        success = {'success': True, 'user': information}
        return success


class Alter(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token')
        parser.add_argument('avatar')
        parser.add_argument('nickname')

        args = parser.parse_args()
        # 验证必要参数完整性
        verList = ['token']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        # 将新的数据update至数据库
        del args['token']  # 删除token以防止token被update
        imformList = ['avatar', 'nickname']
        for x in imformList:  # 更新数据
            if args[x] is not None:
                docu = 'Information.' + x
                userData.update({'username': verify.userdata['username']}, {'$set': {docu: args[x]}})
        success = {'success': True}
        return success


class GetOtherUser(Resource):
    def get(self):
        # 验证
        token = request.args.get('token')
        userID = request.args.get('id')  # ID机制需要改善，暂时使用username
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        userdata = DBOp().sUsername(userID)  # 改善后这里也要改
        if userdata is None:
            failure = {'success': False, 'error': '该用户不存在'}
            return failure
        information = userdata['Information']
        information['id'] = str(userdata['_id'])

        success = {'success': True, 'user': information}
        return success


# 发布树洞
class Announce(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token')
        parser.add_argument('title')
        parser.add_argument('text')
        parser.add_argument('tag', type=list)  # List
        parser.add_argument('type', type=int)

        args = parser.parse_args()
        # 验证必要参数完整性
        verList = ['token', 'title', 'text', 'tag', 'type']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure
        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(args['type']) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        # 插入新文章
        upTime = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        # 祖先数组树结构
        article = {'title': args['title'], 'text': args['text'], 'username': verify.userdata['username'],
                   'type': args['type'], 'date': upTime, 'tag': args['tag'],
                   'detail': '', 'ancestors': [], 'parent': None}
        article_id = announcement.insert(article)

        # 在该用户中添加该文章索引
        userData.update({'username': verify.username},
                        {'$push': {'Information.treehole': {'$each': [str(article_id)], '$position': 0}}})

        success = {'success': True}
        return success


class DeleteArticle(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token')
        parser.add_argument('article_ID')

        args = parser.parse_args()
        # 验证必要参数完整性
        verList = ['token', 'article_ID']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        # 删除操作
        article = db.announcement.find_one({'_id': ObjectId(args['article_ID'])})
        if article is None:
            failure = {'success': False, 'error': '没有找到该文章'}
            return failure
            # 权限验证
        if article['username'] == verify.userdata['username'] or verify.verify_perm(article['type']):
            announcement.remove({'_id': ObjectId(args['article_ID'])})
            success = {'success': True}
            return success
        else:
            failure = {'success': False, 'error': '权限不足'}
            return failure


class AlterArticle(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token')
        parser.add_argument('article_ID')
        parser.add_argument('title')
        parser.add_argument('text')
        parser.add_argument('tag')
        parser.add_argument('type', type=int)

        args = parser.parse_args()
        # 验证必要参数完整性
        verList = ['token', 'article_ID', 'title', 'text', 'type', 'tag']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(args['type']) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        # 修改操作
        article = db.announcement.find_one({'_id': ObjectId(args['article_ID'])})
        if article is None:
            failure = {'success': False, 'error': '没有找到该文章'}
            return failure
        if article['username'] == verify.userdata['username'] or verify.verify_perm(args['type']):
            articleList = ['title', 'text', 'type', 'tag']
            for x in articleList:
                if args[x] is not None:
                    announcement.update({'_id': ObjectId(args['article_ID'])}, {'$set': {x: args[x]}})
            success = {'success': True}
            return success
        else:
            failure = {'success': False, 'error': '权限不足'}
            return failure


class GetArticle(Resource):
    def get(self):
        token = request.args.get('token')
        type = request.args.get('type', type=int)
        count = request.args.get('count', type=int)
        if count is None:
            count = 10
        article_ID = request.args.get('article_ID')

        # 验证
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        # 文章结构初始化
        article = []
        # 获取
        if article_ID is None:
            for item in announcement.find({'type': type}).sort('_id', -1).limit(count):
                item['_id'] = str(item['_id'])
                article.append(item)
        else:
            for item in announcement.find({'_id': {'$lt': ObjectId(article_ID)}, 'type': type}).limit(count).sort('_id',
                                                                                                                  -1):
                item['_id'] = str(item['_id'])
                article.append(item)

        article.reverse()  # list倒序，不知道为什么前端那边会把数据倒置。
        success = {'success': True, 'article': article}
        return success


# class SearchArticle(Resource):
#     def get(self):
#         token = request.args.get('token')
#         type = request.args.get('type', type=int)
#         count = request.args.get('count', type=int)
#         if count is None:
#             count = 10
#         article_ID = request.args.get('article_ID')


class GetLast(Resource):
    def get(self):
        token = request.args.get('token')
        type = request.args.get('type', type=int)
        count = request.args.get('count', type=int)
        if count is None:
            count = 10
        article_ID = request.args.get('article_ID')

        # 验证
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) == False:
            failure = {'success': False, 'error': verify.error}
            return failure

        article = []
        # 获取
        if article_ID is None:
            for item in announcement.find({'type': type}).sort('_id', -1).limit(count):
                item['_id'] = str(item['_id'])
                article.append(item)
        else:
            for item in announcement.find({'_id': {'$gt': ObjectId(article_ID)}, 'type': type}).sort('_id', -1):
                item['_id'] = str(item['_id'])
                article.append(item)

        if len(article) == 0:
            return {'success': True, 'article': None}, 150
        article.reverse()  # list倒序，不知道为什么前端那边会把数据倒置。
        success = {'success': True, 'article': article}
        return success


# 图片上传
class UploadImg(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token')
        parser.add_argument('img')
        parser.add_argument('imgFormat')

        args = parser.parse_args()

        # 验证必要参数完整性
        verList = ['token', 'img', 'imgFormat']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        # 正则表达式处理imgdata
        pattern = r'data:image/(.*);base64,(.*)'

        s = re.search(pattern, args['img'])

        # 将图片解码并保存至images文件夹
        try:
            imageData = s.group(2)
            imageName = shortuuid.uuid() + s.group(1)
            imagePath = os.path.abspath(os.path.join('/var/www/html/images', imageName))
            with open(imagePath, 'wb') as imageFile:
                imageFile.write(imageData)

            imageURL = 'images/' + imageName
            success = {'success': True, 'imgURL': imageURL}
        except Exception as e:
            print(e)
            failure = {'success': False, 'error': '上传失败'}
            return failure
        return success


# 关注用户
class Follow(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token')
        parser.add_argument('username')

        args = parser.parse_args()

        # 验证参数完整性
        verList = ['token', 'username']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure
        try:
            # 检测关注方是否被被关注方拉黑
            temp = DBOp().sUsername(args['username'])
            if args['username'] in temp['Information']['blacklist']:
                failure = {'success': False, 'error': '你已被屏蔽'}
                return failure
            # 给关注方添加following
            userData.update({'username': verify.username},
                            {'$push': {'Information.following': {'$each': [args['username']], '$position': 0}}})

            # 给被关注方添加followed
            userData.update({'username': args['username']},
                            {'$push': {'Information.followed': {'$each': [verify.username], '$position': 0}}})
        except:
            failure = {'success': False, 'error': '内部数据库错误'}
            return failure

        success = {'success': True}
        return success


class UnFollow(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token')
        parser.add_argument('username')

        args = parser.parse_args()

        # 验证参数完整性
        verList = ['token', 'username']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        try:
            # 关注方删除following
            userData.update({'username': verify.username},
                            {"$pull": {"Information.following": args['username']}})

            # 被关注方删除followed
            userData.update({'username': args['username']},
                            {"$pull": {"Information.followed": verify.username}})
        except:
            failure = {'success': False, 'error': '内部数据库错误'}
            return failure

        success = {'success': True}
        return success


class BlackList(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('token')
        parser.add_argument('username')

        args = parser.parse_args()
        # 验证参数完整性
        verList = ['token', 'username']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure
        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        try:
            # 拉黑方删除followed
            userData.update({'username': verify.username},
                            {"$pull": {"Information.followed": args['username']}})

            # 被拉黑删除following
            userData.update({'username': args['username']},
                            {"$pull": {"Information.following": verify.username}})

            # 将被拉黑方放加入blacklist
            userData.update({'username': verify.username},
                            {'$push': {'Information.blacklist': {'$each': [args['username']], '$position': 0}}})
        except:
            failure = {'success': False, 'error': '内部数据库错误'}
            return failure
        success = {'success': True}
        return success


# 评论
class PostComment(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('article_ID')
        parser.add_argument('parent_ID')
        parser.add_argument('token')
        parser.add_argument('content')

        args = parser.parse_args()

        # 验证参数完整性
        verList = ['article_ID', 'parent_ID', 'username', 'content']
        for x in verList:
            if args[x] is None:
                failure = {'success': False, 'error': '缺少必要参数'}
                return failure

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

            # 生成祖先数组需要的元素
            # 祖先
        searchParent = announcement.find_one({"_id": ObjectId(args['parent_ID'])})
        treeAncestors = searchParent['ancestors']
        treeAncestors.append(ObjectId(args['parent_ID']))
        # 父
        treeParent = ObjectId(args['parent_ID'])
        upTime = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        # 将评论写入db.announcement
        commentData = {'text': args['content'], 'username': verify.userdata['username'],
                       'type': None, 'date': upTime,
                       'ancestors': treeAncestors, 'parent': treeParent}
        try:
            id_ = announcement.insert(commentData)
            # 发送至消息提示至父评论作者以及文章作者
            if args['article_ID'] != args['parent_ID']:  # 防止给作者发两次消息
                author = announcement.find_one({"_id": ObjectId(args['article_ID'])})
                Message.message_add(str(id_), author('username'))
            Message.message_add(str(id_), searchParent['username'])
        except:
            failure = {'success': False, 'error': '内部数据库错误'}
            return failure
        success = {'success': True}
        return success


class GetComment(Resource):
    def get(self):
        token = request.args.get('token')
        type = None
        count = request.args.get('count', type=int)
        if count is None:
            count = 10
        article_ID = ObjectId(request.args.get('article_ID'))

        # 验证
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        article = []
        # 获取
        if article_ID is None:
            failure = {'success': False, 'error': 'article_ID为空'}
            return failure
        else:
            for item in announcement.find({'type': type, 'ancestors': article_ID}).sort('_id', -1).limit(count):
                item['_id'] = str(item['_id'])
                article.append(item)

        if len(article) == 0:
            return {'success': True, 'article': None}, 150
        article.reverse()  # list倒序，不知道为什么前端那边会把数据倒置。
        success = {'success': True, 'article': article}
        return success
# API
api.add_resource(Login, '/api/login')
api.add_resource(Register, '/api/register')
api.add_resource(RegisterUsername, '/api/registerUsername')
api.add_resource(GetUser, '/api/getUser')
api.add_resource(Alter, '/api/alter')
api.add_resource(GetOtherUser, '/api/getOtherUser')
api.add_resource(Announce, '/api/announce')
api.add_resource(DeleteArticle, '/api/deleteArticle')
api.add_resource(AlterArticle, '/api/alterArticle')
api.add_resource(GetArticle, '/api/getArticle')
api.add_resource(GetLast, '/api/getLast')
api.add_resource(UploadImg, '/api/uploadImg')
api.add_resource(Follow, '/api/follow')
api.add_resource(UnFollow, '/api/unFollow')
api.add_resource(BlackList, '/api/blackList')
api.add_resource(PostComment, '/api/postComment')
api.add_resource(GetComment, '/api/getComment')

if __name__ == '__main__':
    app.run(host='10.0.0.4', debug=True)
