import time
import json
import os
import base64
import re

import pymongo
import shortuuid

from bson.objectid import ObjectId
from bson.son import SON
from flask import Flask, request, make_response
from flask_restful import Resource, Api, reqparse
from flask_tokenauth import TokenAuth, TokenManager
from pymongo.son_manipulator import AutoReference, NamespaceInjector
from pymongo.database import DBRef

# 数据库初始化
with open('ssl.txt', 'r') as f:
    ssl = f.read()
client = pymongo.MongoClient(ssl)
print('数据库连接成功:' + str(client))
db = client.treehole
userData = db.userData
announcement = db.announcement


# # 自动解引用
"""如果有循环引用使用AutoReference会导致RecursionError， 需要在特定情况下使用
"""
db.add_son_manipulator(NamespaceInjector())
# db.add_son_manipulator(AutoReference(db))


app = Flask(__name__)
api = Api(app)
secret_key = 'VQepsD6W7ZZYvLMWgHVFMk'
token_auth = TokenAuth(secret_key=secret_key)
token_manager = TokenManager(secret_key=secret_key)
permDict = {0: 'user', 1: 'class', 2: 'profession', 3: 'department', 4: 'college', 5: 'university', -1: 'system'}

# 失败代码字典
failure_dict = {1: "缺少必要参数", 2: "token已过期", 3: "用户名错误", 4: "密码错误", 5: "权限不足", 6: "该用户不存在",
                7: "数据库中无此ID", 8: "上传失败"}


# 跨域请求
@api.representation('application/json')
def output_json(data, code, headers=None):
    resp = make_response(json.dumps(data), code)
    resp.headers.extend(headers or {'Access-Control-Allow-Origin': '*'})
    return resp


# 数据库常用方法
class DbTools(object):
    """查询方法
    """
    """userData用
    """
    # 通过username查找用户并返回userdata, 不区分大小写
    @staticmethod
    def user_se_username(username):
        userdata = userData.find_one({"username": {"$regex": username, "$options": "i"}})
        return userdata

    # 通过objectId查找用户并返回userdata
    @staticmethod
    def user_se_objectid(id_):
        userdata = userData.find_one({"_id": id_})
        return userdata
    """announcement用
    """
    # 通过title查找文章并返回article
    @staticmethod
    def arti_se_title(title):
        article = announcement.find_one({"title": title})
        return article

    # 通过objectId查找文章并返回article
    @staticmethod
    def arti_se_objectid(id_):
        article = announcement.find_one({"_id": id_})
        return article


    # """更新方法
    # """
    # """userData用
    # """
    # # 通过key字典作为查询条件，通过传入的new_data字典来依次修改数据
    # @staticmethod
    # def user_update(key, new_data):
    #     for i in new_data:
    #         if

    """批量解引用
    """
    @staticmethod
    def bat_deref(ref_list):
        deref_list = []
        for i in ref_list:
            deref_list.append(db.dereference(i))
        return deref_list


# 自定义常用工具
class CustomTools(object):
    # 验证参数完整性
    @staticmethod
    def ver_par_integrity(ver_list, args):
        for i in ver_list:
            if not args[i]:
                if args[i] == 0:
                    continue
                return False
        return True

    # 返回失败错误
    @staticmethod
    def failure(failure_dict_number):
        return {"success": False, "error": failure_dict[failure_dict_number]}

    # 解引用后把ObjectID转成str后返回
    @staticmethod
    def get_deref_with_strid(ref):
        deref = db.dereference(ref)
        return deref

    # 解引用userdata并且把里面的敏感内容删除和ObjectID转成str后返回(GetOtherUser API格式)
    @staticmethod
    def get_deref_userdata(ref):
        deref = db.dereference(ref)
        deref_data = deref["Information"]
        deref_data["id"] = str(deref["_id"])
        deref_data["username"] = deref["username"]
        treehole = deref_data["treehole"]
        treehole = treehole[0:1]  # 只保留1条数据
        deref_data["treehole"] = CustomTools.batch_deref_children(treehole)
        # 将不解引用的ObjectID全部删除, 防止陷入解引用死循环以及返回报错
        key_list = ["following", "followed", "blacklist", "message"]
        for key in key_list:
            del deref_data[key]
        return deref_data

    # 批量解引用userdata并且把里面的敏感内容删除后返回(GetOtherUser API格式)
    @staticmethod
    def batch_get_deref_userdata(ref_list):
        deref_list = []
        for i in ref_list:
            CustomTools.get_deref_userdata(i)
        return deref_list

    # 将announcement内不解引用的ObjectID全部转成str, 防止陷入解引用死循环以及返回报错
    @staticmethod
    def obid_to_str(deref):
        deref["_id"] = str(deref["_id"])
        deref["ancestor"] = str(deref["ancestor"])
        del deref["parent"]  # 目前删除
        del deref["children"]  # 目前删除

    # 将文章解引用后把里面的ObjectID全都转成str
    @staticmethod
    def deref_article(ref_arti):
        deref = CustomTools.get_deref_with_strid(ref_arti)
        CustomTools.obid_to_str(deref)
        deref["user"] = CustomTools.get_deref_userdata(deref["user"])
        return deref


    # 子评论批量解引用
    @staticmethod
    def batch_deref_children(ref_children):
        deref_list = []
        for i in ref_children:
            deref_list.append(CustomTools.deref_article(i))
        return deref_list

    # 用户信息批量解引用
    @staticmethod
    def batch_deref_info(ref_info):
        # 解引用following
        ref_info["following"] = CustomTools.batch_get_deref_userdata(ref_info["following"])
        ref_info["followed"] = CustomTools.batch_get_deref_userdata(ref_info["followed"])
        ref_info["blacklist"] = CustomTools.batch_get_deref_userdata(ref_info["blacklist"])
        treehole = ref_info["treehole"]
        treehole = treehole[0:10]  # 只保留前10条数据
        ref_info["treehole"] = CustomTools.batch_deref_children(treehole)
        ref_info["message"] = CustomTools.batch_deref_children(ref_info["message"])


# 认证,别改了
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
            self.error = failure_dict[2]
            return False
        self.userdata = DbTools.user_se_username(self.username)
        if self.userdata is not None:
            return True
        return False

    # 通常验证，用于登录获取token
    def verify_normal(self, username, password):
        self.userdata = DbTools.user_se_username(username)
        if self.userdata is None:
            self.error = failure_dict[3]
            return False
        elif self.userdata['password'] == password:
            return True
        else:
            self.error = failure_dict[4]
            return False

    # 权限验证，用于限制用户操作
    def verify_perm(self, type_):
        if self.userdata['permission'][permDict[type_]]:  # 普通用户权限验证
            return True
        elif self.userdata['admin'] >= type_ or self.userdata['admin'] == -1:  # 管理员用户权限验证
            return True
        self.error = '权限不足'
        return False


# 消息
class Message(object):
    @staticmethod
    def message_add(ref_id, userid):
        userData.update({'_id': userid},
                        {'$push': {'Information.message': {'$each': [ref_id], '$position': 0}}})

    @staticmethod
    def message_del(ref_id, userid):
        userData.update({'_id': userid},
                        {"$pull": {"Information.message": ref_id}})

    @staticmethod
    def message_clear(userid):
        userData.update({'_id': userid},
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

        if DbTools.user_se_username(username) is None:  # 判断是否重名
            new_user = {'username': username,
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
            userData.insert(new_user)
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
        # 验证必要参数完整性
        ver_list = ["username"]
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)

        username = args['username']
        if DbTools.user_se_username(username) is None:
            success = {'success': True}
            return success
        else:
            failure = {'success': False,
                       'error': '用户名已被注册'}
            return failure


# 用户信息
class GetUser(Resource):
    def get(self):
        token = request.args.get("token")
        # 验证
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) is False:
            failure = {"success": False, "error": verify.error}
            return failure

        # 返回信息
        information = verify.userdata["Information"]
        CustomTools.batch_deref_info(information)
        information["id"] = str(verify.userdata["_id"])
        information["username"] = str(verify.userdata["username"])
        success = {"success": True, "user": information}
        return success


class Alter(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("token")
        parser.add_argument("avatar")
        parser.add_argument("nickname")

        args = parser.parse_args()
        # 验证必要参数完整性
        ver_list = ["token"]
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)

        # 验证
        token = args["token"]
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) is False:
            failure = {"success": False, "error": verify.error}
            return failure

        # 将新的数据update至数据库
        del args["token"]  # 删除token以防止token被update
        info_list = ["avatar", "nickname"]
        for x in info_list:  # 更新数据
            if args[x] is not None:
                docu = "Information." + x
                userData.update({"_id": verify.userdata["_id"]}, {"$set": {docu: args[x]}})
        success = {"success": True}
        return success


class GetOtherUser(Resource):
    def get(self):
        token = request.args.get("token")
        user_id = request.args.get("id")

        # 验证
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(0) is False:
            failure = {"success": False, "error": verify.error}
            return failure

        userdata = DbTools.user_se_objectid(user_id)
        if userdata is None:
            return CustomTools.failure(6)
        information = userdata["Information"]
        CustomTools.batch_deref_info(information)
        information["id"] = str(userdata["_id"])
        del information["message"]  # 阻止获取其他人的信息
        del information["blacklist"]  # 阻止获取其他人的黑名单
        success = {"success": True, "user": information}
        return success


# 发布树洞
class Announce(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("token")
        parser.add_argument("title")
        parser.add_argument("text")
        parser.add_argument("tag")
        parser.add_argument("extra", type=list)
        parser.add_argument("type", type=int)

        args = parser.parse_args()
        # 验证必要参数完整性
        ver_list = ["token", "title", "text", "tag", "type"]
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)
        if not args["extra"]:
            args["extra"] = []
        # 验证
        token = args["token"]
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(args["type"]) is False:
            failure = {"success": False, "error": verify.error}
            return failure

        """插入新文章
        """
        up_time = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())
        # 祖先数组树结构
        user_ref = DBRef(collection="userData", id=verify.userdata["_id"])
        article = {"title": args["title"], "text": args["text"], "user": user_ref,
                   "type": args["type"], "date": up_time, "tag": args["tag"],
                   "extra": args["extra"], "click": 0,
                   "ancestor": None, "parent": None, "children": []}
        article_id = announcement.insert(article)

        # 在该用户中添加该文章引用
        article_ref = DBRef(collection="announcement", id=article_id)
        userData.update({"_id": verify.userdata["_id"]},
                        {"$push": {"Information.treehole": {"$each": [article_ref], "$position": 0}}})

        success = {'success': True}
        return success


class DeleteArticle(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("token")
        parser.add_argument("article_ID")

        args = parser.parse_args()
        # 验证必要参数完整性
        ver_list = ["token", "article_ID"]
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)
        # 验证
        token = args["token"]
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {"success": False, "error": verify.error}
            return failure

        # 删除操作
        article = db.announcement.find_one({"_id": ObjectId(args["article_ID"])})
        if article is None:
            return CustomTools.failure(7)
            # 权限验证
        if article["userid"] == verify.userdata["_id"] or verify.verify_perm(article["type"]):
            announcement.remove({"_id": article["_id"]})
            # 从用户数据移除引用
            userData.update({"_id": article["userid"]},
                            {"$pull": {"Information.treehole": article["_id"]}})
            success = {'success': True}
            return success
        else:
            return CustomTools.failure(5)


class AlterArticle(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("token")
        parser.add_argument("article_ID")
        parser.add_argument("title")
        parser.add_argument("text")
        parser.add_argument("tag")
        parser.add_argument("type", type=int)
        parser.add_argument("extra", type=list)

        args = parser.parse_args()

        # 验证必要参数完整性
        ver_list = ["token", "article_ID", "title", "text", "type", "tag", "extra"]
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)

        # 验证
        token = args["token"]
        verify = Verify()
        if verify.verify_token(token) is False or verify.verify_perm(args["type"]) is False:
            failure = {"success": False, "error": verify.error}
            return failure

        # 修改操作
        article = db.announcement.find_one({"_id": ObjectId(args["article_ID"])})
        if article is None:
            return CustomTools.failure(7)
        if article["userid"] == verify.userdata["_id"] or verify.verify_perm(args["type"]):
            article_list = ["title", "text", "type", "tag", "extra"]
            for x in article_list:
                if args[x] is not None:
                    announcement.update({"_id": article["_id"]}, {"$set": {x: args[x]}})
            success = {"success": True}
            return success
        else:
            return CustomTools.failure(5)


class GetArticle(Resource):
    def get(self):
        # token = request.args.get("token")
        type_ = request.args.get("type", type=int)
        count = request.args.get('count', type=int)
        if count is None:
            count = 10
        article_id = request.args.get('article_ID')

        # # 验证
        # verify = Verify()
        # if verify.verify_token(token) is False or verify.verify_perm(0) is False:
        #     failure = {'success': False, 'error': verify.error}
        #     return failure

        # 文章结构初始化
        article = []
        # 获取
        if article_id is None:
            for item in announcement.find({'type': type_}).sort('_id', -1).limit(count):
                item['_id'] = str(item['_id'])
                item['user'] = CustomTools.get_deref_userdata(item['user'])
                del item["children"]
                article.append(item)
        else:
            for item in announcement.find({'_id': {'$lt': ObjectId(article_id)}, 'type': type_}).\
                    limit(count).sort('_id', -1):
                item['_id'] = str(item['_id'])
                item['user'] = CustomTools.get_deref_userdata(item['user'])
                del item["children"]
                article.append(item)

        # article.reverse()  # list倒序，不知道为什么前端那边会把数据倒置。
        success = {'success': True, 'article': article}
        return success


class GetOneArticle(Resource):
    def get(self):
        # token = request.args.get('token')
        article_ID = request.args.get('article_ID')

        # 验证参数完整性
        if article_ID:
            return CustomTools.failure(1)

        # # 验证
        # verify = Verify()
        # if verify.verify_token(token) is False or verify.verify_perm(0) is False:
        #     failure = {'success': False, 'error': verify.error}
        #     return failure

        # 获取
        article = DbTools.arti_se_objectid(ObjectId(article_ID))
        article['user'] = CustomTools.get_deref_userdata(article['user'])
        del article["children"]  # 删除children防止报错
        success = {'success': True, 'article': article}
        return success


class GetLast(Resource):
    def get(self):
        # token = request.args.get('token')
        type_ = request.args.get('type', type=int)
        count = request.args.get('count', type=int)
        if count is None:
            count = 10
        article_id = request.args.get('article_ID')

        # # 验证
        # verify = Verify()
        # if verify.verify_token(token) is False or verify.verify_perm(0) is False:
        #     failure = {'success': False, 'error': verify.error}
        #     return failure

        article = []
        # 获取
        if article_id is None:
            for item in announcement.find({'type': type_}).sort('_id', -1).limit(count):
                item['_id'] = str(item['_id'])
                item['user'] = CustomTools.get_deref_userdata(item['user'])
                del item["children"]  # 删除children防止报错
                article.append(item)
        else:
            for item in announcement.find({'_id': {'$gt': ObjectId(article_id)}, 'type': type_}).sort('_id', -1):
                item['_id'] = str(item['_id'])
                item['user'] = CustomTools.get_deref_userdata(item['user'])
                del item["children"]
                article.append(item)

        if len(article) == 0:
            return {'success': True, 'article': None}, 150
        # article.reverse()  # list倒序，不知道为什么前端那边会把数据倒置。
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
        ver_list = ['token', 'img', 'imgFormat']
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)

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
            image_data = base64.b64decode(s.group(2))
            image_name = shortuuid.uuid() + "." + s.group(1)
            image_path = os.path.abspath(os.path.join('/var/www/html/images', image_name))
            with open(image_path, 'wb') as imageFile:
                imageFile.write(image_data)

            image_url = 'images/' + image_name
            success = {'success': True, 'imgURL': image_url}
        except Exception as e:
            print(e)
            return CustomTools.failure(8)
        return success


# 关注用户
class Follow(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("token")
        parser.add_argument("userid")

        args = parser.parse_args()

        args["userid"] = ObjectId(args["userid"])  # 将str的userid装换成objectid
        # 验证参数完整性
        ver_list = ["token", "userid"]
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)

        # 验证
        token = args["token"]
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure
        try:
            # 检测关注方是否被被关注方拉黑
            temp = DbTools.user_se_username(args["userid"])
            blacklist = CustomTools.batch_get_deref_userdata(temp['Information']['blacklist'])
            if args["userid"] in blacklist:
                failure = {'success': False, 'error': '你已被屏蔽'}
                return failure
            # 给关注方添加following
            ref_user = DBRef(collection="userData", id=args["userid"])
            userData.update({'_id': verify.userdata["_id"]},
                            {'$push': {'Information.following': {'$each': [ref_user], '$position': 0}}})

            # 给被关注方添加followed
            ref_user = DBRef(collection="userData", id=verify.userdata["_id"])
            userData.update({'_id': args['userid']},
                            {'$push': {'Information.followed': {'$each': [ref_user], '$position': 0}}})
        except Exception as e:
            print(e)
            failure = {'success': False, 'error': '内部数据库错误'}
            return failure

        success = {'success': True}
        return success


class UnFollow(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("token")
        parser.add_argument("userid")

        args = parser.parse_args()
        args["userid"] = ObjectId(args["userid"])  # 将str的userid装换成objectid
        # 验证参数完整性
        ver_list = ["token", "userid"]
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)

        # 验证
        token = args["token"]
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        try:
            # 关注方删除following
            ref_user = DBRef(collection="userData", id=args["userid"])
            userData.update({"_id": verify.userdata["_id"]},
                            {"$pull": {"Information.following": ref_user}})

            # 被关注方删除followed
            ref_user = DBRef(collection="userData", id=verify.userdata["_id"])
            userData.update({"_id": args["userid"]},
                            {"$pull": {"Information.followed": ref_user}})
        except:
            failure = {'success': False, 'error': '内部数据库错误'}
            return failure

        success = {'success': True}
        return success


class BlackList(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("token")
        parser.add_argument("userid")

        args = parser.parse_args()
        args["userid"] = ObjectId(args["userid"])  # 将str的userid装换成objectid
        # 验证参数完整性
        ver_list = ["token", "userid"]
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        try:
            # 拉黑方删除followed
            ref_user = DBRef(collection="userData", id=args["userid"])
            userData.update({"_id": verify.userdata["_id"]},
                            {"$pull": {"Information.followed": ref_user}})

            # 被拉黑删除following
            ref_user = DBRef(collection="userData", id=verify.userdata["_id"])
            userData.update({"_id": args["userid"]},
                            {"$pull": {"Information.following": ref_user}})

            # 将被拉黑方放加入blacklist
            ref_user = DBRef(collection="userData", id=args["userid"])
            userData.update({"_id": verify.userdata["_id"]},
                            {'$push': {'Information.blacklist': {'$each': [ref_user], '$position': 0}}})
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

        args["article_ID"] = ObjectId(args["article_ID"])
        args["parent_ID"] = ObjectId(args["parent_ID"])
        # 验证参数完整性
        ver_list = ['parent_ID', 'username', 'content']
        if CustomTools.ver_par_integrity(ver_list, args) is False:
            return CustomTools.failure(1)

        # 验证
        token = args['token']
        verify = Verify()
        if verify.verify_token(token) is False:
            failure = {'success': False, 'error': verify.error}
            return failure

        # 生成引用
        if args["parent_ID"] is not None:
            ref_parent = DBRef(collection="announcement", id=args["parent_ID"])
        else:
            ref_parent = None
        ref_ancestor = DBRef(collection="announcement", id=args["article_ID"])
        upTime = time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime())

        # 将评论写入db.announcement
        comment_data = {'text': args['content'], 'user': verify.userdata['_id'],
                        'type': None, 'date': upTime,
                        'ancestor': args["article_ID"], 'parent': ref_parent, 'children': []}
        try:
            id_ = announcement.insert(comment_data)
            ref_id = DBRef(collection="announcement", id=id_)
            # 写入成功后将此评论的引用提交给父评论
            if args["parent_ID"] is not None:
                announcement.update({"_id": args["parent_ID"]},
                                    {"$push": {"children": {"$each": [ref_id], "$position": 0}}})
                # 发送至消息提示至父评论
                par_author = db.dereference(ref_parent)
                Message.message_add(ref_id, par_author['_id'])
            # 发送至消息提示至作者
            ref_author = announcement.find_one({"_id": ObjectId(args['article_ID'])})
            author = db.dereference(ref_author["user"])
            Message.message_add(ref_id, author['_id'])
        except:
            failure = {'success': False, 'error': '内部数据库错误'}
            return failure
        success = {'success': True}
        return success


class GetComment(Resource):
    def get(self):
        # token = request.args.get('token')
        type_ = None
        count = request.args.get('count', type=int)
        if count is None:
            count = 10
        article_id = ObjectId(request.args.get('article_ID'))

        # # 验证
        # verify = Verify()
        # if verify.verify_token(token) is False or verify.verify_perm(0) is False:
        #     failure = {'success': False, 'error': verify.error}
        #     return failure

        article = []
        # 获取
        if article_id is None:
            failure = {'success': False, 'error': 'article_ID为空'}
            return failure
        else:
            for item in announcement.find({'type': type_, 'ancestor': article_id}).sort('_id', -1).limit(count):
                item['_id'] = str(item['_id'])
                item['ancestor'] = str(item['ancestor'])
                item['user'] = CustomTools.get_deref_userdata(item['user'])
                if item['parent']:
                    item['parent'] = CustomTools.deref_article(item['parent'])
                item["children"] = CustomTools.batch_deref_children(item["children"])
                article.append(item)

        print(article)
        if len(article) == 0:
            return {'success': True, 'article': None}, 150
        # article.reverse()  # list倒序，不知道为什么前端那边会把数据倒置。
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
api.add_resource(GetOneArticle, '/api/getOneArticle')
api.add_resource(GetLast, '/api/getLast')
api.add_resource(UploadImg, '/api/uploadImg')
api.add_resource(Follow, '/api/follow')
api.add_resource(UnFollow, '/api/unFollow')
api.add_resource(BlackList, '/api/blackList')
api.add_resource(PostComment, '/api/postComment')
api.add_resource(GetComment, '/api/getComment')

if __name__ == '__main__':
    with open('host.txt', 'r') as f:
        ip = f.read()
    app.run(host=ip, debug=True)
