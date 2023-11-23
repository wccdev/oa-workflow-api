import base64
import json
from itertools import groupby

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from django.core.cache import cache
from requests.exceptions import JSONDecodeError
from rest_framework.exceptions import APIException

from .settings import api_settings


class OaApi:
    TOKEN_KEY = "token"
    CACHE_TOKEN_KEY = "oa-api-token"
    REQUEST_CONTENTTYPE = "application/x-www-form-urlencoded; charset=utf-8"
    REQUEST_HEADERS = {"Content-Type": REQUEST_CONTENTTYPE}

    PUBLIC_KEY_PREFIX = "-----BEGIN PUBLIC KEY-----"
    PUBLIC_KEY_SUFFIX = "-----END PUBLIC KEY-----"

    @classmethod
    def handle_pub_key(cls, pub_key):
        """
        处理公钥格式
        :param pub_key:
        :return:
        """
        start = f"{cls.PUBLIC_KEY_PREFIX}\n"
        end = cls.PUBLIC_KEY_SUFFIX
        result = ''
        # 分割key，每64位长度换一行
        length = len(pub_key)
        divide = 64  # 切片长度
        offset = 0  # 拼接长度
        while length - offset > 0:
            if length - offset > divide:
                result += pub_key[offset : offset + divide] + '\n'
            else:
                result += pub_key[offset:] + '\n'
            offset += divide
        result = start + result + end
        return result

    def __init__(self):
        self.oa_host = api_settings.OA_HOST
        self.app_id = api_settings.APP_ID
        if not api_settings.APP_SPK.startswith(self.PUBLIC_KEY_PREFIX):
            self.app_spk = self.handle_pub_key(api_settings.APP_SPK)
        else:
            self.app_spk = api_settings.APP_SPK
        self.app_encrypted_secret = self.__encrypt_with_spk(api_settings.APP_RAW_SECRET)
        # self.encrypt_userid = self.__get_encrypt_userid(oa_user_id)
        self.encrypt_userid = ""

        self.token = cache.get(self.CACHE_TOKEN_KEY)

        self.maximum_recursion = 8
        self.recursion_c = 0

    def __helpme(self, error):
        if self.recursion_c >= self.maximum_recursion:
            raise ValueError(error)
        self.recursion_c += 1

    def get_sso_token(self, login_id):
        raise BaseException("暂无法使用该方法")
        UMAP = {  # noqa
            "18781": "A0009527",
            "18783": "A0009528",
            "18784": "A0009529",
            "18785": "A0009530",
            "18786": "A0009531",
            "18787": "A0009555",
            "18788": "A0009556",
            "1": "sysadmin",
        }
        api_path = "/ssologin/getToken"
        headers = {"Content-Type": self.REQUEST_CONTENTTYPE}
        post_data = {"appid": "srm_test", "loginid": UMAP[login_id]}
        token = self._post_oa(api_path, post_data=post_data, headers=headers, need_json=False)
        return token

    @property
    def user(self):
        if getattr(self, "_user", None):
            return self._user
        return {"userid": ""}

    def register_user(self, oa_user_id: str):
        if getattr(self, "user", {}) and self.user["userid"] == oa_user_id:
            return

        if not self.token:
            self.get_token()
        self.oa_user_id = oa_user_id
        self.encrypt_userid = self.__encrypt_with_spk(oa_user_id)
        self._user = self.userinfo()

    def __encrypt_with_spk(self, text: str):
        """
        使用OA SPK加密文本
        :param text:
        :return:
        """
        publickey = RSA.import_key(self.app_spk.encode())
        pk = PKCS1_v1_5.new(publickey)
        encrypt_text = pk.encrypt(text.encode())
        result = base64.b64encode(encrypt_text)
        return result.decode()

    def get_token(self, expr=10800):
        """
        获取Oa API Token
        :param expr:
        :return:
        """
        api_path = "/api/ec/dev/auth/applytoken"
        headers = {
            "appid": self.app_id,
            "secret": self.app_encrypted_secret,
            "time": str(expr),
        }
        res = self._post_oa(api_path, headers=headers)
        # resp.text {
        # "msg":"获取成功!","code":0,"msgShowType":"none","status":true,"token":"e3d7e45b-805c-43c3-9c0c-e452135ae1ea"
        # }
        print("新Token: ", res[self.TOKEN_KEY])
        self.token = res[self.TOKEN_KEY]
        cache.set(self.CACHE_TOKEN_KEY, self.token, timeout=None)
        return self.token

    @property
    def _request_headers(self):
        if not self.encrypt_userid:
            raise NotImplementedError("调用前请先使用.register_user(OA_USER_ID: str)方法注册当前要操作的OA账号")
        headers = {
            "Content-Type": self.REQUEST_CONTENTTYPE,
            "appid": self.app_id,
            self.TOKEN_KEY: self.token,
            "userid": self.encrypt_userid,
        }
        return headers

    def __request(
        self, api_path, rf: any([requests.get, requests.post]), headers: dict = None, need_json=True, **kwargs  # noqa
    ):
        url = f"{self.oa_host}{api_path}"
        headers = headers or self._request_headers
        resp: requests.Response = rf(url, headers=headers, **kwargs)

        if resp.status_code != 200:
            # 错误导致递归的问题
            # print(resp.text)
            # raise SystemError(f"OA: Response[{resp.status_code}]")
            self.__helpme(f"OA: Response[{resp.status_code}]")
            headers[self.TOKEN_KEY] = self.get_token()
            return self.__request(api_path, rf, headers=headers, need_json=need_json, **kwargs)

        if not need_json:
            return resp.text

        try:
            res = resp.json()
        except JSONDecodeError:
            raise ValueError(f"OA: {resp.text}")
            res = {"code": -1}

        # TODO 错误响应
        # {"msg":"secret解密失败,请检查加密内容.","code":-1,"msgShowType":"none","status":false}
        # {'msg':'token不存在或者超时：4225b79b-9407-47ca-82ab-d66850c4ec3e','code':-1,'msgShowType':'none','status':False}
        # {'msg': '登录信息超时', 'errorCode': '002', 'status': False}
        # {"msg":"该账号存在异常,单点登录失败","code":-1,"msgShowType":"none","status":false}
        if type(res) is dict and not res.get("status", True):
            resp_msg = res.get("msg", "")
            if res.get("code") == -1:
                if resp_msg == "secret解密失败,请检查加密内容.":
                    explain_suf = "(或为OA APP_SPK失效)"
                elif resp_msg.startswith("认证信息错误"):
                    explain_suf = "(或为OA APP_SECRET失效)"
                elif resp_msg.startswith("token不存在或者超时"):
                    self.__helpme(resp.text)
                    headers[self.TOKEN_KEY] = self.get_token()
                    return self.__request(api_path, rf, headers=headers, need_json=need_json, **kwargs)
                else:
                    explain_suf = "(或为OA License过期)"
                raise APIException(detail=f"OA Error: {resp_msg}。{explain_suf}")
            if resp_msg == "登录信息超时":
                self.__helpme(resp.text)
                headers[self.TOKEN_KEY] = self.get_token()
                return self.__request(api_path, rf, headers=headers, need_json=need_json, **kwargs)
            raise ValueError(f"Error: {resp.text}")
        if type(res) is dict and res.get("code", "") and res["code"] != "SUCCESS":
            raise APIException(detail=f"OA提示: {res['code']}, {res.get('errMsg', '')}")
        return res

    def _get_oa(self, api: str, params: dict = None, headers: dict = None, need_json=True):
        return self.__request(api, requests.get, params=params, headers=headers, need_json=need_json)

    def _post_oa(self, api: str, post_data: dict = None, headers: dict = None, need_json=True, **kwargs):
        return self.__request(api, requests.post, data=post_data, headers=headers, need_json=need_json, **kwargs)

    def _page_data(self, page_count_path, page_data_path, page=1, page_size=10):
        """
        请求分页数据
        :param page_count_path:
        :param page_data_path:
        :return:
        """
        """
        - 测试目录                       workflowTypes    type_id = 1021
           S-返利申请备案流程-测试上线版    workflowIds           id = 49022
           内部价2                       workflowIds           id = 51022
           内部价                        workflowIds           id = 50522
        """
        # search_conditions = {"conditions": json.dumps({"workflowTypes": "1021"})}
        search_conditions = {
            "conditions": json.dumps(
                {
                    # "workflowTypes": "1021",  # 流程目录ID  2,3,4
                    "workflowIds": "52021"  # 流程ID     1,2,3
                }
            )
        }
        resp = self._post_oa(page_count_path, post_data=search_conditions, need_json=False)
        todo_count = int(resp)

        if (page - 1) * page_size >= todo_count:
            return [], page, todo_count

        post_data = {"pageNo": str(page), "pageSize": str(page_size), **search_conditions}
        res: list = self._post_oa(
            page_data_path,
            post_data=post_data,  # , need_json=False
        )

        return res, page, todo_count

    def userinfo(self):
        """
        获取账号信息
        :return:
        """
        api_path = "/api/hrm/login/getAccountList"
        user_info = self._get_oa(api_path)
        # user_info = resp.json()
        _ = {
            "data": {
                "accountlist": [
                    {
                        "subcompanyid": 21,
                        "jobs": "Default",
                        "icon": "/messager/images/icon_m_wev8.jpg",
                        "deptid": 21,
                        "subcompanyname": "格科微电子（上海）有限公司",
                        "iscurrent": "1",
                        "userid": "18781",
                        "username": "Leslie Chan",
                        "deptname": "公共关系部",
                    }
                ],
                "subcompanyid": 21,
                "jobs": "Default",
                "icon": "/messager/images/icon_m_wev8.jpg",
                "deptid": 21,
                "subcompanyname": "格科微电子（上海）有限公司",
                "iscurrent": "1",
                "userid": "18781",
                "deptname": "公共关系部",
                "userLanguage": "7",
                "showSearch": False,
                "showMore": True,
                "username": "Leslie Chan",
                "fontSetting": False,
            },
            "status": "1",
        }
        return user_info["data"]

    def upload_file(self, oa_category_id: str, file_source: BytesIO, file_name):
        """
        上传附件
        :param oa_category_id: Oa附件目录ID
        :param file_source: 上传到Oa的文件内容
        :param file_name: 上传到Oa的文件名称
        :return:
        """
        api_path = "/api/doc/upload/uploadFile2Doc"
        # api_path = "/api/doc/upload/uploadFile"
        body = {"category": oa_category_id, "name": file_name}
        headers = self._request_headers.copy()
        headers.pop("Content-Type")
        files = {"file": file_source}
        resp = self._post_oa(api_path, post_data=body, headers=headers, files=files)
        return resp["data"]["fileid"]


class OaWorkFlow(OaApi):
    def get_todo_list(self, page, page_size):
        """
        待办流程
        """
        # count_api_path = "/api/workflow/paService/getDoingWorkflowRequestCount"
        # data_api_path = "/api/workflow/paService/getDoingWorkflowRequestList"
        count_api_path = "/api/workflow/paService/getToDoWorkflowRequestCount"
        data_api_path = "/api/workflow/paService/getToDoWorkflowRequestList"
        data, page, total_count = self._page_data(count_api_path, data_api_path, page=page, page_size=page_size)
        _ = [
            {
                "agentorbyagentid": "-1",
                "agenttype": "0",
                "cid": "425163",
                "createTime": "2023-08-04 16:23:04",
                "creatorDepartmentId": "0",
                "creatorDepartmentName": "",
                "creatorId": "1",
                "creatorName": "系统管理员",
                "creatorSubcompanyId": "0",
                "creatorSubcompanyName": "",
                "currentNodeId": "61021",
                "currentNodeName": "创建",
                "currentnodetype": "0",
                "isbereject": "1",  # 是否被退回  1: 是
                "isprocessed": "",
                "isremark": "0",
                "lastOperateTime": "2023-08-04 16:23:28",
                "lastOperatorId": "18781",
                "lastOperatorName": "Leslie Chan",
                "nodeid": "61021",
                "operateTime": "2023-08-04 16:24:11",
                "preisremark": "0",
                "receiveTime": "2023-08-04 16:23:28",
                "requestId": "315437",
                "requestLevel": "0",
                "requestName": "NBJ2-Leslie-202308040005",
                "requestmark": "",
                "status": "创建",
                "sysName": "",
                "takisremark": "",
                "userDepartmentId": "0",
                "userDepartmentName": "",
                "userName": "系统管理员",
                "userSubcompanyId": "0",
                "userSubcompanyName": "",
                "userid": "1",
                "usertype": "0",
                "viewtype": "-2",
                "workflowBaseInfo": {
                    "formId": "-266",
                    "workflowId": "51022",
                    "workflowName": "内部价2",
                    "workflowTypeId": "1021",
                    "workflowTypeName": "测试目录",
                },
            },
            # ...
        ]
        return data, page, total_count

    def get_handled_list(self, page, page_size):
        """
        已办流程
        """
        count_api_path = "/api/workflow/paService/getHandledWorkflowRequestCount"
        data_api_path = "/api/workflow/paService/getHandledWorkflowRequestList"
        data, page, total_count = self._page_data(count_api_path, data_api_path, page=page, page_size=page_size)
        _ = [
            {
                "agentorbyagentid": "-1",
                "agenttype": "0",
                "cid": "425367",
                "createTime": "2023-08-08 15:09:09",
                "creatorDepartmentId": "0",
                "creatorDepartmentName": "",
                "creatorId": "1",
                "creatorName": "系统管理员",
                "creatorSubcompanyId": "0",
                "creatorSubcompanyName": "",
                "currentNodeId": "60031",
                "currentNodeName": "销管审核",
                "currentnodetype": "1",
                "isbereject": "",
                "isprocessed": "",
                "isremark": "2",
                "lastOperateTime": "2023-08-08 15:09:09",
                "lastOperatorId": "1",
                "lastOperatorName": "系统管理员",
                "nodeid": "60024",
                "operateTime": "2023-08-08 15:09:09",
                "preisremark": "0",
                "receiveTime": "2023-08-08 15:09:09",
                "requestId": "315470",
                "requestLevel": "0",
                "requestName": "Leslie-TEST-202308080014",
                "requestmark": "",
                "status": "TO 销管审核",
                "sysName": "",
                "takisremark": "",
                "userDepartmentId": "0",
                "userDepartmentName": "",
                "userName": "系统管理员",
                "userSubcompanyId": "0",
                "userSubcompanyName": "",
                "userid": "1",
                "usertype": "0",
                "viewtype": "-2",
                "workflowBaseInfo": {
                    "formId": "-259",
                    "workflowId": "50021",
                    "workflowName": "S-特价报备流程2",
                    "workflowTypeId": "521",
                    "workflowTypeName": "销售部流程",
                },
            },
            # ...
        ]
        return data, page, total_count

    def get_create_list(self):
        """
        可创建流程
        """
        # count_api_path = "/api/workflow/paService/getCreateWorkflowCount"
        api_path = "/api/workflow/paService/getCreateWorkflowList"
        post_data = {
            "conditions": json.dumps(
                {
                    # "wfIds": "51022",  # 流程
                    "wfTypeIds": "1"  # "1021"  # 目录
                }
            )
        }
        res: list = self._post_oa(api_path, post_data=post_data)
        _ = [
            {
                "formId": "-40",
                "workflowId": "6021",
                "workflowName": "A-外部车辆租车申请",
                "workflowTypeId": "1521",
                "workflowTypeName": "行政部流程",
            },
            # ...
        ]
        result = []
        res.sort(key=lambda x: x["workflowTypeName"])
        for type_name, g in groupby(res, key=lambda x: x["workflowTypeName"]):
            result.append({"workflowTypeName": type_name, "workflows": list(g)})
        return result

    def submit(self, post_data: dict, work_flow_id: str = None):
        """
        创建流程
        :param post_data:
        :param work_flow_id: Oa中的流程ID
        # :param oa_detail_table: SCM单据ID
        """
        # work_flow_id 51002 创建流程
        # work_flow_id 51003 编辑流程

        # doc_id 单据ID

        doc_id = "ABCCCCCCCCCCC"
        doc_code = f"Leslie-TEST-{doc_id}"

        """1.内部价2"""
        _post_data = {  # noqa
            "detailData": json.dumps(
                [
                    {
                        "tableDBName": "formtable_main_266_dt1",
                        "workflowRequestTableRecords": [
                            {
                                "recordOrder": 0,
                                "workflowRequestTableFields": [
                                    {"fieldName": "cpbh", "fieldValue": "2asdsd33233"},
                                    {"fieldName": "bz", "fieldValue": 1},
                                    {"fieldName": "jg", "fieldValue": 12.22},
                                    {"fieldName": "jgbs", "fieldValue": 1},
                                    {"fieldName": "cplx", "fieldValue": 1},
                                    {"fieldName": "cgqy", "fieldValue": "Haha"},
                                    {"fieldName": "xsqy", "fieldValue": "Heihei"},
                                    {"fieldName": "sxrq", "fieldValue": "2023-08-12"},
                                    {"fieldName": "zzrq", "fieldValue": "2023-08-12"},
                                ],
                            }
                        ],
                    }
                ]
            ),
            "mainData": json.dumps(
                [
                    {"fieldName": "cjriqi", "fieldValue": "2023-08-12"},
                    # {"fieldName": "djbh", "fieldValue": doc_code},
                    # {"fieldName": "sqrtrue", "fieldValue": "1"},
                    # {"fieldName": "sqrbmtrue", "fieldValue": ""},
                    # {"fieldName": "wybh", "fieldValue": str(uuid.uuid4())},
                ]
            ),
            "otherParams": {},
            "remark": "",
            "requestLevel": "0",
            "requestName": f"NBJ2-{doc_code}",
            "workflowId": "51022",  # 内部价2
        }

        """2.S-特价报备流程2"""
        post_data2 = {  # noqa
            "detailData": json.dumps(
                [
                    {
                        "tableDBName": "formtable_main_259_dt1",
                        "workflowRequestTableRecords": [
                            {
                                "recordOrder": 0,
                                "workflowRequestTableFields": [
                                    {"fieldName": "gnamewb", "fieldValue": "纽晨"},
                                    {"fieldName": "gname", "fieldValue": "7656"},
                                    {"fieldName": "ppwb", "fieldValue": "珠穆朗玛"},
                                    {"fieldName": "pp", "fieldValue": "866"},
                                    {"fieldName": "omdwb", "fieldValue": "宏达创新"},
                                    {"fieldName": "omd", "fieldValue": "882"},
                                    {"fieldName": "xm", "fieldValue": "阿萨德"},
                                    {"fieldName": "cpxhwb", "fieldValue": "CSPsd-3.5"},
                                    {"fieldName": "cpxh", "fieldValue": "3724"},
                                    {"fieldName": "yj", "fieldValue": "12.2200"},
                                    {"fieldName": "tj", "fieldValue": "10.2200"},
                                    {"fieldName": "sxrq", "fieldValue": "2023-08-12"},
                                    {"fieldName": "zzrq", "fieldValue": "2023-08-31"},
                                    {"fieldName": "yjxmchlk", "fieldValue": "123.0"},
                                    {"fieldName": "sfbj", "fieldValue": "1"},
                                    # {"fieldName": "blslpcs", "fieldValue": ""},
                                    {"fieldName": "dj", "fieldValue": ""},
                                    {"fieldName": "sqyy", "fieldValue": "111111111"},
                                    {"fieldName": "sfsjrebate", "fieldValue": "2"},
                                    {"fieldName": "bz", "fieldValue": "4"},
                                ],
                            }
                        ],
                    }
                ]
            ),
            "mainData": json.dumps(
                [
                    {"fieldName": "djbh", "fieldValue": doc_code},
                    {"fieldName": "sqr", "fieldValue": "1"},
                    {"fieldName": "sqrq", "fieldValue": "2023-08-12"},
                    {"fieldName": "sqrbm", "fieldValue": ""},
                    {"fieldName": "sffdba", "fieldValue": "1"},
                    {"fieldName": "cplx1", "fieldValue": "3,1"},
                    {"fieldName": "djlx", "fieldValue": "0"},
                    {"fieldName": "fjsc", "fieldValue": ""},
                    {"fieldName": "sfpc", "fieldValue": "1"},
                ]
            ),
            "otherParams": {},
            "remark": "",
            "requestLevel": "0",
            "requestName": doc_code,
            "workflowId": "50021",  # S-特价报备流程2
        }

        """SRM V0.1"""
        __post_data = {  # noqa
            "mainData": json.dumps(
                [
                    {"fieldName": "djbh", "fieldValue": "2023-08-12"},
                    # {"fieldName": "djbh", "fieldValue": doc_code},
                    # {"fieldName": "sqrtrue", "fieldValue": "1"},
                    # {"fieldName": "sqrbmtrue", "fieldValue": ""},
                    # {"fieldName": "wybh", "fieldValue": str(uuid.uuid4())},
                ]
            ),
            "otherParams": {},
            "remark": "",
            "requestLevel": "0",
            "requestName": f"SRM-V0.1-{doc_code}",
            "workflowId": "51022",  # 内部价2
        }
        api_path = "/api/workflow/paService/doCreateRequest"
        res: dict = self._post_oa(api_path, post_data=post_data)
        oa_request_id = res["data"]["requestid"]
        return oa_request_id

    def review(self, request_id: str, remark="", extras: dict = None):
        """
        提交/审核
        :param request_id OA流程请求ID
        :param remark
        :param extras
        """
        api_path = "/api/workflow/paService/submitRequest"
        post_data = {"otherParams": {}, "remark": remark, "requestId": request_id}
        if extras:
            post_data.update(extras)
        resp = self._post_oa(api_path, post_data=post_data)

        # ERROR DATA
        _ERROR = {  # noqa
            "code": "NO_PERMISSION",
            "errMsg": {"isremark": 2},
            "reqFailMsg": {
                "keyParameters": {},
                "msgInfo": {},
                "msgType": "NO_REQUEST_SUBMIT_PERMISSION",
                "otherParams": {},
            },
        }
        return resp

    def reject(self, request_id: str, node_id: str = "", remark=""):
        """
        退回流程
        """
        api_path = "/api/workflow/paService/rejectRequest"
        other_params = "{}"
        if node_id:
            other_params = json.dumps({"RejectToType": 0, "RejectToNodeid": int(node_id)})

        post_data = {"otherParams": other_params, "remark": remark, "requestId": request_id}
        resp = self._post_oa(api_path, post_data=post_data)

        # ERROR DEEMO
        _ERROR = {  # noqa
            "code": "NO_PERMISSION",
            "errMsg": {"isremark": 2, "takisremark": -1, "nodeType": 0},
            "reqFailMsg": {
                "keyParameters": {},
                "msgInfo": {},
                "msgType": "NO_REQUEST_SUBMIT_PERMISSION",
                "otherParams": {},
            },
        }
        _OK = {  # noqa
            "code": "SUCCESS",
            "errMsg": {},
            "reqFailMsg": {"keyParameters": {}, "msgInfo": {}, "otherParams": {"doAutoApprove": "0"}},
        }
        return resp

    def get_chart_url(self, request_id: str):
        """
        OA流程明细页 流程图 数据
        :return:
        """
        api_path = "/api/workflow/paService/getRequestFlowChart"
        params = {"requestid": request_id}
        # params = None
        resp = self._get_oa(api_path, params=params)
        _ = {  # noqa
            "code": "SUCCESS",
            "data": {
                "chartUrl": """
                /workflow/workflowDesign/readOnly-index.html?requestid=315470
                &f_weaver_belongto_userid=1&f_weaver_belongto_usertype=0
                &isFree=0&isAllowNodeFreeFlow=&isReadOnlyModel=true
                &isFlowModel=0&hasFreeNode=0&showE9Pic=1&isFromWfForm=true&workflowId=50021
                """
            },
            "errMsg": {},
        }
        # 获取单点Token
        sso_token = self.get_sso_token(self.oa_user_id)
        resp["data"]["chartUrl"] = resp["data"]["chartUrl"] + f"&ssoToken={sso_token}"
        return resp

    def get_status(self, request_id: str):
        """
        获取流程状态
        :param request_id:
        :return:
        """
        api_path = "/api/workflow/paService/getRequestStatus"
        params = {"requestId": request_id}
        resp = self._get_oa(api_path, params=params)
        _ = {  # noqa
            'code': 'SUCCESS',
            'data': {
                'create': False,
                'creatertype': 0,
                'creatorId': '1',
                'currentNodeId': '61021',
                'currentNodeType': '0',
                'currentOperateId': 425163,
                'eh_operatorMap': {},
                'extendNodeId': '61021',
                'handWrittenSign': 0,
                'isremark': 0,
                'languageid': 7,
                'mainTableInfoEntity': {'billid': -266, 'tableDbName': 'formtable_main_266'},
                'needAffirmance': False,
                'rejcetToType': 0,
                'rejectToNodeid': 0,
                'requestId': '315437',
                'requestLevel': '0',
                'requestName': 'NBJ2-Leslie-202308040005',
                'speechAttachment': 0,
                'status': '创建',
                'submitToNodeid': 0,
                'takisremark': -1,
                'workflowBaseInfo': {
                    'formId': '-266',
                    'isBill': '1',
                    'ischangrejectnode': 0,
                    'isrejectremind': 0,
                    'isselectrejectnode': 0,
                    'workflowName': '内部价2',
                    'workflowTypeId': '1021',
                },
                'workflowId': 51022,
            },
            'errMsg': {},
        }
        return resp

    def get_operator_info(self, request_id):
        """
        OA流程明细页 流程状态 数据
        :param request_id:
        :return:
        """
        api_path = "/api/workflow/paService/getRequestOperatorInfo"
        res = self._get_oa(api_path, params={"requestId": request_id})
        return res

    def get_resources(self, request_id):
        """
        OA流程明细页 相关资源 数据
        相关流程/相关文档/相关资源
        :param request_id:
        :return:
        """
        api_path = "/api/workflow/paService/getRequestResources"
        params = {"requestId": request_id}
        result = self._get_oa(api_path, params=params)
        _ = {  # noqa
            "code": "SUCCESS",
            "data": [
                {
                    "createdate": "2023-08-07",
                    "createrName": "系统管理员",
                    "createrid": 1,
                    "createtime": "18:05:14",
                    "downloadUrl": "/weaver/weaver.file.FileDownload?"
                    "fileid=ab99dab3f07c723903c7fdeb696"
                    "e56eed2a6885aa3f633100a6e5fb5cc55a"
                    "f339d1c3817502a4fc2f476f90a9ce9fc8"
                    "b3cb067d6b4bb7f4d1&amp;download=1&"
                    "amp;requestid=&amp;ddcode=45a3b24f8d8aeca4",
                    "id": 13529,
                    "name": "计时器.png",
                    "type": 3,
                },
                {
                    "createdate": "2023-08-07",
                    "createrName": "系统管理员",
                    "createrid": 1,
                    "createtime": "18:05:15",
                    "downloadUrl": "/weaver/weaver.file.FileDownload?fileid"
                    "=a170157de37192f7a67a612d37a2bfeefc7d9f"
                    "09056b45b5e1bf048cf9294b2ffab4f36b60ab2"
                    "64bf1405a62c95de624acb067d6b4bb7f4d1&am"
                    "p;download=1&amp;requestid=&amp;ddcode=ea71400844d01f1d",
                    "id": 13530,
                    "name": "test.py",
                    "type": 3,
                },
                {
                    "createdate": "2023-08-07",
                    "createrName": "系统管理员",
                    "createrid": 1,
                    "createtime": "18:05:15",
                    "id": 13531,
                    "name": "测试Fake流程1",
                    "type": 1,
                },
                {
                    "createdate": "2023-08-07",
                    "createrName": "系统管理员",
                    "createrid": 1,
                    "createtime": "18:05:15",
                    "id": 13532,
                    "name": "测试Fake流程2",
                    "type": 1,
                },
                {
                    "createdate": "2023-08-07",
                    "createrName": "系统管理员",
                    "createrid": 1,
                    "createtime": "18:05:15",
                    "id": 13533,
                    "name": "测试Fake文档1",
                    "type": 2,
                },
                {
                    "createdate": "2023-08-07",
                    "createrName": "系统管理员",
                    "createrid": 1,
                    "createtime": "18:05:15",
                    "id": 13534,
                    "name": "测试Fake文档2",
                    "type": 2,
                },
            ],
            "errMsg": {},
        }
        __ = {  # noqa
            'code': 'SUCCESS',
            'data': [  # noqa
                {
                    'createdate': '2023-08-07',
                    'createrName': '系统管理员',
                    'createrid': 1,
                    'createtime': '18:05:14',
                    'downloadUrl': '/weaver/weaver.file.FileDownload?fil'
                    'eid=a8462a2aefc95637489c1085bee08b34'
                    '6254c7a6e7eb28707d2c2374288f69a2905d'
                    'ea01c801cea42d890ab08a283f0d87136214'
                    '1037cfb4e&download=1&requestid=&ddco'
                    'de=45a3b24f8d8aeca4',
                    'id': 13529,
                    'name': '计时器.png',
                    'type': 3,
                },
                {
                    'createdate': '2023-08-07',
                    'createrName': '系统管理员',
                    'createrid': 1,
                    'createtime': '18:05:15',
                    'downloadUrl': '/weaver/weaver.file.FileDownload?file'
                    'id=a0adc047bc57e9af7a5b33de57d18409b5'
                    '33970a43927596406fa3e32c64751d3ad5cf1'
                    'a03d173f1dd890ab08a283f0d871362141037'
                    'cfb4e&download=1&requestid=&ddcode=ea71400844d01f1d',
                    'id': 13530,
                    'name': 'test.py',
                    'type': 3,
                },
            ],
            'errMsg': {},
        }
        # 资源类型 type
        # 1: 相关流程
        # 2: 相关文档
        # 3: 相关附件
        # result = _
        type_map = {1: "相关流程", 2: "相关文档", 3: "相关附件"}
        for res in result["data"]:
            if res["type"] == 3:  # 相关附件
                pass
            res["typeName"] = type_map[res["type"]]
        return result

    def get_remark(self, request_id, page=1, page_size=10):
        """
        流程意见
        :return:
        """
        api_path = "/api/workflow/paService/getRequestLog"
        post_data = {"requestId": request_id, "otherParams": json.dumps({"pageSize": page_size, "pageNumber": page})}
        resp = self._get_oa(api_path, params=post_data)
        _ = {  # noqa
            'code': 'SUCCESS',
            'data': [
                {
                    'speechattachmentid': 0,
                    'signdocids': '',
                    'nodeattribute': '0',
                    'speechAttachmente9': '',
                    'operatorDept': '21',
                    'tmpLogId': '419352',
                    'operatedate': '2023-08-04',
                    'destnodeid': '61021',
                    'receivedPersons': '系统管理员',
                    'nodeid': '61022',
                    'operator': '18781',
                    'isRobotNode': '',
                    'annexdocids': '',
                    'handwrittensignid': 'null',
                    'signworkflowids': '',
                    'agentorbyagentid': '-1',
                    'iframeId': 'FCKsigniframe419352',
                    'remarkHtml': '',
                    'id': '419352',
                    'isMobile': '',
                    'receivedPersonids': '1',
                    'remarkLocation': 'null',
                    'operatetime': '16:23:28',
                    'logid': '0',
                    'operatortype': '0',
                    'agenttype': '0',
                    'nodename': '审批2',
                    'isbranche': '0',
                    'fulltextannotation': '',
                    'logtype': '3',
                },
                {
                    'speechattachmentid': 0,
                    'signdocids': '',
                    'nodeattribute': '0',
                    'speechAttachmente9': '',
                    'operatorDept': '0',
                    'tmpLogId': '419351',
                    'operatedate': '2023-08-04',
                    'destnodeid': '61022',
                    'receivedPersons': 'Leslie Chan',
                    'nodeid': '61021',
                    'operator': '1',
                    'isRobotNode': '',
                    'annexdocids': '',
                    'handwrittensignid': 'null',
                    'signworkflowids': '',
                    'agentorbyagentid': '-1',
                    'iframeId': 'FCKsigniframe419351',
                    'remarkHtml': '',
                    'id': '419351',
                    'isMobile': '',
                    'receivedPersonids': '18781',
                    'remarkLocation': 'null',
                    'operatetime': '16:23:04',
                    'logid': '0',
                    'operatortype': '0',
                    'agenttype': '0',
                    'nodename': '创建',
                    'isbranche': '0',
                    'fulltextannotation': '',
                    'logtype': '2',
                },
            ],
            'errMsg': {},
        }
        return resp

    def get_info(self, request_id):
        """
        流程信息
        :param request_id:
        :return:
        """
        api_path = "/api/workflow/paService/getWorkflowRequest"
        res = self._get_oa(api_path, params={"requestId": request_id})
        _ = {  # noqa
            'code': 'SUCCESS',
            'data': {
                'canEdit': True,
                'canView': True,
                'createTime': '2023-08-04 16:23:04',
                'creatorId': '1',
                'creatorName': '系统管理员',
                'currentNodeId': '61021',
                'currentNodeName': '创建',
                'forwardButtonName': '转发',
                'lastOperateTime': '2023-08-04 16:23:28',
                'lastOperatorName': '',
                'messageType': '0',
                'mustInputRemark': False,
                'needAffirmance': False,
                'rejectButtonName': '',
                'remark': '',
                'requestId': '315437',
                'requestLevel': '0',
                'requestName': 'NBJ2-Leslie-202308040005',
                'status': '创建',
                'subbackButtonName': '',
                'submitButtonName': '提交',
                'subnobackButtonName': '',
                'workflowBaseInfo': {
                    'workflowId': '51022',
                    'workflowName': '内部价2',
                    'workflowTypeId': '1021',
                    'workflowTypeName': '测试目录',
                },
                'workflowDetailTableInfos': [
                    {
                        'tableDBName': 'formtable_main_266_dt1',
                        'tableFieldName': ['产品编号', '币种', '价格', '价格标识', '产品类型', '采购企业', '销售企业', '生效日期', '终止日期'],
                        'tableTitle': '',
                        'workflowRequestTableRecords': [
                            {
                                'recordOrder': 41,
                                'workflowRequestTableFields': [
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'varchar2(300)',
                                        'fieldFormName': 'field179945_0',
                                        'fieldHtmlType': '1',
                                        'fieldId': '179945',
                                        'fieldName': 'cpbh',
                                        'fieldOrder': 0,
                                        'fieldShowName': '产品编号',
                                        'fieldShowValue': '2asdsd33233',
                                        'fieldType': '1',
                                        'fieldValue': '2asdsd33233',
                                        'filedHtmlShow': (
                                            '<table style="width:100%;"><tr><'
                                            'td style="width:99%;white-space:n'
                                            'ormal;" align="left"><input type='
                                            '"text" name="field179945_0" id="cp'
                                            'bh" value="2asdsd33233" onChange='
                                            '"checkLength(\'field179945_0\',300'
                                            ', \'产品编号\', \'文本长度不能超过\', \''
                                            '1个中文字符等于3个长度\');"/></td></tr></table>'
                                        ),
                                        'mand': False,
                                        'selectnames': [],
                                        'selectvalues': [],
                                        'view': True,
                                    },
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'integer',
                                        'fieldFormName': 'field179946_0',
                                        'fieldHtmlType': '5',
                                        'fieldId': '179946',
                                        'fieldName': 'bz',
                                        'fieldOrder': 0,
                                        'fieldShowName': '币种',
                                        'fieldShowValue': '人民币',
                                        'fieldType': '1',
                                        'fieldValue': '1',
                                        'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><select name="field179946_0" id="bz"><option value="" ></option><option value="1" selected>人民币</option><option value="2" >港币</option><option value="3" >台币</option><option value="4" >美元</option><option value="5" >欧元</option></select></td></tr></table>',  # noqa
                                        'mand': False,
                                        'selectnames': ['人民币', '港币', '台币', '美元', '欧元'],
                                        'selectvalues': ['1', '2', '3', '4', '5'],
                                        'view': True,
                                    },
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'number(38,4)',
                                        'fieldFormName': 'field179947_0',
                                        'fieldHtmlType': '1',
                                        'fieldId': '179947',
                                        'fieldName': 'jg',
                                        'fieldOrder': 0,
                                        'fieldShowName': '价格',
                                        'fieldShowValue': '12.22',
                                        'fieldType': '3',
                                        'fieldValue': '12.22',
                                        'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><input type="text" onkeypress="ItemNum_KeyPress(\'field179947_0\')" onblur="checknumber1(this);" name="field179947_0" id="jg" value="12.22" /></td></tr></table>',  # noqa
                                        'mand': False,
                                        'selectnames': [],
                                        'selectvalues': [],
                                        'view': True,
                                    },
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'integer',
                                        'fieldFormName': 'field179948_0',
                                        'fieldHtmlType': '5',
                                        'fieldId': '179948',
                                        'fieldName': 'jgbs',
                                        'fieldOrder': 0,
                                        'fieldShowName': '价格标识',
                                        'fieldShowValue': '含税价',
                                        'fieldType': '1',
                                        'fieldValue': '1',
                                        'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><select name="field179948_0" id="jgbs"><option value="" ></option><option value="1" selected>含税价</option><option value="2" >去税价</option></select></td></tr></table>',  # noqa
                                        'mand': False,
                                        'selectnames': ['含税价', '去税价'],
                                        'selectvalues': ['1', '2'],
                                        'view': True,
                                    },
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'integer',
                                        'fieldFormName': 'field179949_0',
                                        'fieldHtmlType': '5',
                                        'fieldId': '179949',
                                        'fieldName': 'cplx',
                                        'fieldOrder': 0,
                                        'fieldShowName': '产品类型',
                                        'fieldShowValue': 'LCD',
                                        'fieldType': '1',
                                        'fieldValue': '1',
                                        'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><select name="field179949_0" id="cplx"><option value="" ></option><option value="0" >CIS</option><option value="1" selected>LCD</option><option value="2" >Digital</option><option value="3" >COM</option></select></td></tr></table>',  # noqa
                                        'mand': False,
                                        'selectnames': ['CIS', 'LCD', 'Digital', 'COM'],
                                        'selectvalues': ['0', '1', '2', '3'],
                                        'view': True,
                                    },
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'varchar2(300)',
                                        'fieldFormName': 'field179950_0',
                                        'fieldHtmlType': '1',
                                        'fieldId': '179950',
                                        'fieldName': 'cgqy',
                                        'fieldOrder': 0,
                                        'fieldShowName': '采购企业',
                                        'fieldShowValue': 'Haha',
                                        'fieldType': '1',
                                        'fieldValue': 'Haha',
                                        'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><input type="text" name="field179950_0" id="cgqy" value="Haha" onChange="checkLength(\'field179950_0\',300, \'采购企业\', \'文本长度不能超过\', \'1个中文字符等于3个长度\');"/></td></tr></table>',  # noqa
                                        'mand': False,
                                        'selectnames': [],
                                        'selectvalues': [],
                                        'view': True,
                                    },
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'varchar2(300)',
                                        'fieldFormName': 'field179951_0',
                                        'fieldHtmlType': '1',
                                        'fieldId': '179951',
                                        'fieldName': 'xsqy',
                                        'fieldOrder': 0,
                                        'fieldShowName': '销售企业',
                                        'fieldShowValue': 'Heihei',
                                        'fieldType': '1',
                                        'fieldValue': 'Heihei',
                                        'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><input type="text" name="field179951_0" id="xsqy" value="Heihei" onChange="checkLength(\'field179951_0\',300, \'销售企业\', \'文本长度不能超过\', \'1个中文字符等于3个长度\');"/></td></tr></table>',  # noqa
                                        'mand': False,
                                        'selectnames': [],
                                        'selectvalues': [],
                                        'view': True,
                                    },
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'char(10)',
                                        'fieldFormName': 'field179952_0',
                                        'fieldHtmlType': '3',
                                        'fieldId': '179952',
                                        'fieldName': 'sxrq',
                                        'fieldOrder': 0,
                                        'fieldShowName': '生效日期',
                                        'fieldShowValue': '2023-08-04',
                                        'fieldType': '2',
                                        'fieldValue': '2023-08-04',
                                        'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><input type="text" name="field179952_0" id="sxrq" value="2023-08-04" /></td></tr></table>',  # noqa
                                        'mand': False,
                                        'selectnames': [],
                                        'selectvalues': [],
                                        'view': True,
                                    },
                                    {
                                        'browserurl': '',
                                        'edit': True,
                                        'fieldDBType': 'char(10)',
                                        'fieldFormName': 'field179953_0',
                                        'fieldHtmlType': '3',
                                        'fieldId': '179953',
                                        'fieldName': 'zzrq',
                                        'fieldOrder': 0,
                                        'fieldShowName': '终止日期',
                                        'fieldShowValue': '2023-08-04',
                                        'fieldType': '2',
                                        'fieldValue': '2023-08-04',
                                        'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><input type="text" name="field179953_0" id="zzrq" value="2023-08-04" /></td></tr></table>',  # noqa
                                        'mand': False,
                                        'selectnames': [],
                                        'selectvalues': [],
                                        'view': True,
                                    },
                                ],
                            }
                        ],
                    }
                ],
                'workflowHtmlShow': [None, None],
                'workflowHtmlTemplete': [None, None],
                'workflowMainTableInfo': {
                    'requestRecords': [
                        {
                            'recordOrder': 0,
                            'workflowRequestTableFields': [
                                {
                                    'edit': True,
                                    'fieldDBType': '',
                                    'fieldFormName': 'requestname',
                                    'fieldHtmlType': '1',
                                    'fieldId': '-1',
                                    'fieldName': 'requestname',
                                    'fieldOrder': -1,
                                    'fieldShowName': '标题',
                                    'fieldShowValue': 'NBJ2-Leslie-202308040005',
                                    'fieldType': '',
                                    'fieldValue': 'NBJ2-Leslie-202308040005',
                                    'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><input type="text" name="requestname" id="requestname" value="NBJ2-Leslie-202308040005" /></td><td><span id="requestname_ismandspan" class="ismand">!</span><input type="hidden" id="ismandfield" name="ismandfield" value="requestname"/></td></tr></table>',  # noqa
                                    'mand': True,
                                    'view': True,
                                },
                                {
                                    'edit': True,
                                    'fieldDBType': '',
                                    'fieldFormName': 'requestlevel',
                                    'fieldHtmlType': '5',
                                    'fieldId': '-2',
                                    'fieldName': 'requestlevel',
                                    'fieldOrder': -2,
                                    'fieldShowName': '',
                                    'fieldShowValue': '正常',
                                    'fieldType': '',
                                    'fieldValue': '0',
                                    'filedHtmlShow': '<table style="width:100%;"><tr><td style="width:99%;white-space:normal;" align="left"><fieldset data-role="controlgroup"><input type="radio" name="requestlevel" id="requestlevel-0" value="0" checked /><label for="requestlevel-0">正常</label><input type="radio" name="requestlevel" id="requestlevel-1" value="1"  /><label for="requestlevel-1">重要</label><input type="radio" name="requestlevel" id="requestlevel-2" value="2"  /><label for="requestlevel-2">紧急</label></fieldset></td></tr></table>',  # noqa
                                    'mand': False,
                                    'selectnames': ['正常', '重要', '紧急'],
                                    'selectvalues': ['0', '1', '2'],
                                    'view': True,
                                },
                                {
                                    'edit': True,
                                    'fieldDBType': '',
                                    'fieldFormName': 'messageType',
                                    'fieldHtmlType': '5',
                                    'fieldId': '-3',
                                    'fieldName': 'messageType',
                                    'fieldOrder': -3,
                                    'fieldShowName': '短信提醒',
                                    'fieldShowValue': '不短信提醒',
                                    'fieldType': '',
                                    'fieldValue': '0',
                                    'filedHtmlShow': '',
                                    'mand': False,
                                    'selectnames': ['不短信提醒', '离线短信提醒', '在线短信提醒'],
                                    'selectvalues': ['0', '1', '2'],
                                    'view': False,
                                },
                                {
                                    'browserurl': '',
                                    'edit': False,
                                    'fieldDBType': 'char(10)',
                                    'fieldFormName': 'field179462',
                                    'fieldHtmlType': '3',
                                    'fieldId': '179462',
                                    'fieldName': 'cjriqi',
                                    'fieldOrder': 0,
                                    'fieldShowName': '申请日期',
                                    'fieldShowValue': '2023-08-04',
                                    'fieldType': '2',
                                    'fieldValue': '2023-08-04',
                                    'filedHtmlShow': '2023-08-04',
                                    'mand': False,
                                    'selectnames': [],
                                    'selectvalues': [],
                                    'view': True,
                                },
                                {
                                    'browserurl': '',
                                    'edit': False,
                                    'fieldDBType': 'varchar2(256)',
                                    'fieldFormName': 'field179463',
                                    'fieldHtmlType': '1',
                                    'fieldId': '179463',
                                    'fieldName': 'djbh',
                                    'fieldOrder': 2,
                                    'fieldShowName': '单据编号',
                                    'fieldShowValue': 'NBJ2-202308040005',
                                    'fieldType': '1',
                                    'fieldValue': 'NBJ2-202308040005',
                                    'filedHtmlShow': 'NBJ2-202308040005',
                                    'mand': False,
                                    'selectnames': [],
                                    'selectvalues': [],
                                    'view': True,
                                },
                                {
                                    'browserurl': '',
                                    'edit': False,
                                    'fieldDBType': 'varchar2(50)',
                                    'fieldFormName': 'field179954',
                                    'fieldHtmlType': '1',
                                    'fieldId': '179954',
                                    'fieldName': 'sqr',
                                    'fieldOrder': 4,
                                    'fieldShowName': '申请人-fake',
                                    'fieldShowValue': '',
                                    'fieldType': '1',
                                    'fieldValue': '',
                                    'filedHtmlShow': '',
                                    'mand': False,
                                    'selectnames': [],
                                    'selectvalues': [],
                                    'view': False,
                                },
                                {
                                    'browserurl': '',
                                    'edit': False,
                                    'fieldDBType': 'varchar2(50)',
                                    'fieldFormName': 'field179955',
                                    'fieldHtmlType': '1',
                                    'fieldId': '179955',
                                    'fieldName': 'sqrbm',
                                    'fieldOrder': 7,
                                    'fieldShowName': '申请人部门-fake',
                                    'fieldShowValue': '',
                                    'fieldType': '1',
                                    'fieldValue': '',
                                    'filedHtmlShow': '',
                                    'mand': False,
                                    'selectnames': [],
                                    'selectvalues': [],
                                    'view': False,
                                },
                                {
                                    'browserurl': '',
                                    'edit': False,
                                    'fieldDBType': 'integer',
                                    'fieldFormName': 'field179957',
                                    'fieldHtmlType': '3',
                                    'fieldId': '179957',
                                    'fieldName': 'sqrtrue',
                                    'fieldOrder': 9,
                                    'fieldShowName': '申请人',
                                    'fieldShowValue': '系统管理员 ',
                                    'fieldType': '1',
                                    'fieldValue': '1',
                                    'filedHtmlShow': '系统管理员 ',
                                    'mand': False,
                                    'selectnames': [],
                                    'selectvalues': [],
                                    'view': True,
                                },
                                {
                                    'browserurl': '',
                                    'edit': False,
                                    'fieldDBType': 'integer',
                                    'fieldFormName': 'field179958',
                                    'fieldHtmlType': '3',
                                    'fieldId': '179958',
                                    'fieldName': 'sqrbmtrue',
                                    'fieldOrder': 10,
                                    'fieldShowName': '申请人部门',
                                    'fieldShowValue': '',
                                    'fieldType': '4',
                                    'fieldValue': '',
                                    'filedHtmlShow': '',
                                    'mand': False,
                                    'selectnames': [],
                                    'selectvalues': [],
                                    'view': True,
                                },
                                {
                                    'browserurl': '',
                                    'edit': False,
                                    'fieldDBType': 'varchar2(100)',
                                    'fieldFormName': 'field179959',
                                    'fieldHtmlType': '1',
                                    'fieldId': '179959',
                                    'fieldName': 'wybh',
                                    'fieldOrder': 12,
                                    'fieldShowName': '唯一编号',
                                    'fieldShowValue': '3a441b47-119d-4168-b21a-df4c4bdc58dc',
                                    'fieldType': '1',
                                    'fieldValue': '3a441b47-119d-4168-b21a-df4c4bdc58dc',
                                    'filedHtmlShow': '3a441b47-119d-4168-b21a-df4c4bdc58dc',
                                    'mand': False,
                                    'selectnames': [],
                                    'selectvalues': [],
                                    'view': True,
                                },
                                {
                                    'browserurl': '',
                                    'edit': True,
                                    'fieldDBType': 'varchar2(4000)',
                                    'fieldFormName': 'field180555',
                                    'fieldHtmlType': '6',
                                    'fieldId': '180555',
                                    'fieldName': 'fjsc',
                                    'fieldOrder': 15,
                                    'fieldShowName': '附件上传',
                                    'fieldShowValue': "<span style='color:#ACA899'>[该字段暂不支持]</span>",
                                    'fieldType': '1',
                                    'fieldValue': '',
                                    'filedHtmlShow': "<span style='color:#ACA899'>[该字段暂不支持]</span>",
                                    'mand': False,
                                    'selectnames': [],
                                    'selectvalues': [],
                                    'view': True,
                                },
                            ],
                        }
                    ],
                    'tableDBName': 'formtable_main_266',
                },
                'workflowRequestLogs': [
                    {
                        'annexDocHtmls': '',
                        'id': '419352',
                        'nodeId': '61022',
                        'nodeName': '审批2',
                        'operateDate': '2023-08-04',
                        'operateTime': '16:23:28',
                        'operateType': '退回',
                        'operatorDept': '公共关系部',
                        'operatorId': '18781',
                        'operatorName': 'Leslie Chan',
                        'receivedPersons': '系统管理员',
                        'remark': '',
                        'signDocHtmls': '',
                        'signWorkFlowHtmls': '',
                    },
                    {
                        'annexDocHtmls': '',
                        'id': '419351',
                        'nodeId': '61021',
                        'nodeName': '创建',
                        'operateDate': '2023-08-04',
                        'operateTime': '16:23:04',
                        'operateType': '提交',
                        'operatorId': '1',
                        'operatorName': '系统管理员',
                        'receivedPersons': 'Leslie Chan',
                        'remark': '',
                        'signDocHtmls': '',
                        'signWorkFlowHtmls': '',
                    },
                ],
            },
            'errMsg': {},
        }
        return res

    def transmit(self, request_id, trans_type, user_id: str, remark: str = ""):
        """
        转发、意见征询、转办(对外)
        :param request_id:
        :param trans_type:
        :param user_id:
        :param remark:
        :return:
        """
        api_path = "/api/workflow/paService/forwardRequest"
        if trans_type == 3:
            if len(user_id.split(",")) > 1:
                raise APIException(detail="转办只能转给一个用户")
        post_data = {
            "forwardFlag": trans_type,  # 1:转发  2:意见征询 3:转办
            "forwardResourceIds": user_id,
            "otherParams": {},
            "remark": remark,
            "requestId": request_id,
        }
        resp = self._post_oa(api_path, post_data=post_data)
        return resp

    def recover(self, request_id):
        """
        强制收回
        :param request_id:
        :return:
        """
        api_path = "/api/workflow/paService/doForceDrawBack"
        post_data = {"requestId": request_id}
        resp = self._post_oa(api_path, post_data=post_data)
        _ = {"code": "SUCCESS", "errMsg": {}}  # noqa
        return resp
