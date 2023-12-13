# oa-workflow-api


[![pypi](https://img.shields.io/pypi/v/oa-workflow-api.svg)](https://pypi.org/project/oa-workflow-api/)
[![python](https://img.shields.io/pypi/pyversions/oa-workflow-api.svg)](https://pypi.org/project/oa-workflow-api/)
[![Build Status](https://github.com/wccdev/oa-workflow-api/actions/workflows/dev.yml/badge.svg)](https://github.com/wccdev/oa-workflow-api/actions/workflows/dev.yml)
[![codecov](https://codecov.io/gh/wccdev/oa-workflow-api/branch/main/graphs/badge.svg)](https://codecov.io/github/wccdev/oa-workflow-api)



Skeleton project created by Cookiecutter PyPackage


* Documentation: <https://wccdev.github.io/oa-workflow-api>
* GitHub: <https://github.com/wccdev/oa-workflow-api>
* PyPI: <https://pypi.org/project/oa-workflow-api/>
* Free software: MIT


## Installation
- 使用 pip:
```bash
pip install wccoaworkflowapi

```
- 使用 poetry:
```bash
poetry add wccoaworkflowapi
```

## Usage
- 在 django setting中注册本应用 `'oa_workflow_api'`, 添加相关的配置
```python
INSTALLED_APPS = [
    "django.contrib.admin",
    ...,
    "oa_workflow_api",
]

# 由oa提供
OA_WORKFLOW_API = {
    # oa接口应用id
    "APP_ID": "xxxx",
    # oa接口应用secret
    "APP_RAW_SECRET": "xxxx-xxx-xxxx",
    # oa接口应用spk
    "APP_SPK": "xxxxxxxxxx",
    # oa接口服务地址(域名)
    "OA_HOST": "https://oa.demo.com",
    # Requests HTTP Library
    "REQUESTS_LIBRARY": "requests",
}
```

### 1.全局使用
- 在 django setting中注册中间件 `'oa_workflow_api.middleware.OaWFRequestMiddleware'`:
```python
MIDDLEWARE = [
    ...,
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    ...,
    "oa_workflow_api.middleware.OaWFRequestMiddleware",
]
```


### 2.局部使用
- 在需要使用的视图上继承
```python
from oa_workflow_api.mixin import OaWFApiViewMixin
from rest_framework.views import APIView


class YourViewSet(OaWFApiViewMixin, APIView):
    ...
```

#### 注意!!!
- 上述两种使用方法需要项目的`AUTH_USER_MODEL`提供属性`oa_user_id`

- `oa_user_id`为当前登入用户request.user在oa系统中对应的user_id
```python
from django.db.models import Model
class User(Model):
    ...

    class Meta:
        ...

    @property
    def oa_user_id(self):
        # TODO
        oa_user_id = "1"
        return oa_user_id
```

- 完成上述步骤，即可在视图中使用
```python
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import action


class YourViewSet(APIView):
    @action(detail=False)
    def test(self, request, *args, **kwargs):
        workflow = request.oa_wf_api
        # 待办流程
        workflow.get_todo_list(page=1, page_size=10)
        # 已办流程
        workflow.get_handled_list(page=1, page_size=10)
        # 可创建流程
        workflow.get_create_list()
        # ...
        return Response()
```

### 3.使用类
```python
from oa_workflow_api.utils import OaWorkFlow

workflow = OaWorkFlow()
# 调用前必须使用register_user方法
# 注册需要调用流程接口的oa用户id
oa_user_id = "TODO"  # TODO
workflow.register_user(oa_user_id)

# 待办流程
workflow.get_todo_list(page=1, page_size=10)
# 已办流程
workflow.get_handled_list(page=1, page_size=10)
# 可创建流程
workflow.get_create_list()
# ...
```

### 4.使用现成接口 (TODO, 开发中)
```python
from django.urls import include, path

urlpatterns = [
    ...,
    path("api/", include("oa_workflow_api.urls"))
]
```
