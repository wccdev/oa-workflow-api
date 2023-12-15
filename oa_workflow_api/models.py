from django.contrib.auth import get_user_model
from django.core.exceptions import FieldDoesNotExist
from django.db import models

from .settings import SETTING_PREFIX, api_settings

if api_settings.USE_OA_USER_INFO_MODEL:
    UserModel = get_user_model()

    try:
        UserModel._meta.get_field(api_settings.STAFF_CODE_FIELD_NAME)
    except FieldDoesNotExist:
        raise FieldDoesNotExist(
            f"项目用户Model '{UserModel}' 中不存在"
            f"项目 setting 中 {SETTING_PREFIX}配置指定的’STAFF_CODE_FIELD_NAME‘: '{api_settings.STAFF_CODE_FIELD_NAME}'"
            f"请重新指定字段名或者在Model上添加相应字段!"
        )

    class OaUserInfo(models.Model):
        user_id = models.IntegerField(unique=True, primary_key=True, verbose_name="OA用户数据ID")
        staff_code = models.OneToOneField(
            UserModel,
            on_delete=models.DO_NOTHING,
            to_field=api_settings.STAFF_CODE_FIELD_NAME,
            related_name="oa_user_info",
            verbose_name="OA用户工号",
        )
        dept_id = models.IntegerField(null=True, verbose_name="OA用户部门ID")

        class Meta:
            verbose_name = verbose_name_plural = "OA用户信息"
            db_table = "oa_user_info"
