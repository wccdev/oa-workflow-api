from django.contrib.auth import get_user_model
from django.db import models

UserModel = get_user_model()

# if api_settings.USE_SYNC_OA_USER_INFO_MODEL:
# try:
#     UserModel._meta.get_field(UserModel.USERNAME_FIELD)
# except FieldDoesNotExist:
#     raise FieldDoesNotExist(
#         f"("
#         f"\n    项目配置'{SETTING_PREFIX}'下 USE_SYNC_OA_USER_INFO_MODEL={api_settings.USE_SYNC_OA_USER_INFO_MODEL} "
#         f"设置为开启用于同步OA用户信息的Model,"
#         f"\n    但是当前项目用户Model '{UserModel}' 中不存在 'USERNAME_FIELD' {UserModel.USERNAME_FIELD} "
#         f"\n)"
#     )


class AbstractOaUserInfo(models.Model):
    DJANGO_USER_STAFF_CODE__FIELD = UserModel.USERNAME_FIELD

    user_id = models.IntegerField(unique=True, primary_key=True, verbose_name="OA用户数据ID")
    staff_code = models.OneToOneField(
        UserModel,
        on_delete=models.DO_NOTHING,
        to_field=DJANGO_USER_STAFF_CODE__FIELD,
        related_name="oa_user",
        db_column="staff_code",
        db_constraint=False,
        verbose_name="OA用户工号",
    )
    dept_id = models.IntegerField(null=True, verbose_name="OA用户部门ID")

    class Meta:
        abstract = True
        verbose_name = verbose_name_plural = "OA用户信息"
