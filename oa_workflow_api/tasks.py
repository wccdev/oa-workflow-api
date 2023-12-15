from .utils import FetchOaDbHandler, get_sync_oa_user_model


def sync_oa_users():
    """
    同步Oa用户到项目
    """
    oa_user_model = get_sync_oa_user_model()  # noqa
    FetchOaDbHandler.get_instance()
