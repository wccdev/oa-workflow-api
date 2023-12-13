import oracledb
from django.conf import settings

try:
    oracledb.init_oracle_client()
except Exception:
    pass


def get_oa_oracle_connection():
    """
    OA 数据库连接
    """
    return oracledb.connect(
        user=settings.OA_DB_USER,
        password=settings.OA_DB_PASSWORD,
        host=settings.OA_DB_HOST,
        port=settings.OA_DB_PORT,
        service_name=settings.OA_DB_SERVER_NAME,
    )
