from django.apps import AppConfig

from .settings import DEFAULT_SYNC_OA_USER_MODEL


class OaWorkflowApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "oa_workflow_api"

    def ready(self):
        from django.conf import settings

        if not hasattr(settings, "SYNC_OA_USER_MODEL"):
            settings.SYNC_OA_USER_MODEL = DEFAULT_SYNC_OA_USER_MODEL
