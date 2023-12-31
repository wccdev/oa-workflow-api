# Generated by Django 4.2.2 on 2023-12-15 15:13

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='OaUserInfo',
            fields=[
                ('user_id', models.IntegerField(primary_key=True, serialize=False, unique=True, verbose_name='OA用户数据ID')),
                ('dept_id', models.IntegerField(null=True, verbose_name='OA用户部门ID')),
                ('staff_code', models.OneToOneField(db_column='staff_code', db_constraint=False, on_delete=django.db.models.deletion.DO_NOTHING, to=settings.AUTH_USER_MODEL, to_field='username', verbose_name='OA用户工号')),
            ],
            options={
                'verbose_name': 'OA用户信息',
                'verbose_name_plural': 'OA用户信息',
                'abstract': False,
                'swappable': 'SYNC_OA_USER_MODEL',
            },
        ),
    ]
