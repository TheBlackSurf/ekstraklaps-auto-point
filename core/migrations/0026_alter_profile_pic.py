# Generated by Django 4.0.5 on 2022-06-23 18:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0025_profile_name_profile_pic_profile_surnname'),
    ]

    operations = [
        migrations.AlterField(
            model_name='profile',
            name='pic',
            field=models.ImageField(blank=True, default='profile-pic/profile.png', null=True, upload_to='profile-pic'),
        ),
    ]