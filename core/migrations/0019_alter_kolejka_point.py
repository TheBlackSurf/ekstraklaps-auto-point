# Generated by Django 4.0.5 on 2022-06-14 17:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0018_kolejka_delete_point'),
    ]

    operations = [
        migrations.AlterField(
            model_name='kolejka',
            name='point',
            field=models.IntegerField(blank=True, null=True),
        ),
    ]