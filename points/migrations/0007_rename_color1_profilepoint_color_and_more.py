# Generated by Django 4.0.5 on 2022-08-06 09:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('points', '0006_alter_profilepoint_dodatkowepunkty_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='profilepoint',
            old_name='color1',
            new_name='color',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color10',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color11',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color12',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color13',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color14',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color15',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color16',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color17',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color18',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color19',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color2',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color20',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color21',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color22',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color23',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color24',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color25',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color26',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color27',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color28',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color29',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color3',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color30',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color31',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color32',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color33',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color34',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color4',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color5',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color6',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color7',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color8',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color9',
        ),
        migrations.RemoveField(
            model_name='profilepoint',
            name='color_dodatkowe_punkty',
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='dodatkowepunkty',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka1',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka10',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka11',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka12',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka13',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka14',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka15',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka16',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka17',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka18',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka19',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka2',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka20',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka21',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka22',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka23',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka24',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka25',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka26',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka27',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka28',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka29',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka3',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka30',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka31',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka32',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka33',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka34',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka4',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka5',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka6',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka7',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka8',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
        migrations.AlterField(
            model_name='profilepoint',
            name='kolejka9',
            field=models.IntegerField(blank=True, default=0, null=True),
        ),
    ]
