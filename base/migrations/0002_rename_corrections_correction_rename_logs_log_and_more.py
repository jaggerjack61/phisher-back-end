# Generated by Django 4.2.5 on 2023-10-09 21:00

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Corrections',
            new_name='Correction',
        ),
        migrations.RenameModel(
            old_name='Logs',
            new_name='Log',
        ),
        migrations.RenameModel(
            old_name='Sites',
            new_name='Site',
        ),
    ]
