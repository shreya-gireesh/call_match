# Generated by Django 5.0.6 on 2024-08-02 06:25

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('AdminApp', '0033_customermodel_c'),
    ]

    operations = [
        migrations.RenameField(
            model_name='customermodel',
            old_name='c',
            new_name='terms_conditions',
        ),
    ]
