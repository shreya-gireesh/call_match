# Generated by Django 5.0.6 on 2024-08-09 06:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AdminApp', '0037_alter_customermodel_customer_password'),
    ]

    operations = [
        migrations.AddField(
            model_name='userpurchasemodel',
            name='purchase_type',
            field=models.CharField(choices=[('Chat', 'Chat'), ('Call', 'Call')], max_length=10, null=True),
        ),
    ]