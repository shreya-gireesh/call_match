# Generated by Django 5.0.6 on 2024-07-28 13:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('AdminApp', '0028_alter_paymentmodel_amount'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customermodel',
            name='adhaar_no',
            field=models.CharField(default='unknown', max_length=50),
        ),
        migrations.AlterField(
            model_name='customermodel',
            name='customer_email',
            field=models.EmailField(default='unknown', max_length=254),
        ),
        migrations.AlterField(
            model_name='customermodel',
            name='customer_first_name',
            field=models.CharField(default='unknown', max_length=100),
        ),
        migrations.AlterField(
            model_name='customermodel',
            name='customer_last_name',
            field=models.CharField(default='unknown', max_length=100),
        ),
    ]
