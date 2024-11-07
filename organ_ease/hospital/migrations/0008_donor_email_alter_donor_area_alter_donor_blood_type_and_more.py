# Generated by Django 5.0.7 on 2024-11-03 10:49

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hospital', '0007_donor'),
    ]

    operations = [
        migrations.AddField(
            model_name='donor',
            name='email',
            field=models.EmailField(blank=True, max_length=255, null=True, unique=True, verbose_name='Email'),
        ),
        migrations.AlterField(
            model_name='donor',
            name='area',
            field=models.CharField(blank=True, max_length=20),
        ),
        migrations.AlterField(
            model_name='donor',
            name='blood_type',
            field=models.CharField(choices=[('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'), ('AB+', 'AB+'), ('AB-', 'AB-'), ('O+', 'O+'), ('O-', 'O-')], max_length=15),
        ),
        migrations.AlterField(
            model_name='donor',
            name='guardian_name',
            field=models.CharField(blank=True, max_length=30),
        ),
        migrations.AlterField(
            model_name='donor',
            name='guardian_number',
            field=models.CharField(blank=True, max_length=10, validators=[django.core.validators.RegexValidator('^\\d{10}$', message='Enter a valid guardian number')]),
        ),
        migrations.AlterField(
            model_name='donor',
            name='mobile_number',
            field=models.CharField(max_length=10, validators=[django.core.validators.RegexValidator('^\\d{10}$', message='Enter a valid mobile number')]),
        ),
        migrations.AlterField(
            model_name='donor',
            name='pin_code',
            field=models.CharField(max_length=6, validators=[django.core.validators.RegexValidator('^\\d{6}$', message='Enter a valid pin code')]),
        ),
    ]