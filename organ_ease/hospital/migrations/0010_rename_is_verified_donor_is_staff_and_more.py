# Generated by Django 5.0.7 on 2024-11-04 10:30

import django.core.validators
import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hospital', '0009_donor_is_active_donor_is_verified_alter_donor_email'),
    ]

    operations = [
        migrations.RenameField(
            model_name='donor',
            old_name='is_verified',
            new_name='is_staff',
        ),
        migrations.RemoveField(
            model_name='donor',
            name='pin_code',
        ),
        migrations.AlterField(
            model_name='donor',
            name='area',
            field=models.CharField(max_length=20),
        ),
        migrations.AlterField(
            model_name='donor',
            name='blood_type',
            field=models.CharField(choices=[('A+', 'A+'), ('A-', 'A-'), ('B+', 'B+'), ('B-', 'B-'), ('AB+', 'AB+'), ('AB-', 'AB-'), ('O+', 'O+'), ('O-', 'O-')], max_length=3),
        ),
        migrations.AlterField(
            model_name='donor',
            name='gender',
            field=models.CharField(choices=[('Male', 'Male'), ('Female', 'Female'), ('Other', 'Other')], max_length=6),
        ),
        migrations.AlterField(
            model_name='donor',
            name='guardian_name',
            field=models.CharField(max_length=30),
        ),
        migrations.AlterField(
            model_name='donor',
            name='guardian_number',
            field=models.CharField(max_length=10, validators=[django.core.validators.RegexValidator('^\\d{10}$', message='Enter a valid mobile number')]),
        ),
        migrations.AlterField(
            model_name='donor',
            name='hospital',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='donors', to=settings.AUTH_USER_MODEL),
        ),
    ]
