import re
from django.db import IntegrityError
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.models import update_last_login
from .models import *
from django.contrib.auth.models import User
from django.core.validators import *
from rest_framework.validators import *


class RegistrationSerializer(serializers.ModelSerializer):
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = HospitalRegister
        fields = ['id', 'email', 'password', 'confirm_password', 'hospital_name', 'area', 'city', 'state', 'pincode', 'mobile_number', 'is_active', 'is_staff']
        extra_kwargs = {
            'password': {'write_only': True, 'validators': [validate_password]}  # Add the validator here
        }

    def validate(self, attrs):
        # Check if password and confirm_password match
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords do not match."})
        return attrs

    def create(self, validated_data):
        # Remove confirm_password from the validated data before creating the user
        validated_data.pop('confirm_password')
        user = HospitalRegister(
            hospital_name=validated_data['hospital_name'],
            email=validated_data['email'],
            area=validated_data.get('area', ''),
            city=validated_data['city'],
            state=validated_data['state'],
            pincode=validated_data['pincode'],
            mobile_number=validated_data['mobile_number'],
            is_active=validated_data.get('is_active', True),
            is_staff=validated_data.get('is_staff', False)
        )
        user.set_password(validated_data['password'])  # Set the hashed password
        user.save()
        return user
    
from rest_framework import serializers
from django.contrib.auth.models import User  # Import your user model

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True, write_only=True)

from rest_framework import serializers
from .models import HospitalRegister

class ForgotPasswordSerializer(serializers.Serializer):
    user_id = serializers.IntegerField()

class ResetPasswordSerializer(serializers.Serializer):
    token = serializers.CharField(required=True)
    new_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long.")
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one digit.")
        if not re.search(r'[A-Za-z]', value):
            raise serializers.ValidationError("Password must contain at least one letter.")
        if not re.search(r'[!@#$%^&*(),.?\":{}|<>]', value):
            raise serializers.ValidationError("Password must contain at least one special character.")
        return value


from rest_framework import serializers
from .models import Donor

class DonorSerializer(serializers.ModelSerializer):
    class Meta:
        model = Donor
        fields = [
            'donor_id',
            'name',
            'email',
            'mobile_number',
            'date_of_birth',
            'blood_type',
            'area',
            'city',
            'state',
            'country',
            'gender',
            'hospital',
            'guardian_name',
            'guardian_number',
            'is_active',
            'is_staff'
        ]

    def validate_email(self, value):
        """Check if the email is unique."""
        if Donor.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

