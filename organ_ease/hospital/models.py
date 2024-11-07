from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.core.validators import RegexValidator, ValidationError
import re

class HospitalManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with an email and hashed password."""
        if not email:
            raise ValueError('The Email field must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # Hash the password
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser with an email and hashed password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(email, password, **extra_fields)

class HospitalRegister(AbstractBaseUser, PermissionsMixin):
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='customuser_groups',
        blank=True,
        help_text='The groups this user belongs to.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='customuser_permissions',
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )
    id = models.AutoField(primary_key=True)
    hospital_name = models.CharField(max_length=30)
    email = models.EmailField(unique=True,verbose_name='Email',max_length=255)
    area = models.CharField(max_length=50, blank=True)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    pincode = models.CharField(max_length=10, 
                               validators=[
                                   RegexValidator(r'^\d{6}$', message="Enter a valid pincode")
                                   ])
    mobile_number = models.CharField(max_length=10, 
                                     validators=[
                                         RegexValidator(r'^\d{10}$', message="Enter a valid mobile number")
                                         ])
    
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = HospitalManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['hospital_name', 'city', 'state', 'pincode', 'mobile_number']

    def __str__(self):
        return self.email

def validate_password(value):
    """Validate the password according to certain criteria."""
    if len(value) < 8:
        raise ValidationError('Password must be at least 8 characters long.')
    if not re.search(r'\d', value):
        raise ValidationError('Password must contain at least one digit.')
    if not re.search(r'[A-Za-z]', value):
        raise ValidationError('Password must contain at least one letter.')
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', value):
        raise ValidationError('Password must contain at least one special character.')

from django.db import models
from django.core.validators import RegexValidator

class Donor(models.Model):
    # Gender and Blood Type Choices
    GENDER_CHOICES = [
        ('Male', 'Male'),
        ('Female', 'Female'),
        ('Other', 'Other'),
    ]

    BLOOD_TYPE_CHOICES = [
        ('A+', 'A+'),
        ('A-', 'A-'),
        ('B+', 'B+'),
        ('B-', 'B-'),
        ('AB+', 'AB+'),
        ('AB-', 'AB-'),
        ('O+', 'O+'),
        ('O-', 'O-'),
    ]

    # Custom fields based on the data dictionary
    donor_id = models.AutoField(primary_key=True)  # Donor ID (Primary Key)
    name = models.CharField(max_length=25)  # Name of Donor
    email = models.EmailField(unique=True, verbose_name='Email', max_length=255)  # Email of Donor
    mobile_number = models.CharField(
        max_length=10, 
        validators=[RegexValidator(r'^\d{10}$', message="Enter a valid mobile number")]
    )  # Mobile Number of Donor
    date_of_birth = models.DateField()  # Date of Birth of Donor
    blood_type = models.CharField(max_length=3, choices=BLOOD_TYPE_CHOICES)  # Blood Type of Donor
    area = models.CharField(max_length=20)  # Area where the donor lives
    city = models.CharField(max_length=20)  # City where the donor lives
    state = models.CharField(max_length=20)  # State where the donor lives
    country = models.CharField(max_length=20)  # Country where the donor lives
    gender = models.CharField(max_length=6, choices=GENDER_CHOICES)  # Gender of Donor
    hospital = models.ForeignKey(
        'HospitalRegister', on_delete=models.CASCADE, related_name='donors'
    )  # Foreign Key to Hospital
    guardian_name = models.CharField(max_length=30)  # Guardian's Name
    guardian_number = models.CharField(
        max_length=10,
        validators=[RegexValidator(r'^\d{10}$', message="Enter a valid mobile number")]
    )  # Guardian's Mobile Number

    # User permissions and activity
    is_active = models.BooleanField(default=True)  # If the donor is active
    is_staff = models.BooleanField(default=False)  # If the donor has staff privileges

    def __str__(self):
        return f"{self.name} - {self.email}"

