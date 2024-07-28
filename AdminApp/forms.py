from django import forms
from .models import CustomerModel, AdminModel, CallPackageModel, ChatPackageModel


class CustomerForm(forms.ModelForm):
    class Meta:
        model = CustomerModel
        fields = ['customer_first_name', 'customer_last_name', 'customer_email', 'customer_contact']

        labels = {
            'customer_first_name': 'First Name',
            'customer_last_name': 'Last Name',
            'customer_email': 'Email',
            'customer_contact': 'Phone Number',
        }

        widgets = {
            'customer_first_name': forms.TextInput(attrs={'class': 'form-control form-control-user', 'placeholder': 'First Name'}),
            'customer_last_name': forms.TextInput(attrs={'class': 'form-control form-control-user', 'placeholder': 'Last Name'}),
            'customer_email': forms.EmailInput(attrs={'class': 'form-control form-control-user', 'placeholder': 'Email'}),
            'customer_contact': forms.TextInput(attrs={'class': 'form-control form-control-user', 'placeholder': 'Phone Number'}),

        }


class AdminForm(forms.ModelForm):
    class Meta:
        model = AdminModel
        fields = ['admin_first_name', 'admin_last_name', 'admin_mail', 'admin_password']
        widgets = {
            'admin_first_name': forms.TextInput(
                attrs={'class': 'form-control form-control-user', 'placeholder': 'First Name'}),
            'admin_last_name': forms.TextInput(attrs={'class': 'form-control form-control-user', 'placeholder': 'Last Name'}),
            'admin_mail': forms.EmailInput(attrs={'class': 'form-control form-control-user', 'placeholder': 'Email Address'}),
            'admin_password': forms.PasswordInput(attrs={'class': 'form-control form-control-user', 'placeholder': 'Password'}),
        }

    repeat_password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control form-control-user', 'placeholder': 'Repeat Password'}))

    def clean(self):
        cleaned_data = super().clean()
        password = self.cleaned_data.get("admin_password")
        repeat_password = self.cleaned_data.get("repeat_password")

        if password != repeat_password:
            raise forms.ValidationError("Passwords do not match")

        return cleaned_data


class AdminLoginForm(forms.ModelForm):
    class Meta:
        model = AdminModel
        fields = ['admin_mail', 'admin_password']
        widgets = {
            'admin_mail': forms.EmailInput(
                attrs={'class': 'form-control form-control-user', 'placeholder': 'Email Address'}),
            'admin_password': forms.PasswordInput(
                attrs={'class': 'form-control form-control-user', 'placeholder': 'Password'}),
        }


class CallPackageForm(forms.ModelForm):
    class Meta:
        model = CallPackageModel
        fields = ['package_price', 'total_coins']
        widgets = {
            'package_price': forms.NumberInput(
                attrs={'class': 'form-control form-control-user', 'placeholder': 'Enter price'}),
            'total_coins': forms.NumberInput(
                attrs={'class': 'form-control form-control-user', 'placeholder': 'Enter coins'}),
        }


class ChatPackageForm(forms.ModelForm):
    class Meta:
        model = ChatPackageModel
        fields = ['package_price', 'message_count']
        widgets = {
            'package_price': forms.NumberInput(
                attrs={'class': 'form-control form-control-user', 'placeholder': 'Enter price'}),
            'message_count': forms.NumberInput(
                attrs={'class': 'form-control form-control-user', 'placeholder': 'Messages'}),
        }