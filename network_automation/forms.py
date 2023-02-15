from django import forms


class LoginForm(forms.Form):
    username = forms.CharField(widget=forms.TextInput(attrs={"placeholder": "Username", "class": "form-control",}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={"placeholder": "Password", "class": "form-control",}))


class ACIMenuForm(forms.Form):
    menu_option = forms.CharField(max_length=100)
    uploaded_file = forms.FileField()
    host_ip = forms.GenericIPAddressField(protocol="IPv4")
    aci_username = forms.CharField(max_length=100)
    aci_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"placeholder": "Password", "class": "form-control",})
    )


class F5MenuForm(forms.Form):
    menu_option = forms.CharField(max_length=100)
    uploaded_file = forms.FileField()
    f5_username = forms.CharField(max_length=100)
    f5_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"placeholder": "Password", "class": "form-control",})
    )


class IOSMenuForm(forms.Form):
    menu_option = forms.CharField(max_length=100)
    deployment_file = forms.FileField()
    inventory_file = forms.FileField()


class SDWANMenuForm(forms.Form):
    menu_option = forms.CharField(max_length=100)
    uploaded_file = forms.FileField()
    host_ip = forms.GenericIPAddressField(protocol="IPv4")
    vmanage_username = forms.CharField(max_length=100)
    vmanage_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"placeholder": "Password", "class": "form-control",})
    )