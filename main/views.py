from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from .forms import *

        # user = request.user
        # user.last_view = 'encryption'
        # user.save()
        # user_action = UserAction(user=request.user, action='encryption')
        # user_action.save()

import base64
from Crypto.Cipher import AES
from django.http import HttpResponse
import io

@login_required
def encryption(request):
    key = request.POST.get('key', '')
    user = request.user
    user.last_view = 'encryption'
    user.save()
    user_action = UserAction(user=request.user, action='encryption')
    user_action.save()
    if 'submit_text' in request.POST:
        text = request.POST.get('text', '')
        encrypted_text = encrypt_text(text, key)
        print(encrypted_text)
        
        return render(request, 'encryption.html', {'key': key, 'encrypted_text': encrypted_text})
    elif 'submit_file' in request.POST:
        file = request.FILES['file']
        encrypted_file = encrypt_file(file, key)
        response = HttpResponse(encrypted_file, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="encrypted{file.name}"'
        return response
    else:
        return render(request, 'encryption.html', {'key': key})
    
def encrypt_text(text, key):
    key_bytes = base64.b64decode(key)
    cipher = AES.new(key_bytes, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(text.encode())
    return base64.b64encode(nonce + ciphertext + tag).decode()

def encrypt_file(file, key):
    key_bytes = base64.b64decode(key)
    cipher = AES.new(key_bytes, AES.MODE_EAX)
    nonce = cipher.nonce
    encrypted_data = b''
    for chunk in file.chunks():
        encrypted_chunk, _ = cipher.encrypt_and_digest(chunk)
        encrypted_data += encrypted_chunk
    output_file = io.BytesIO()
    # output_file.write(b'Your key is: ')
    # output_file.write(key.encode())
    # output_file.write(b'\n\n')
    output_file.write(base64.b64encode(nonce + encrypted_data))
    return output_file.getvalue()

@login_required
def decryption(request):
    key = request.POST.get('key', '')
    user = request.user
    user.last_view = 'decryption'
    user.save()
    user_action = UserAction(user=request.user, action='decryption')
    user_action.save()
    if 'submit_text' in request.POST:
        ciphertext = request.POST.get('text', '')
        decrypted_text = decrypt_text(ciphertext, key)
        return render(request, 'decryption.html', {'key': key, 'decrypted_text': decrypted_text})
    elif 'submit_file' in request.POST:
        file = request.FILES['file']
        decrypted_file = decrypt_file(file, key)
        response = HttpResponse(decrypted_file, content_type='application/octet-stream')
        response['Content-Disposition'] = f'attachment; filename="decrypted{file.name}"'
        return response
    else:
        return render(request, 'decryption.html', {'key': key})


def decrypt_text(ciphertext, key):
    key_bytes = base64.b64decode(key)
    ciphertext_bytes = base64.b64decode(ciphertext)
    nonce = ciphertext_bytes[:16]
    tag = ciphertext_bytes[-16:]
    cipher = AES.new(key_bytes, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext_bytes[16:-16], tag)
    return plaintext.decode()


def decrypt_file(file, key):
    data = base64.b64decode(file.read())
    nonce = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(base64.b64decode(key.encode()), AES.MODE_EAX, nonce=nonce)
    decrypted_data = b''
    for i in range(0, len(ciphertext), AES.block_size):
        chunk = ciphertext[i:i+AES.block_size]
        decrypted_chunk = cipher.decrypt(chunk)
        decrypted_data += decrypted_chunk
    return decrypted_data


import re

@login_required
def masking(request):
    if request.method == 'POST':
        text = request.POST['text']
        # add masking logic here
        masked_text = text
        
        # mask phone number
        masked_text = re.sub(r'(\+?7|8)[\s-]?\(?(701|702|705|707|708|747|750|751|760|761|762|763|771|775|777|778)\)?[\s.-]?(\d{3})[\s.-]?(\d{2})[\s.-]?(\d{2})', '***', masked_text)


        # mask email
        masked_text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '***', masked_text)
        masked_text = re.sub(r'\b[А-Яа-я0-9._%+-]+@[А-Яа-я0-9.-]+\.[А-Я|а-я]{2,}\b', '***', masked_text)

        # mask name and surname in English
        masked_text = re.sub(r'\b[A-Z][a-z]*\b', '***', masked_text)

        # mask name and surname in Russian
        masked_text = re.sub(r'\b[А-ЯЁ][а-яё]*\b', '***', masked_text)
        
        user = request.user
        user.last_view = 'masking'
        user.save()
        user_action = UserAction(user=request.user, action='masking')
        user_action.save()
        return render(request, 'masking.html', {'masked_text': masked_text})
    
    return render(request, 'masking.html')
        
        
# User = get_user_model()
def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            login(request, user)
            return redirect('encryption')
    else:
        form = CustomUserCreationForm()
    return render(request, 'register.html', {'form': form})

from django.contrib.auth.forms import AuthenticationForm

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            return redirect('encryption')
    else:
        form = AuthenticationForm()
    return render(request, 'login.html', {'form': form})


import logging
from .utils import get_client_ip

logger = logging.getLogger(__name__)



from django.utils import timezone
from datetime import timedelta
from main.models import UserAction

@login_required
def all_entries(request):
    ip_address = get_client_ip(request)
    users = CustomUser.objects.filter(last_login__isnull=False).order_by('-last_login')
    user_actions_dict = {}
    for user in users:
        if user.last_view == 'encryption':
            user.last_view = 'Шифрлау'
        elif user.last_view == 'decryption':
            user.last_view = 'Дешифрлау'
        elif user.last_view == 'masking':
            user.last_view = 'Құпия ақпаратты жасыру'
        else:
            user.last_view = 'Белгісіз'
        user_actions = UserAction.objects.filter(user=user).order_by('-timestamp')[:3]
        user_actions_dict[user.id] = user_actions
    return render(request, 'all_entries.html', {'users': users, 'ip_address': ip_address, 'user_actions_dict': user_actions_dict})





@login_required
def logout_view(request):
    logout(request)
    return redirect('login')



from django.contrib.auth.views import LoginView

class CustomLoginView(LoginView):
    def form_valid(self, form):
        response = super().form_valid(form)
        self.request.user.last_login = timezone.now()
        self.request.user.save()
        return response