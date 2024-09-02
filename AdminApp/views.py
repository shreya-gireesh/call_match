import base64
import json
import uuid

import requests
import re
import csv
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import JsonResponse, HttpResponseNotAllowed, HttpResponse, HttpResponseRedirect
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_POST, require_GET
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q, Sum
from CallMatch import settings
from utilis.paytm import PaytmChecksum
from .utils import generate_agora_token
from django.utils import timezone
from datetime import datetime
from .forms import CustomerForm, AdminForm, CallPackageForm, ChatPackageForm
from .serializer import *
from .models import *
import logging
from utilis.paytm.PaytmChecksum import verifySignature, generateSignature

logger = logging.getLogger(__name__)

MESSAGE_COST = 0.25  # Cost per message to agent


# Create your views here.
@require_GET
def get_payment_data(request):
    # Fetching payments data
    payments = PaymentModel.objects.all()

    # Aggregating data by month
    data = {}
    for payment in payments:
        month = payment.created_at.strftime("%b")  # Get the month abbreviation (e.g., 'Jan')
        if month not in data:
            data[month] = 0
        data[month] += float(payment.amount)

    # Making sure all months are present in the data, even if they have 0 earnings
    all_months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    data = {month: data.get(month, 0) for month in all_months}

    # Sorting data by month
    sorted_data = {month: data[month] for month in all_months}

    return JsonResponse(sorted_data)


def download_report(request):
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    if from_date and to_date:
        from_date = datetime.strptime(from_date, '%Y-%m-%d')
        to_date = datetime.strptime(to_date, '%Y-%m-%d')

        customers = CustomerModel.objects.all()
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="report.csv"'

        writer = csv.writer(response)
        writer.writerow(
            ['Type', 'Customer ID', 'Name', 'Email', 'Contact', 'Status', 'Languages', 'Adhaar No', 'Details'])

        for customer in customers:
            if customer.is_agent:
                withdrawals = WithdrawalHistoryModel.objects.filter(agent=customer, withdrawal_date__range=[from_date,
                                                                                                            to_date]).order_by(
                    '-withdrawal_date')
                transactions = AgentTransactionModel.objects.filter(agent=customer, transaction_date__range=[from_date,
                                                                                                             to_date]).order_by(
                    '-transaction_date')
                details = f"Withdrawals: {' | '.join([f'{w.withdrawal_date} - {w.withdrawal_amount}' for w in withdrawals])}; Transactions: {' | '.join([f'{t.transaction_date} - {t.transaction_amount} ({t.transaction_type})' for t in transactions])}"
                writer.writerow(
                    ['Agent', customer.customer_id, f"{customer.customer_first_name} {customer.customer_last_name}",
                     customer.customer_email, customer.customer_contact, customer.status, customer.languages,
                     customer.adhaar_no, details])
            else:
                purchases = UserPurchaseModel.objects.filter(user=customer,
                                                             purchase_date__range=[from_date, to_date]).order_by(
                    '-purchase_date')
                payments = PaymentModel.objects.filter(user=customer, created_at__range=[from_date, to_date]).order_by(
                    '-created_at')
                details = f"Purchases: {' | '.join([f'{p.purchase_date} - {p.purchase_amount}' for p in purchases])}; Payments: {' | '.join([f'{p.created_at} - {p.amount}' for p in payments])}"
                writer.writerow(
                    ['User', customer.customer_id, f"{customer.customer_first_name} {customer.customer_last_name}",
                     customer.customer_email, customer.customer_contact, customer.status, customer.languages,
                     customer.adhaar_no, details])

        return response

    return JsonResponse({'error': 'Invalid date range'}, status=400)


def agent_report(request):
    agents = CustomerModel.objects.filter(status='Agent User')
    report_data = {}
    if request.method == 'POST':
        agent_id = request.POST.get('agent_id')
        from_date = request.POST.get('from_date')
        to_date = request.POST.get('to_date')

        from_date = parse_date(from_date) if from_date else None
        to_date = parse_date(to_date) if to_date else None

        if not agent_id or not from_date or not to_date:
            return JsonResponse({'error': 'Agent, from date, and to date are required'}, status=400)

        agent = get_object_or_404(CustomerModel, customer_id=agent_id)
        wallet = WalletModel.objects.get(user__customer_id=agent_id)
        withdrawals = WithdrawalHistoryModel.objects.filter(agent=agent, withdrawal_date__range=[from_date, to_date])
        transactions = AgentTransactionModel.objects.filter(agent=agent, transaction_date__range=[from_date, to_date])
        wallet_data = {
            'call_amount': wallet.call_amount if wallet else 0,
            'chat_amount': wallet.chat_amount if wallet else 0,
            'total_messages_received': wallet.total_messages_received if wallet else 0,
            'total_minutes': wallet.total_minutes if wallet else 0,
            'total_amount': wallet.total_amount if wallet else 0,
        }
        withdrawal_data = [
            {
                'withdrawal_amount': w.withdrawal_amount,
                'withdrawal_date': w.withdrawal_date.strftime('%d %B %Y %I:%M %p')
            }
            for w in withdrawals
        ]
        transactions_data = [
            {
                "receiver": f"{t.receiver.customer_first_name} {t.receiver.customer_last_name}",
                "amount": t.transaction_amount,
                "date": t.transaction_date.strftime('%d %B %Y %I:%M %p'),
                "type": t.transaction_type
            }
            for t in transactions
        ]
        report_data = {
            'agent_name': f"{agent.customer_first_name} {agent.customer_last_name}",
            'wallet': wallet_data,
            'transactions': transactions_data,
            'withdrawals': withdrawal_data,
        }
        return JsonResponse(report_data, status=200)
    return render(request, 'agent_report.html', {'agents': agents})


def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            admin = AdminModel.objects.get(admin_mail=email, admin_password=password)
            admin_name = f"{admin.admin_first_name} {admin.admin_last_name}"
            request.session['user'] = admin_name
            request.session.set_expiry(21600)

            expiry = request.session.get_expiry_age()

            return redirect('/')
        except AdminModel.DoesNotExist:
            return render(request, 'login.html', {'error': "User not found"})
    return render(request, 'login.html')


def reg(request):
    if request.method == 'POST':
        form = AdminForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('login')  # Redirect to login page after successful registration
    else:
        form = AdminForm()
    return render(request, 'register.html', {'form': form})


def home(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')
    else:
        normal_users_count = CustomerModel.objects.filter(status='Normal User').count
        agent_user_count = CustomerModel.objects.filter(status='Agent User').count
        all_agents = CustomerModel.objects.filter(status='Agent User')
        payments = PaymentModel.objects.all().aggregate(Sum('amount'))
        amount = payments['amount__sum']
        # Ensure each agent's rating is included in the context
        agents_with_ratings = []
        for agent in all_agents:
            agent_rating = agent.rating  # This uses the rating property defined in the model
            agents_with_ratings.append({
                'customer_first_name': agent.customer_first_name,
                'customer_last_name': agent.customer_last_name,
                'customer_id': agent.customer_id,
                'is_online': agent.is_online,
                'rating': agent_rating
            })

        # Total Revenue from Users
        total_revenue = UserPurchaseModel.objects.aggregate(Sum('purchase_amount'))['purchase_amount__sum']

        # Total Payments to Agents (For Chats and Calls)
        total_agent_payments = AgentTransactionModel.objects.aggregate(Sum('transaction_amount'))[
            'transaction_amount__sum']

        # Total Withdrawals by Agents
        total_withdrawals = WithdrawalHistoryModel.objects.aggregate(Sum('withdrawal_amount'))['withdrawal_amount__sum']

        # Calculating Profit
        company_profit = total_revenue - (total_agent_payments + total_withdrawals)
        if total_revenue:
            profit = round((company_profit / total_revenue) * 100, 2)
        else:
            profit = 0.00
    return render(request, 'index.html', {'normaluser': normal_users_count, 'agentuser': agent_user_count,
                                          'all_agents': agents_with_ratings, 'payments': amount, 'username': username, 'profit': profit})


@require_POST
def toggle_online_status(request, customer_id):
    try:
        customer = CustomerModel.objects.get(pk=customer_id)
        customer.is_online = False
        customer.save()
        return JsonResponse({'success': True})
    except CustomerModel.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Customer not found'})


def registered_users(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')
    else:
        users = CustomerModel.objects.all()
        if request.method == 'POST':
            userid = request.POST.get('user_id')
            new_status = request.POST.get('status')
            user = CustomerModel.objects.get(customer_id=userid)
            user.status = new_status
            user.save()
            wallet = WalletModel.objects.get(user=userid)

            if new_status == 'Normal User':
                wallet.wallet_coins = 300
                wallet.purchase_date = None
                wallet.agent_balance = 0
                wallet.save()
            elif new_status == 'Agent User':
                wallet.wallet_coins = 0
                wallet.purchase_date = None
                wallet.save()

                user.is_existing = False
                user.save()

    return render(request, 'registered_users.html', {'users': users, 'username': username})


def add_user(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')
    else:
        if request.method == 'POST':
            form = CustomerForm(request.POST)
            if form.is_valid():
                customer = form.save()  # Saves the form data to the CustomerModel database table

                wallet = WalletModel(user=customer)
                wallet.save()

                return redirect('users')  # Redirect to a success page or another view after successful submission
        else:
            form = CustomerForm()
    return render(request, 'add_user.html', {'form': form, 'username': username})


def delete_user(request):
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        if user_id:
            try:
                user = CustomerModel.objects.get(pk=user_id)
                user.delete()
                return redirect('users')  # Redirect to the users list page after deletion
            except CustomerModel.DoesNotExist:
                return redirect('users')  # Handle the case where the user does not exist
    return HttpResponseNotAllowed(['POST'])


def wallet_normaluser(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')
    wallets = WalletModel.objects.filter(user__status='Normal User')
    return render(request, 'normaluser_wallet.html', {'wallets': wallets, 'username': username})


def wallet_agentuser(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')

    wallets = WalletModel.objects.filter(user__status='Agent User')
    return render(request, 'agentuser_wallet.html', {'wallets': wallets, 'username': username})


def user_history(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')

    user_history = UserPurchaseModel.objects.all()
    return render(request, 'normaluser_history.html', {'user_history': user_history, 'username': username})


def agent_history(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')

    agent_history = WithdrawalHistoryModel.objects.all()
    return render(request, 'agentuser_history.html', {'agent_history': agent_history, 'username': username})


def coin_package(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')
    coins = CallPackageModel.objects.all()
    chats = ChatPackageModel.objects.all()
    return render(request, 'coin_package.html', {'coins': coins, 'chats': chats, 'username': username})


def add_package(request):
    username = request.session.get('user', None)
    if username is None:
        return redirect('/login')
    else:
        if request.method == 'POST':
            callform = CallPackageForm(request.POST)
            chatform = ChatPackageForm(request.POST)

            if request.POST.get('call_package'):
                if callform.is_valid():
                    callform.save()
                    return redirect('coin_package')

            if request.POST.get('chat_package'):
                if chatform.is_valid():
                    chatform.save()
                    return redirect('coin_package')

        else:
            callform = CallPackageForm()
            chatform = ChatPackageForm()
    return render(request, 'add_package.html', {'callform': callform, 'chatform': chatform, 'username': username})


@require_POST
def delete_chat_package(request, chat_id):
    chat_package = get_object_or_404(ChatPackageModel, chat_id=chat_id)
    chat_package.delete()
    return redirect('coin_package')


@require_POST
def delete_coin_package(request, coin_id):
    coin_package = get_object_or_404(CallPackageModel, coin_id=coin_id)
    coin_package.delete()
    return redirect('coin_package')


def report_view(request):
    if request.method == 'POST':
        from_date = request.POST.get('from_date')
        to_date = request.POST.get('to_date')
        if from_date and to_date:
            from_date = datetime.strptime(from_date, '%Y-%m-%d')
            to_date = datetime.strptime(to_date, '%Y-%m-%d')

            user_details = []
            agent_details = []

            users = CustomerModel.objects.filter(status='Normal User')

            for user in users:
                purchases = UserPurchaseModel.objects.filter(user=user, purchase_date__range=[from_date, to_date])
                payments = PaymentModel.objects.filter(user=user, created_at__range=[from_date, to_date])
                user_details.append({
                    'user': {
                        'first_name': user.customer_first_name if user else None,
                        'last_name': user.customer_last_name if user else None,
                        'email': user.customer_email if user else None,
                        'contact': user.customer_contact,
                    },
                    'purchases': [
                        {
                            'purchase_date': '-' if not purchases else purchase.purchase_date.strftime(
                                '%d %B %Y %I:%M %p'),
                            'purchase_amount': '-' if not purchases else purchase.purchase_amount,
                            'purchase_type': '-' if not purchases else purchase.purchase_type
                        }
                        for purchase in purchases
                    ],
                    'payments': [
                        {
                            'created_at': '-' if not payments else payment.created_at.strftime('%d %B %Y %I:%M %p'),
                            'amount': '-' if not payments else payment.amount
                        }
                        for payment in payments
                    ],
                })

            agents = CustomerModel.objects.filter(status='Agent User')

            for agent in agents:
                withdrawals = WithdrawalHistoryModel.objects.filter(agent=agent,
                                                                    withdrawal_date__range=[from_date, to_date])
                transactions = AgentTransactionModel.objects.filter(agent=agent,
                                                                    transaction_date__range=[from_date, to_date])
                agent_details.append({
                    'agent': {
                        'customer_id': agent.customer_id,
                        'first_name': agent.customer_first_name,
                        'last_name': agent.customer_last_name,
                        'email': agent.customer_email,
                        'contact': agent.customer_contact,
                        'status': agent.status,
                        'languages': agent.languages,
                        'adhaar_no': agent.adhaar_no,
                    },
                    'withdrawals': [
                        {
                            'withdrawal_date': withdrawal.withdrawal_date.strftime('%d %B %Y %I:%M %p'),
                            'withdrawal_amount': withdrawal.withdrawal_amount
                        }
                        for withdrawal in withdrawals
                    ],
                    'transactions': [
                        {
                            'transaction_date': transaction.transaction_date.strftime('%d %B %Y %I:%M %p'),
                            'transaction_amount': transaction.transaction_amount,
                            'transaction_type': transaction.transaction_type
                        }
                        for transaction in transactions
                    ],
                })
            return JsonResponse({'user_details': user_details, 'agent_details': agent_details})

        return JsonResponse({'error': 'Invalid date range'}, status=400)

    return render(request, 'report.html')


def get_agora_token(request):
    channel_name = request.GET.get('channelName')
    uid = request.GET.get('uid')
    role = request.GET.get('role', 1)  # Default role is 1 (Attendee)
    expiration_time_in_seconds = int(request.GET.get('expiry', 3600))  # Default to 1 hour

    if not channel_name or not uid:
        return JsonResponse({'error': 'Channel name and uid are required'}, status=400)

    token = generate_agora_token(channel_name, uid, role, expiration_time_in_seconds)
    return JsonResponse({'token': token})


def privacypolicy(request):
    return HttpResponseRedirect('https://sites.google.com/view/callmatch-privacy-policy/home')
    # return render(request, 'privacypolicy.html')


def logout(request):
    del request.session['user']
    return redirect('/')


# api
@api_view(['GET'])
def check_users(request, mobileno, password):
    # Check if the user already exists
    try:
        user = CustomerModel.objects.get(customer_contact=mobileno, customer_password=password)
        user_data = CustomerSerializer(user)
        return Response(user_data.data, status=status.HTTP_200_OK)

    except CustomerModel.DoesNotExist:
        return Response({'message': 'User not existing'}, status=400)


def check_password(password):
    # Check if the password meets the criteria
    if len(password) < 8:
        return False, 'Password must be at least 8 characters long.'

    if not re.search(r'[A-Za-z]', password):
        return False, 'Password must contain at least one alphabet.'

    if not re.search(r'\d', password):
        return False, 'Password must contain at least one numeral.'

    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False, 'Password must contain at least one special character.'

    return True, ''  # Return True if the password is valid


@api_view(['POST'])
def customers(request):
    contact = request.data.get('mobile_no')
    password = request.data.get('password')
    gender = request.data.get('gender')
    if not contact:
        return Response({'error': 'Phone Number required'}, status=status.HTTP_400_BAD_REQUEST)

    # Validate if the contact number contains only digits and is exactly 10 digits long
    if not contact.isdigit() or len(contact) != 10:
        return Response(
            {'error': 'Invalid Phone Number. It must be exactly 10 digits long and contain only numbers.'},
            status=status.HTTP_400_BAD_REQUEST)

    # Check if the user already exists
    try:
        user = CustomerModel.objects.get(customer_contact=contact)
        # If the user exists, check if the password is correct
        if user.customer_password != password:
            return Response({'error': 'Incorrect password'}, status=status.HTTP_400_BAD_REQUEST)

        # If the password is correct, update user's is_existing and is_online to True
        user.is_existing = True
        user.is_online = True
        user.save()
        user_data = CustomerSerializer(user)
        return Response(user_data.data, status=status.HTTP_200_OK)

    except CustomerModel.DoesNotExist:
        # Validate the password using check_password function
        is_valid, error_message = check_password(password)
        if not is_valid:
            return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)

        # If user does not exist, create a new user
        user = CustomerModel.objects.create(
            customer_contact=contact,
            customer_password=password,
            gender=gender,
            is_existing=False,
            is_online=True
        )
        user.save()

        # Create a wallet for the new user
        wallet = WalletModel(user=user)
        wallet.save()

    user_data = CustomerSerializer(user)
    return Response(user_data.data, status=status.HTTP_200_OK)



# @api_view(['POST'])
# def signup(request):
#     contact = request.data.get('mobile_no')
#     password = request.data.get('password')
#     repeat_password = request.data.get('repeat_password')



@api_view(['GET'])
def all_agents(request):
    users = CustomerModel.objects.filter(status=CustomerModel.AGENT_USER)
    user_data = []

    for user in users:
        # Get the last message sent by this user
        last_message_obj = MessageModel.objects.filter(sender=user).order_by('-created_at').first()

        if last_message_obj:
            last_message = last_message_obj.message
            last_message_time = last_message_obj.created_at
        else:
            last_message = "no message"
            last_message_time = "no message"

        user_data.append({
            'customer_id': user.customer_id,
            'customer_first_name': user.customer_first_name,
            'customer_last_name': user.customer_last_name,
            'customer_contact': user.customer_contact,
            'customer_password': user.customer_password,
            'gender': user.gender,
            'status': user.status,
            'is_online': user.is_online,
            'last_message': last_message,
            'last_message_time': last_message_time,
        })

    return Response(user_data, status=status.HTTP_200_OK)


@api_view(['GET'])
def all_users(request):
    users = CustomerModel.objects.filter(status=CustomerModel.NORMAL_USER)
    user_data = []

    for user in users:
        # Get the last message sent by this user
        last_message_obj = MessageModel.objects.filter(sender=user).order_by('-created_at').first()

        if last_message_obj:
            last_message = last_message_obj.message
            last_message_time = last_message_obj.created_at
        else:
            last_message = "no message"
            last_message_time = "no message"

        user_data.append({
            'customer_id': user.customer_id,
            'customer_first_name': user.customer_first_name,
            'customer_last_name': user.customer_last_name,
            'customer_contact': user.customer_contact,
            'customer_password': user.customer_password,
            'gender': user.gender,
            'status': user.status,
            'is_online': user.is_online,
            'last_message': last_message,
            'last_message_time': last_message_time,
        })

    return Response(user_data, status=status.HTTP_200_OK)


@api_view(['POST'])
def update_profile(request, id):
    user = CustomerModel.objects.get(customer_id=id)
    user_data = CustomerSerializer(instance=user, data=request.data, partial=True)
    if user_data.is_valid():
        user_data.save()
        return Response({"message": "Profile updated successfully"})
    return Response(user_data.errors)


@api_view(['GET'])
def wallet(request, id):
    wallet = WalletModel.objects.get(user=id)
    wallet_data = WalletSerializer(wallet, many=False)
    return Response(wallet_data.data)


@api_view(['POST'])
def withdrawal(request, id):
    agent = WalletModel.objects.get(user__customer_id=id)
    agent_amount = request.data.get('amount')

    if agent.total_amount >= 5000:
        agent.total_amount = agent.total_amount - agent_amount
        agent.save()
        WithdrawalHistoryModel.objects.create(
            agent=CustomerModel.objects.get(customer_id=id),
            withdrawal_amount=agent_amount,
            withdrawal_date=datetime.now()
        )

        return JsonResponse({'message': f'Withdrawn amount: {agent_amount}'}, status=200)
    else:
        # Return error response if balance is insufficient
        return JsonResponse({'error': 'Insufficient balance for withdrawal'}, status=400)


# call
@api_view(['POST'])
def notify_agent(request):
    caller_id = request.data.get('caller_id')
    agent_id = request.data.get('agent_id')

    try:
        caller = CustomerModel.objects.get(customer_id=caller_id)
        agent = CustomerModel.objects.get(customer_id=agent_id)

        notification = {
            "message": f"{caller.username} is trying to connect with you.",
            "caller_id": caller.id,
            "caller_name": caller.username
        }

        return Response(notification)
    except CustomerModel.DoesNotExist:
        return Response({"error": "User not found"}, status=404)


@api_view(['POST'])
def start_call(request):
    caller_id = request.data.get('caller_id')
    agent_id = request.data.get('agent_id')
    agora_channel_name = request.data.get('agora_channel_name')

    call = CallDetailsModel.objects.create(
        caller_id=caller_id,
        agent_id=agent_id,
        agora_channel_name=agora_channel_name,
        start_time=timezone.now()
    )

    agent = CustomerModel.objects.get(customer_id=agent_id)
    agent.is_online = False
    agent.save()

    return Response({"call_id": call.call_id})


@api_view(['POST'])
def end_call(request):
    call_id = request.data.get('call_id')
    try:
        call = CallDetailsModel.objects.get(call_id=call_id)
        call.end_time = timezone.now()
        call.save()

        agent_id = call.agent.customer_id
        agent = CustomerModel.objects.get(customer_id=agent_id)
        agent.is_online = True
        agent.save()

        # Calculate exact duration in seconds
        duration_seconds = (call.end_time - call.start_time).total_seconds()

        caller_wallet = WalletModel.objects.get(user=call.caller)
        agent_wallet = WalletModel.objects.get(user=call.agent)

        cost_per_minute = 150
        amount_per_minute = 3

        # Calculate cost per second
        cost_per_second = cost_per_minute / 60
        amount_per_second = amount_per_minute / 60

        # Deduct coins from caller
        caller_wallet.wallet_coins -= duration_seconds * cost_per_second
        caller_wallet.save()

        # Add amount to agent's balance
        agent_wallet.call_amount += duration_seconds * amount_per_second
        agent_wallet.total_minutes += duration_seconds / 60
        agent_wallet.total_amount += duration_seconds * amount_per_second
        agent_wallet.save()

        # Create transaction record
        AgentTransactionModel.objects.create(
            agent=agent,
            receiver=call.caller,
            transaction_amount=duration_seconds * amount_per_second,
            transaction_date=datetime.now(),
            transaction_type='Call'
        )

        return Response({"duration": duration_seconds / 60})
    except CallDetailsModel.DoesNotExist:
        return Response({"error": "Call not found"}, status=404)
    except CustomerModel.DoesNotExist:
        return Response({"error": "Customer not found"}, status=404)
    except WalletModel.DoesNotExist:
        return Response({"error": "Wallet not found"}, status=404)
    except Exception as e:
        return Response({"error": str(e)}, status=500)


@api_view(['GET'])
def list_chat_packages(request):
    packages = ChatPackageModel.objects.all()
    serializer = PackageSerializer(packages, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['GET'])
def list_call_packages(request):
    packages = CallPackageModel.objects.all()
    serializer = CoinsSerializer(packages, many=True)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(['POST'])
def buy_chat_package(request):
    user_id = request.data.get('user_id')
    package_id = request.data.get('package_id')
    razorpay_payment_id = request.data.get('razorpay_payment_id')

    try:
        user = CustomerModel.objects.get(customer_id=user_id, status=CustomerModel.NORMAL_USER)
        package = ChatPackageModel.objects.get(chat_id=package_id)
    except (CustomerModel.DoesNotExist):
        return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
    except ChatPackageModel.DoesNotExist:
        return Response({'error': 'package not found'}, status=status.HTTP_404_NOT_FOUND)

    # Create payment entry
    package_type = ContentType.objects.get_for_model(package)
    payment = PaymentModel.objects.create(
        user=user,
        package_content_type=package_type,
        package_object_id=package.pk,
        amount=package.package_price,
        razorpay_id=razorpay_payment_id,
        paid=True,
        created_at=datetime.now()
    )

    # Add messages to user
    wallet = WalletModel.objects.get(user=user_id)
    wallet.messages_remaining += package.message_count
    wallet.save()

    purchase_date = datetime.now()
    history = UserPurchaseModel.objects.create(
        user=user,
        purchase_amount=package.package_price,
        purchase_date=purchase_date,
        purchase_type = 'Chat'
    )

    return Response({'message': 'Package purchased successfully'}, status=status.HTTP_200_OK)


@api_view(['POST'])
def buy_call_package(request):
    user_id = request.data.get('user_id')
    package_id = request.data.get('package_id')
    razorpay_payment_id = request.data.get('razorpay_payment_id')

    try:
        user = CustomerModel.objects.get(pk=user_id, status=CustomerModel.NORMAL_USER)
        package = CallPackageModel.objects.get(pk=package_id)
    except (CustomerModel.DoesNotExist, CallPackageModel.DoesNotExist):
        return Response({'error': 'User or package not found'}, status=status.HTTP_404_NOT_FOUND)

    # Create payment entry
    package_type = ContentType.objects.get_for_model(package)
    payment = PaymentModel.objects.create(
        user=user,
        package_content_type=package_type,
        package_object_id=package.pk,
        amount=package.package_price,
        razorpay_id=razorpay_payment_id,
        paid=True,
        created_at=datetime.now()
    )

    # Add messages to user
    wallet = WalletModel.objects.get(user=user_id)
    wallet.wallet_coins += package.total_coins
    wallet.save()

    purchase_date = datetime.now()
    history = UserPurchaseModel.objects.create(
        user=user,
        purchase_amount=package.package_price,
        purchase_date=purchase_date,
        purchase_type='Call'
    )

    return Response({'message': 'Package purchased successfully'}, status=status.HTTP_200_OK)


@api_view(['POST'])
def send_message(request):
    user_1 = request.data.get('user_1')
    user_2 = request.data.get('user_2')
    message_text = request.data.get('message')

    if not user_1 or not user_2 or not message_text:
        return Response({'error': 'Users, and message are required'}, status=status.HTTP_400_BAD_REQUEST)

    try:
        sender = CustomerModel.objects.get(customer_id=user_1)
        recipient = CustomerModel.objects.get(customer_id=user_2)
    except CustomerModel.DoesNotExist:
        return Response({'error': 'User or agent not found'}, status=status.HTTP_404_NOT_FOUND)

    if sender.status == 'Normal User':
        user_wallet = WalletModel.objects.get(user=sender)
        if user_wallet.messages_remaining <= 0:
            return Response({'error': 'Not enough messages remaining'}, status=status.HTTP_400_BAD_REQUEST)
        # Deduct message from user's wallet
        user_wallet.messages_remaining -= 1
        user_wallet.save()

    # Add amount to agent's account if the sender is the user
    if recipient.status == 'Agent User':
        agent_wallet, created = WalletModel.objects.get_or_create(user=recipient)
        agent_wallet.chat_amount += MESSAGE_COST
        agent_wallet.total_messages_received += 1
        agent_wallet.total_amount += MESSAGE_COST
        agent_wallet.save()

        # Create transaction record
        AgentTransactionModel.objects.create(
            agent=recipient,
            receiver=sender,
            transaction_amount=MESSAGE_COST,
            transaction_date=datetime.now(),
            transaction_type='Chat'
        )

    inbox, created = InboxModel.objects.get_or_create(
        last_sent_user=sender,
        defaults={'last_message': message_text}
    )
    if not created:
        inbox.last_message = message_text
        inbox.save()

    # Ensure both participants are in the inbox
    InboxParticipantsModel.objects.get_or_create(inbox=inbox, user=sender)
    InboxParticipantsModel.objects.get_or_create(inbox=inbox, user=recipient)

    # Create the message
    message = MessageModel.objects.create(
        inbox=inbox,
        sender=sender,
        receiver=recipient,
        message=message_text,
        created_at=datetime.now()
    )

    return Response({'message': 'Message sent successfully'}, status=status.HTTP_200_OK)


@api_view(['GET'])
def message_inbox(request, id):
    user = CustomerModel.objects.get(customer_id=id)
    inboxes = InboxModel.objects.filter(
        inboxparticipantsmodel__user=user
    ).distinct()

    user_data = []
    message = []

    for inbox in inboxes:
        last_message = MessageModel.objects.filter(
            inbox=inbox
        ).order_by('-created_at').first()

        if last_message:
            other_participant = (
                CustomerModel.objects
                .filter(inboxparticipantsmodel__inbox=inbox)
                .exclude(customer_id=user.customer_id)
                .first()
            )
            user_data.append({

                'participant_name': other_participant.customer_first_name,
                'last_message': last_message.message,
                'sent_by': last_message.sender.customer_first_name,
                'sent_at': last_message.created_at,
            })
        # user_data.append({
        #     'first_name': user.customer_first_name,
        #     'last_name': user.customer_last_name,
        #     'message':[{
        #         'agent_name':message.participant_name,
        #         'last_message':message.last_message,
        #
        #     }]
        # })

    return Response(user_data)


@api_view(['GET'])
def get_chat(request, user1, user2):
    try:
        user_1 = CustomerModel.objects.get(customer_id=user1)
        user_2 = CustomerModel.objects.get(customer_id=user2)
    except CustomerModel.DoesNotExist:
        return Response({'error': 'User or agent not found'}, status=status.HTTP_404_NOT_FOUND)

    # Fetch all messages in the inbox where both user and agent are participants
    messages = MessageModel.objects.filter(
        inbox__in=InboxParticipantsModel.objects.filter(user=user_1).values_list('inbox', flat=True),
        sender__in=[user_1, user_2],
        receiver__in=[user_1, user_2]
    ).order_by('created_at')

    # Serialize the messages
    serializer = MessageSerializer(messages, many=True)

    return Response({'messages': serializer.data}, status=status.HTTP_200_OK)


@api_view(['POST'])
def give_rating(request):
    agent_id = request.data.get('agent')
    user_id = request.data.get('user')
    rating = request.data.get('ratings')

    # Get the agent and user instances
    try:
        agent = CustomerModel.objects.get(customer_id=agent_id)
        user = CustomerModel.objects.get(customer_id=user_id)
    except CustomerModel.DoesNotExist:
        return Response({'error': 'Invalid agent or user ID'}, status=status.HTTP_400_BAD_REQUEST)

    newrating = RatingModel.objects.create(
        agent=agent,
        user=user,
        ratings=rating,
        created_at=datetime.now()
    )

    return Response({'message': "Thank you for your feedback!"}, status=status.HTTP_200_OK)


@api_view(['POST'])
def terms_conditions(request, id):
    agent = CustomerModel.objects.get(customer_id=id)
    agent.terms_conditions = True
    agent.is_online = True
    agent.save()
    return Response({'message': "Terms and conditions accepted"}, status=status.HTTP_200_OK)


@api_view(['GET'])
def initiate_payment(request):
    # Replace with your actual details
    mid = "cFrLti86230523261499"
    merchant_key = "B05yxmmdhxhdp129"
    # Generate a unique order ID for each transaction
    order_id = str(uuid.uuid4())
    callback_url = " http://127.0.0.1:8000/callback/"
    txn_amount = request.data.get('amount')
    customer_id = request.data.get('user_id')

    paytmParams = dict()
    paytmParams["body"] = {
        "requestType": "Payment",
        "mid": "cFrLti86230523261499",
        "websiteName": "CallMatch",
        "orderId": "ORDERID_98765",
        "callbackUrl": "http://127.0.0.1:8000/callback/",
        "txnAmount": {
            "value": "1.00",
            "currency": "INR",
        },
        "userInfo": {
            "custId": "CUST_001",
        },
    }

    # Generate checksum by parameters we have in body
    # Find your Merchant Key in your Paytm Dashboard at https://dashboard.paytm.com/next/apikeys
    checksum = PaytmChecksum.generateSignature(json.dumps(paytmParams["body"]), merchant_key)

    paytmParams["head"] = {
        "signature": checksum
    }

    post_data = json.dumps(paytmParams)
    print(post_data)
    # for Staging
    url = f"https://securegw-stage.paytm.in/theia/api/v1/initiateTransaction?mid={mid}&orderId=ORDERID_98765"

    # for Production
    # url = "https://securegw.paytm.in/theia/api/v1/initiateTransaction?mid=YOUR_MID_HERE&orderId=ORDERID_98765"
    response = requests.post(url, data=post_data, headers={"Content-type": "application/json"}).json()
    print(response)
    return JsonResponse(response)


@csrf_exempt
def payment_callback(request):
    # Extract the Paytm parameters from the POST request
    received_data = dict(request.POST.items())

    paytm_params = received_data.copy()
    paytm_checksum = received_data.pop('CHECKSUMHASH', None)

    # Verify the checksum
    is_valid_checksum = verifySignature(paytm_params, "B05yxmmdhxhdp129", paytm_checksum)

    if is_valid_checksum:
        # Check the transaction status
        if received_data['RESPCODE'] == '01':
            # Transaction was successful
            # Update your database, e.g., mark order as paid
            return HttpResponse("Payment successful")
        else:
            # Transaction failed
            return HttpResponse(f"Payment failed: {received_data['RESPMSG']}")
    else:
        # Checksum is invalid
        return HttpResponse("Checksum verification failed", status=400)


@api_view(['GET'])
def online_status(request, id):
    user = CustomerModel.objects.get(customer_id = id)
    user.is_online = True
    user.save()
    return JsonResponse({'status': 'success', 'message': 'User is now online.'})


@api_view(['GET'])
def offline_status(request, id):
    user = CustomerModel.objects.get(customer_id=id)
    user.is_online = False
    user.save()
    return JsonResponse({'status': 'success', 'message': 'User is now offline.'})
