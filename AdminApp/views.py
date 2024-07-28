import requests
import csv
from django.shortcuts import render, redirect, get_object_or_404
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.http import JsonResponse, HttpResponseNotAllowed, HttpResponse
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_POST, require_GET
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q, Sum
from CallMatch import settings
from .utils import generate_agora_token
from django.utils import timezone
from datetime import datetime
from .forms import CustomerForm, AdminForm, CallPackageForm, ChatPackageForm
from .serializer import *
from .models import *


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
        writer.writerow(['Type', 'Customer ID', 'Name', 'Email', 'Contact', 'Status', 'Languages', 'Adhaar No', 'Details'])

        for customer in customers:
            if customer.is_agent:
                withdrawals = WithdrawalHistoryModel.objects.filter(agent=customer, withdrawal_date__range=[from_date, to_date]).order_by('-withdrawal_date')
                transactions = AgentTransactionModel.objects.filter(agent=customer, transaction_date__range=[from_date, to_date]).order_by('-transaction_date')
                details = f"Withdrawals: {' | '.join([f'{w.withdrawal_date} - {w.withdrawal_amount}' for w in withdrawals])}; Transactions: {' | '.join([f'{t.transaction_date} - {t.transaction_amount} ({t.transaction_type})' for t in transactions])}"
                writer.writerow(['Agent', customer.customer_id, f"{customer.customer_first_name} {customer.customer_last_name}", customer.customer_email, customer.customer_contact, customer.status, customer.languages, customer.adhaar_no, details])
            else:
                purchases = UserPurchaseModel.objects.filter(user=customer, purchase_date__range=[from_date, to_date]).order_by('-purchase_date')
                payments = PaymentModel.objects.filter(user=customer, created_at__range=[from_date, to_date]).order_by('-created_at')
                details = f"Purchases: {' | '.join([f'{p.purchase_date} - {p.purchase_amount}' for p in purchases])}; Payments: {' | '.join([f'{p.created_at} - {p.amount}' for p in payments])}"
                writer.writerow(['User', customer.customer_id, f"{customer.customer_first_name} {customer.customer_last_name}", customer.customer_email, customer.customer_contact, customer.status, customer.languages, customer.adhaar_no, details])

        return response

    return JsonResponse({'error': 'Invalid date range'}, status=400)


def agent_report(request):
    agents = CustomerModel.objects.filter(status ='Agent User' )
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
                "date":  t.transaction_date.strftime('%d %B %Y %I:%M %p'),
                "type":t.transaction_type
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
            request.session.set_expiry(600)

            expiry = request.session.get_expiry_age()
            print(f"Session will expire in {expiry} seconds")

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
            print(form.errors)
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
        all_agents = CustomerModel.objects.filter(status = 'Agent User')
        payments = PaymentModel.objects.all().aggregate(Sum('amount'))
        amount = payments['amount__sum']
    return render(request, 'index.html', {'normaluser': normal_users_count, 'agentuser': agent_user_count,
                                          'all_agents': all_agents, 'payments': amount, 'username': username})


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

                wallet = WalletModel(user = customer)
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
    return render(request, 'coin_package.html', {'coins': coins,'chats': chats, 'username': username})


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

            users = CustomerModel.objects.filter(status = 'Normal User')

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
                        'purchase_date': '-' if not purchases else purchase.purchase_date.strftime('%d %B %Y %I:%M %p'),
                        'purchase_amount': '-' if not purchases else purchase.purchase_amount
                    }
                    for purchase in purchases
                ],
                    'payments': [
                    {
                        'created_at': '-' if not payments else payment.created_at.strftime('%d %B %Y %I:%M %p'),
                        'amount': '-' if not payments else  payment.amount
                    }
                    for payment in payments
                ],
                })

            agents = CustomerModel.objects.filter(status = 'Agent User')

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


def logout(request):
    del request.session['user']
    return redirect('/')


# api
@api_view(['POST'])
def customers(request):
    contact = request.data.get('mobile_no')
    if not contact:
        return Response({'error': 'Phone Number required'}, status=status.HTTP_400_BAD_REQUEST)

    # Check if the user already exists
    try:
        user = CustomerModel.objects.get(customer_contact=contact)
        # Update existing user's is_existing and is_online to True
        user.is_existing = True
        user.is_online = True
        user.save()
        user_data = CustomerSerializer(user)
        return Response(user_data.data, status=status.HTTP_200_OK)

    except CustomerModel.DoesNotExist:
        # If user does not exist, create a new user
        user = CustomerModel.objects.create(
            customer_contact=contact,
            is_existing=False,
            is_online=True
        )
        user.save()

        # Create a wallet for the new user
        wallet = WalletModel(user=user)
        wallet.save()

    user_data = CustomerSerializer(user)
    return Response(user_data.data, status=status.HTTP_200_OK)


@api_view(['GET'])
def all_agents(request):
    users = CustomerModel.objects.filter(status = CustomerModel.AGENT_USER)
    user_data = CustomerSerializer(users, many=True)
    return Response(user_data.data, status=status.HTTP_200_OK)


@api_view(['GET'])
def all_users(request):
    users = CustomerModel.objects.filter(status = CustomerModel.NORMAL_USER)
    user_data = CustomerSerializer(users, many=True)
    return Response(user_data.data, status=status.HTTP_200_OK)


@api_view(['POST'])
def update_profile(request, id):
    user = CustomerModel.objects.get(customer_id = id)
    user_data = CustomerSerializer(instance=user, data=request.data, partial = True)
    if user_data.is_valid():
        user_data.save()
        return Response({"message": "Profile updated successfully"})
    return Response(user_data.errors)


@api_view(['POST'])
def register(request):
    contact = request.data.get('mobile_no')
    if not contact:
        return Response({'error': 'Phone Number required'}, status=status.HTTP_400_BAD_REQUEST)

    user, created = CustomerModel.objects.get_or_create(
        customer_contact=contact,
        defaults={
            'customer_first_name': request.data.get('first_name', ''),
            'customer_last_name': request.data.get('last_name', ''),
            'customer_email': request.data.get('email', ''),
        }
    )

    if created:
        user.is_online = True
        user.save()

        # Create a wallet for the new user
        wallet = WalletModel(user=user)
        wallet.save()

        user_data = CustomerSerializer(user)
        return Response(user_data.data, status=status.HTTP_201_CREATED)
    else:
        return Response({'error': 'Customer already exists'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
def wallet(request, id):
    wallet = WalletModel.objects.get(user=id)
    wallet_data = WalletSerializer(wallet, many=False)
    return Response(wallet_data.data)


@api_view(['GET'])
def withdrawal(request, id):
    agent = WalletModel.objects.get(user__customer_id=id)

    if agent.total_amount >= 5000:
        withdrawal_amount = agent.total_amount
        agent.total_amount = agent.total_amount - withdrawal_amount
        print(agent.total_amount)
        agent.save()
        WithdrawalHistoryModel.objects.create(
            agent=CustomerModel.objects.get(customer_id= id),
            withdrawal_amount=withdrawal_amount,
            withdrawal_date=datetime.now()
        )

        return JsonResponse({'message': f'Withdrawn amount: {withdrawal_amount}'}, status=200)
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
        agent = CustomerModel.objects.get(customer_id =agent_id)

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

    return Response({"call_id": call.call_id})


@api_view(['POST'])
def end_call(request):
    call_id = request.data.get('call_id')

    call = CallDetailsModel.objects.get(call_id=call_id)
    call.end_time = timezone.now()
    call.save()

    # Fetch call duration from Agora API
    agora_app_id = settings.AGORA_APP_ID
    agora_app_certificate = settings.AGORA_APP_CERTIFICATE
    agora_api_url = f'https://api.agora.io/dev/v1/channel/{agora_app_id}/{call.agora_channel_name}?token={agora_app_certificate}'

    response = requests.get(agora_api_url)
    call_data = response.json()

    if 'duration' in call_data:
        duration = call_data['duration'] // 60  # Convert seconds to minutes
        call.duration = duration
        call.save()

        caller_wallet = WalletModel.objects.get(user=call.caller)
        agent_purchase = WalletModel.objects.get(user=call.agent)

        cost_per_minute = 150
        amount_per_minute = 3

        # Deduct coins from caller
        caller_wallet.wallet_coins -= duration * cost_per_minute
        caller_wallet.save()

        # Add amount to agent's balance
        agent_purchase.call_amount += duration * amount_per_minute
        agent_purchase.total_minutes += duration
        agent_purchase.total_amount = agent_purchase.total_amount + (duration * amount_per_minute)
        agent_purchase.save()

        # Create transaction record
        AgentTransactionModel.objects.create(
            agent=agent_purchase,
            receiver= call.caller,
            transaction_amount=amount_per_minute,
            transaction_date=datetime.now(),
            transaction_type='Call'
        )

        return Response({"duration": duration})
    else:
        return Response({"error": "Failed to fetch call duration from Agora API"}, status=500)


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
        created_at = datetime.now()
    )

    # Add messages to user
    wallet = WalletModel.objects.get(user=user_id)
    wallet.messages_remaining += package.message_count
    wallet.save()

    purchase_date = datetime.now()
    history = UserPurchaseModel.objects.create(
        user = user,
        purchase_amount = package.package_price,
        purchase_date=purchase_date
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
        created_at = datetime.now()
    )

    # Add messages to user
    wallet = WalletModel.objects.get(user=user_id)
    wallet.wallet_coins += package.total_coins
    wallet.save()

    purchase_date = datetime.now()
    history = UserPurchaseModel.objects.create(
        user=user,
        purchase_amount=package.package_price,
        purchase_date = purchase_date
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