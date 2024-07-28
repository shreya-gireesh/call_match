from rest_framework import serializers
from .models import *


class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomerModel
        fields = '__all__'


class WalletSerializer(serializers.ModelSerializer):
    class Meta:
        model = WalletModel
        fields = '__all__'


class AgentPurchaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserPurchaseModel
        fields = '__all__'


class CoinsSerializer(serializers.ModelSerializer):
    class Meta:
        model = CallPackageModel
        fields = '__all__'


class MessageSerializer(serializers.ModelSerializer):
    sender = CustomerSerializer(read_only=True)
    receiver = CustomerSerializer(read_only=True)

    class Meta:
        model = MessageModel
        fields = ['message_id', 'sender', 'receiver','message', 'created_at']


class InboxSerializer(serializers.ModelSerializer):
    last_sent_user = CustomerSerializer(read_only=True)
    messages = MessageSerializer(many=True, read_only=True, source='messagemodel_set')

    class Meta:
        model = InboxModel
        fields = ['inbox_id', 'last_message', 'last_sent_user', 'messages']


class PackageSerializer(serializers.ModelSerializer):
    class Meta:
        model = ChatPackageModel
        fields = '__all__'


class WithdrawalHistorySerializer(serializers.ModelSerializer):
    class Meta:
        model = WithdrawalHistoryModel
        fields = ['agentpurchase_id', 'withdrawal_amount', 'withdrawal_date']



