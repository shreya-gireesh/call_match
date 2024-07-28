from django.contrib import admin
from AdminApp.models import *

# Register your models here.
admin.site.register(CustomerModel)
admin.site.register(WalletModel)
admin.site.register(UserPurchaseModel)
admin.site.register(CallPackageModel)
admin.site.register(AdminModel)
admin.site.register(ChatPackageModel)
admin.site.register(InboxModel)
admin.site.register(InboxParticipantsModel)
admin.site.register(MessageModel)
admin.site.register(WithdrawalHistoryModel)
admin.site.register(AgentTransactionModel)
admin.site.register(PaymentModel)