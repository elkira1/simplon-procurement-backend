from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import PurchaseRequest, RequestStep

@receiver(post_save, sender=PurchaseRequest)
def create_initial_step(sender, instance, created, **kwargs):
    if created:
        RequestStep.objects.create(
            request=instance,
            user=instance.user,
            action='submitted',
            comment="Demande créée"
        )