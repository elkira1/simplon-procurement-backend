from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient

from .models import CustomUser, PurchaseRequest


class PurchaseRequestListAPITests(TestCase):
    def setUp(self):
        self.mg_user = CustomUser.objects.create_user(
            username="mg_user",
            email="mg@example.com",
            password="password",
            role="mg",
        )
        self.employee = CustomUser.objects.create_user(
            username="employee",
            email="employee@example.com",
            password="password",
            role="employee",
        )

        base_date = timezone.now() - timedelta(days=10)
        self.pending_request = PurchaseRequest.objects.create(
            user=self.employee,
            item_description="Achat d'imprimante",
            quantity=1,
            estimated_cost=Decimal("150000"),
            urgency="high",
            justification="Imprimante pour le bureau",
            status="pending",
        )
        PurchaseRequest.objects.filter(pk=self.pending_request.pk).update(
            created_at=base_date
        )
        self.pending_request.refresh_from_db()
        self.approved_request = PurchaseRequest.objects.create(
            user=self.employee,
            item_description="Ordinateur portable",
            quantity=2,
            estimated_cost=Decimal("900000"),
            urgency="medium",
            justification="Renouvellement matériel",
            status="director_approved",
        )
        PurchaseRequest.objects.filter(pk=self.approved_request.pk).update(
            created_at=base_date - timedelta(days=5)
        )
        self.approved_request.refresh_from_db()

        self.client = APIClient()
        self.client.force_authenticate(user=self.mg_user)

    def test_filter_by_status_returns_only_matching(self):
        url = reverse("requests_list")
        response = self.client.get(url, {"status": "pending"})
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["id"], self.pending_request.id)

    def test_search_and_date_filters(self):
        url = reverse("requests_list")
        params = {
            "search": "portable",
            "date_from": (timezone.now() - timedelta(days=20)).date().isoformat(),
            "date_to": timezone.now().date().isoformat(),
        }
        response = self.client.get(url, params)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["results"][0]["id"], self.approved_request.id)

    def test_urgency_and_amount_filters(self):
        very_expensive = PurchaseRequest.objects.create(
            user=self.employee,
            item_description="Serveur critique",
            quantity=1,
            estimated_cost=Decimal("2500000"),
            urgency="critical",
            justification="Infrastructure",
            status="pending",
        )

        url = reverse("requests_list")
        params = {
            "urgency": "critical",
            "min_amount": "2000000",
        }
        response = self.client.get(url, params)
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        ids = [item["id"] for item in payload["results"]]
        self.assertIn(very_expensive.id, ids)
        self.assertNotIn(self.pending_request.id, ids)
