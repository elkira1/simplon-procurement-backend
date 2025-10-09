import secrets
from django.shortcuts import render
from django.contrib.auth import get_user_model


# Create your views here.
from django.shortcuts import get_object_or_404
from django.db.models import Q, Count, Sum, Avg, Case, When, Value, F, DecimalField
from dateutil.relativedelta import relativedelta
from django.utils import timezone
from datetime import datetime, timedelta
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.pagination import PageNumberPagination
from .models import PasswordResetCode, PurchaseRequest, RequestStep, Attachment, UserActivity
from .serializers import (
    PasswordChangeSerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer, PasswordResetVerifySerializer, PurchaseRequestListSerializer, PurchaseRequestDetailSerializer,
    PurchaseRequestCreateSerializer, UserActivitySerializer, UserListSerializer, UserProfileUpdateSerializer, UserRegistrationSerializer, UserUpdateSerializer, ValidateRequestSerializer,
    AttachmentSerializer, DashboardSerializer, UserSerializer
)

from django.core.paginator import Paginator
from django.db.models.functions import Extract
from django.conf import settings
import logging
import cloudinary

from rest_framework.permissions import AllowAny
from services.email_service import EmailService


logger = logging.getLogger(__name__)



User = get_user_model()

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    """Retourne les infos de l'utilisateur connecté"""
    serializer = UserSerializer(request.user)
    return Response(serializer.data)

def get_client_ip(request):
    """Récupérer l'adresse IP du client"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_request(request):
    
    serializer = PasswordResetRequestSerializer(data=request.data)
    
    if serializer.is_valid():
        email = serializer.validated_data['email']
        
        try:
            user = User.objects.get(email__iexact=email)
            
            PasswordResetCode.objects.filter(
                user=user, 
                is_used=False
            ).update(is_used=True)
            
            reset_code = PasswordResetCode.objects.create(
                user=user,
                ip_address=get_client_ip(request)
            )
            
            email_service = EmailService()
            email_sent = email_service.send_password_reset_code(user, reset_code.code)
            
            if email_sent:
                logger.info(f"Password reset code sent to {email}")
                return Response({
                    'message': 'Code de vérification envoyé par email',
                    'expires_in': 300  
                }, status=status.HTTP_200_OK)
            else:
                logger.error(f"Failed to send password reset code to {email}")
                return Response({
                    'error': 'Erreur lors de l\'envoi de l\'email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except User.DoesNotExist:
            return Response({
                'message': 'Si cet email existe, un code a été envoyé'
            }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_verify(request):
    serializer = PasswordResetVerifySerializer(data=request.data)
    
    if serializer.is_valid():
        reset_code = serializer.validated_data['reset_code']
        
        reset_code.is_used = True
        reset_code.save()
        
        reset_token = secrets.token_urlsafe(32)
        
        from django.core.cache import cache
        cache.set(f'reset_token_{reset_token}', reset_code.user.id, timeout=300)  
        
        logger.info(f"Password reset code verified for user {reset_code.user.username}")
        
        return Response({
            'message': 'Code vérifié avec succès',
            'reset_token': reset_token
        }, status=status.HTTP_200_OK)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def password_reset_confirm(request):
    serializer = PasswordResetConfirmSerializer(data=request.data)
    
    if serializer.is_valid():
        reset_token = serializer.validated_data['token']
        new_password = serializer.validated_data['new_password']
        
        from django.core.cache import cache
        user_id = cache.get(f'reset_token_{reset_token}')
        
        if not user_id:
            return Response({
                'error': 'Token invalide ou expiré'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(id=user_id)
            user.set_password(new_password)
            user.save()
            
            cache.delete(f'reset_token_{reset_token}')
            
            from .models import UserActivity
            UserActivity.objects.create(
                user=user,
                performed_by=user,
                action='updated',
                details={'action': 'password_reset'},
                ip_address=get_client_ip(request)
            )
            
            logger.info(f"Password successfully reset for user {user.username}")
            
            return Response({
                'message': 'Mot de passe réinitialisé avec succès'
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                'error': 'Utilisateur non trouvé'
            }, status=status.HTTP_400_BAD_REQUEST)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def register_user(request):
    
    if request.user.role not in ['mg', 'director']:
        return Response(
            {'error': 'Vous n\'avez pas les droits pour créer des utilisateurs'}, 
            status=status.HTTP_403_FORBIDDEN
        )

    logger.info(f"User registration attempt by: {request.user.username} (role: {request.user.role})")
    logger.info(f"Registration data: {request.data}")

    serializer = UserRegistrationSerializer(
        data=request.data,
        context={
            'created_by': request.user,
            'ip_address': get_client_ip(request)
        }
    )

    if serializer.is_valid():
        try:
            user = serializer.save()
            logger.info(f"User created successfully: {user.username}")
            
            email_status = getattr(user, 'email_sent', False)
            if email_status:
                logger.info(f"Welcome email sent successfully to {user.email}")
            else:
                logger.warning(f"Failed to send welcome email to {user.email}")
            
            return Response(
                serializer.data, 
                status=status.HTTP_201_CREATED
            )
                    
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return Response(
                {'error': f'Erreur lors de la création de l\'utilisateur: {str(e)}'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    else:
        logger.warning(f"Registration validation errors: {serializer.errors}")
        return Response(
            serializer.errors, 
            status=status.HTTP_400_BAD_REQUEST
        )


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def users_list(request):
    
    if request.user.role not in ['mg', 'director']:
        return Response(
            {'error': 'Vous n\'avez pas les droits pour voir la liste des utilisateurs'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    search = request.GET.get('search', '')
    role_filter = request.GET.get('role', '')
    created_by_filter = request.GET.get('created_by', '')
    is_active = request.GET.get('is_active', '')
    page = request.GET.get('page', 1)
    
    queryset = User.objects.all().select_related('created_by')
    
    if search:
        queryset = queryset.filter(
            Q(username__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search) |
            Q(email__icontains=search)
        )
    
    if role_filter:
        queryset = queryset.filter(role=role_filter)
    
    if created_by_filter:
        queryset = queryset.filter(created_by__username=created_by_filter)
    
    if is_active:
        queryset = queryset.filter(is_active=is_active.lower() == 'true')
    
    paginator = Paginator(queryset, 20)
    users = paginator.get_page(page)
    
    serializer = UserListSerializer(users, many=True)
    
    stats = {
        'total_users': User.objects.count(),
        'active_users': User.objects.filter(is_active=True).count(),
        'users_created_by_me': User.objects.filter(created_by=request.user).count(),
        'recent_users': User.objects.filter(created_by=request.user).count(),
        'users_created_last_7_days': User.objects.filter(
        created_by=request.user,
        date_joined__gte=timezone.now() - timedelta(days=7)).count()
    
    }
    
    print(f"users_created_last_7_days: {stats['users_created_last_7_days']}")
    
    creators = User.objects.filter(
        created_users__isnull=False
    ).distinct().values('username', 'first_name', 'last_name')
    
    return Response({
        'users': serializer.data,
        'pagination': {
            'current_page': users.number,
            'total_pages': users.paginator.num_pages,
            'total_count': users.paginator.count,
            'has_next': users.has_next(),
            'has_previous': users.has_previous()
        },
        'stats': stats,
        'filters': {
            'creators': list(creators),
            'roles': User.ROLES
        }
    })


@api_view(['GET', 'PATCH'])
@permission_classes([IsAuthenticated])
def user_detail(request, user_id):
    
    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return Response(
            {'error': 'Utilisateur non trouvé'}, 
            status=status.HTTP_404_NOT_FOUND
        )
    
    if request.method == 'GET':
        serializer = UserListSerializer(user)
        
        activities = UserActivity.objects.filter(user=user)[:10]  # 10 dernières activités
        activities_serializer = UserActivitySerializer(activities, many=True)
        
        data = serializer.data
        data['activities'] = activities_serializer.data
        
        return Response(data)
    
    elif request.method == 'PATCH':        
        if user == request.user:
            serializer = UserProfileUpdateSerializer(
                user, 
                data=request.data, 
                partial=True,
                context={'ip_address': get_client_ip(request)}
            )
        elif request.user.role in ['mg', 'director']:
            serializer = UserUpdateSerializer(
                user, 
                data=request.data, 
                partial=True,
                context={
                    'performed_by': request.user,
                    'ip_address': get_client_ip(request)
                }
            )
        else:
            return Response(
                {'error': 'Vous n\'avez pas les droits pour modifier cet utilisateur'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def users_stats(request):
    
    if request.user.role not in ['mg', 'director']:
        return Response(
            {'error': 'Accès non autorisé'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    
    now = timezone.now()
    last_30_days = now - timedelta(days=30)
    last_7_days = now - timedelta(days=7)
    
    stats = {
        'total_users': User.objects.count(),
        'active_users': User.objects.filter(is_active=True).count(),
        'users_by_role': dict(
            User.objects.values('role').annotate(
                count=Count('role')
            ).values_list('role', 'count')
        ),
        'users_created_last_30_days': User.objects.filter(
            created_at__gte=last_30_days
        ).count(),
        'users_created_last_7_days': User.objects.filter(
            created_at__gte=last_7_days
        ).count(),
        'users_created_by_me': User.objects.filter(
            created_by=request.user
        ).count(),
        'recent_activities': UserActivitySerializer(
            UserActivity.objects.select_related('user', 'performed_by')[:5],
            many=True
        ).data
    }
    
    return Response(stats)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    """Changer le mot de passe de l'utilisateur connecté"""
    
    serializer = PasswordChangeSerializer(
        data=request.data,
        context={'request': request, 'ip_address': get_client_ip(request)}
    )
    
    if serializer.is_valid():
        try:
            serializer.save()
            return Response(
                {'message': 'Mot de passe modifié avec succès'}, 
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Error changing password for user {request.user.username}: {e}")
            return Response(
                {'error': 'Erreur lors du changement de mot de passe'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def purchase_requests_list(request):
    """Liste des demandes d'achat + Création d'une nouvelle demande"""
    
    if request.method == 'GET':
        user_role = request.user.role
        user_id = request.user.id
        print(repr(settings.FRONTEND_URL))
        
        if user_role == 'employee':
            queryset = PurchaseRequest.objects.filter(user=request.user)
        elif user_role == 'mg':
            queryset = PurchaseRequest.objects.all()
        elif user_role == 'accounting':
            queryset = PurchaseRequest.objects.filter(
                Q(status__in=['mg_approved', 'accounting_reviewed', 'director_approved']) |
                Q(status='rejected', rejected_by_role='accounting') |
                Q(rejected_by=user_id, rejected_by_role='accounting')
            )
        elif user_role == 'director':
            queryset = PurchaseRequest.objects.filter(
                Q(status__in=['accounting_reviewed', 'director_approved']) |
                Q(status='rejected', rejected_by_role='director') |
                Q(rejected_by=user_id, rejected_by_role='director')
            )
        else:
            queryset = PurchaseRequest.objects.none()
        
        queryset = queryset.select_related('user', 'rejected_by').order_by('-created_at')
        
        paginator = PageNumberPagination()
        paginator.page_size = 20
        page = paginator.paginate_queryset(queryset, request)
        
        serializer = PurchaseRequestListSerializer(page, many=True)
        return paginator.get_paginated_response(serializer.data)
    
    elif request.method == 'POST':
        if request.user.role not in ['employee', 'mg']:
            return Response(
                {'error': 'Seuls les employés et les managers peuvent créer des demandes'}, 
                status=status.HTTP_403_FORBIDDEN
            )

        auto_validate_mg = request.data.get('auto_validate_mg', False)
        print(f"Auto-validate MG flag: {auto_validate_mg}, User role: {request.user.role}")
        
        serializer = PurchaseRequestCreateSerializer(data=request.data)
        if serializer.is_valid():
            purchase_request = serializer.save(user=request.user)
            
            if auto_validate_mg and request.user.role == 'mg':
                print(f"Auto-validating request {purchase_request.id} for MG user {request.user.username}")
                
                purchase_request.status = 'mg_approved'
                purchase_request.mg_validated_by = request.user
                purchase_request.mg_validated_at = timezone.now()
                purchase_request.save()
                
                RequestStep.objects.create(
                    request=purchase_request,
                    user=request.user,
                    action='approved',
                    comment="Auto-validé par le créateur (Moyens Généraux)"
                )
                
                print(f"Request {purchase_request.id} auto-validated. New status: {purchase_request.status}")
               
            try:
                
                email_service = EmailService()
                
                if request.user.role == 'mg' and auto_validate_mg:
                    recipients_role = 'accounting'
                    logger.info(f"Envoi de notification à la comptabilité pour la demande #{purchase_request.id} (auto-validée par MG)")
                else:
                    recipients_role = 'mg'
                    logger.info(f"Envoi de notification aux Moyens Généraux pour la demande #{purchase_request.id}")
                
                email_sent = email_service.send_purchase_request_notification(
                    purchase_request=purchase_request,
                    recipients_role=recipients_role
                )
                
                if email_sent:
                    logger.info(f"Notification envoyée avec succès pour la demande #{purchase_request.id}")
                else:
                    logger.warning(f"Échec de l'envoi de notification pour la demande #{purchase_request.id}")
                    
            except Exception as e:
                logger.error(f"Erreur lors de l'envoi de notification pour la demande #{purchase_request.id}: {str(e)}")
         
            detail_serializer = PurchaseRequestDetailSerializer(purchase_request)
            return Response(detail_serializer.data, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def purchase_request_detail(request, pk):
    """Détail d'une demande d'achat"""
    purchase_request = get_object_or_404(PurchaseRequest, pk=pk)
    
    user_role = request.user.role
    
    if user_role == 'employee' and purchase_request.user != request.user:
        return Response(
            {'error': 'Vous ne pouvez voir que vos propres demandes'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = PurchaseRequestDetailSerializer(purchase_request)
    return Response(serializer.data)



@api_view(['POST'])
@permission_classes([IsAuthenticated])
def validate_request(request, pk):
    """Valider ou rejeter une demande selon le rôle"""
    purchase_request = get_object_or_404(PurchaseRequest, pk=pk)
    user_role = request.user.role
    
    action = request.data.get('action')
    comment = request.data.get('comment', '')

    print(f"Action: {action}, Comment: {comment}, User Role: {user_role}")
    print(f"Request Status: {purchase_request.status}")
    print(f"Request data: {request.data}")
    
    can_validate = False
    
    if action == 'reject':
        if user_role == 'mg' and purchase_request.status == 'pending':
            can_validate = True
        elif user_role == 'accounting' and purchase_request.status == 'mg_approved':
            can_validate = True
        elif user_role == 'director' and purchase_request.status == 'accounting_reviewed':
            can_validate = True
    elif action == 'approve':
        if user_role == 'mg' and purchase_request.status == 'pending':
            can_validate = True
        elif user_role == 'accounting' and purchase_request.status == 'mg_approved':
            can_validate = True
        elif user_role == 'director' and purchase_request.status == 'accounting_reviewed':
            can_validate = True
    
    
    
    if not can_validate:
        return Response(
            {'error': f'Vous ne pouvez pas agir sur cette demande à cette étape. Status: {purchase_request.status}, Role: {user_role}'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    serializer = ValidateRequestSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        action = serializer.validated_data['action']
        comment = serializer.validated_data.get('comment', '')
        budget_available = serializer.validated_data.get('budget_available')
        final_cost = serializer.validated_data.get('final_cost')
        
        
        if action == 'reject':
            purchase_request.status = 'rejected'
            purchase_request.rejection_reason = comment
            purchase_request.rejected_by = request.user
            purchase_request.rejected_at = timezone.now()
            purchase_request.rejected_by_role = user_role
            
        else:  
            if user_role == 'mg':
                    purchase_request.status = 'mg_approved'
                    purchase_request.mg_validated_by = request.user  
                    purchase_request.mg_validated_at = timezone.now() 
                    
                    if final_cost:
                        purchase_request.final_cost = final_cost 
            elif user_role == 'accounting':
                    purchase_request.status = 'accounting_reviewed'
                    purchase_request.budget_available = budget_available
                    purchase_request.accounting_validated_by = request.user  
                    purchase_request.accounting_validated_at = timezone.now()
                      
                    if final_cost:
                        purchase_request.final_cost = final_cost
            elif user_role == 'director':
                    purchase_request.status = 'director_approved'
                    purchase_request.approved_by = request.user  
                    purchase_request.approved_at = timezone.now()
        
        purchase_request.save()
        
        RequestStep.objects.create(
            request=purchase_request,
            user=request.user,
            action='approved' if action == 'approve' else 'rejected',
            comment=comment,
            budget_check=budget_available if user_role == 'accounting' else None
        )
        
        detail_serializer = PurchaseRequestDetailSerializer(purchase_request)
        return Response(detail_serializer.data)
    else:
        print(f"Serializer errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_rejection_reason(request, pk):
    """Modifier le motif de refus"""
    purchase_request = get_object_or_404(PurchaseRequest, pk=pk)
    
    if purchase_request.status != 'rejected':
        return Response({'error': 'Cette demande n\'est pas refusée'}, status=400)
    
    if purchase_request.rejected_by != request.user:
        return Response({'error': 'Vous ne pouvez modifier que vos propres refus'}, status=403)
    
    new_comment = request.data.get('comment', '').strip()
    if not new_comment:
        return Response({'error': 'Le commentaire ne peut pas être vide'}, status=400)
    
    purchase_request.rejection_reason = new_comment
    purchase_request.save()
    
    return Response(PurchaseRequestDetailSerializer(purchase_request).data)


from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from django.shortcuts import get_object_or_404
from django.conf import settings
import cloudinary
import cloudinary.uploader
import os
import uuid
import logging
from .models import Attachment, PurchaseRequest
from .serializers import AttachmentSerializer

logger = logging.getLogger(__name__)

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def attachments_list(request):
    """Liste des pièces jointes + Upload d'un nouveau fichier"""
    
    if request.method == 'GET':
        request_id = request.query_params.get('request_id')
        if request_id:
            attachments = Attachment.objects.filter(request_id=request_id)
        else:
            attachments = Attachment.objects.all()
        
        serializer = AttachmentSerializer(attachments, many=True)
        return Response(serializer.data)
    
    elif request.method == 'POST':
        print("=" * 50)
        print("DEBUG - Upload attachment")
        print(f"request.data: {request.data}")
        print(f"request.FILES: {request.FILES}")
        print("=" * 50)

        # DEBUG: Vérifier l'utilisateur authentifié
        print(f"🔐 Utilisateur authentifié: {request.user.username} (ID: {request.user.id})")

        if 'file' not in request.FILES:
            return Response({'error': "Le fichier est requis"}, status=400)
        
        if 'request' not in request.data:
            return Response({'error': "Le champ 'request' est requis"}, status=400)

        uploaded_file = request.FILES['file']

        if uploaded_file.size > 10 * 1024 * 1024:
            return Response({'error': 'Fichier trop volumineux (max 10MB)'}, status=400)

        allowed_types = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg']
        if uploaded_file.content_type not in allowed_types:
            return Response({'error': f"Format non supporté: {uploaded_file.content_type}"}, status=400)

        request_id = request.data.get('request')
        try:
            purchase_request = get_object_or_404(PurchaseRequest, pk=request_id)
        except Exception as e:
            return Response({'error': f"Demande introuvable: {str(e)}"}, status=400)

        # Vérification des permissions d'upload
        can_upload = False
        if (purchase_request.user == request.user and 
            purchase_request.status not in ['rejected', 'director_approved']):
            can_upload = True
        elif (request.user.role == 'mg' and 
            purchase_request.status in ['pending', 'mg_approved']):
            can_upload = True

        if not can_upload:
            return Response({'error': 'Vous ne pouvez pas ajouter de pièce jointe à cette étape'}, status=403)

        try:
            # Vérifier si Cloudinary est configuré
            cloudinary_configured = all([
                getattr(settings, 'CLOUDINARY_CLOUD_NAME', None),
                getattr(settings, 'CLOUDINARY_API_KEY', None), 
                getattr(settings, 'CLOUDINARY_API_SECRET', None)
            ])
            
            if cloudinary_configured:
                # Utiliser Cloudinary
                return handle_cloudinary_upload(request, uploaded_file, purchase_request)
            else:
                # Fallback vers le stockage local
                return handle_local_upload(request, uploaded_file, purchase_request)
                
        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Erreur lors de l'upload: {str(e)}")
            return Response({'error': f'Erreur lors de l\'upload: {str(e)}'}, status=500)


def handle_cloudinary_upload(request, uploaded_file, purchase_request):
    """Gestion de l'upload avec Cloudinary"""
    try:
        # Reconfigurer Cloudinary pour être sûr
        cloudinary.config(
            cloud_name=settings.CLOUDINARY_CLOUD_NAME,
            api_key=settings.CLOUDINARY_API_KEY,
            api_secret=settings.CLOUDINARY_API_SECRET,
            secure=True
        )
        
        # Déterminer le bon resource_type
        content_type = uploaded_file.content_type
        if content_type == 'application/pdf':
            resource_type = 'pdf'
            print("Fichier PDF détecté - utilisation de resource_type: 'pdf'")
        else:
            resource_type = 'auto'
            print("Fichier image détecté - utilisation de resource_type: 'auto'")
        
        print("🔄 Tentative d'upload Cloudinary...")
        
        result = cloudinary.uploader.upload(
            uploaded_file,
            folder='attachments',
            resource_type=resource_type,  # Utiliser le bon type
            access_mode='public',  # S'assurer que le fichier est public
            type='upload'
        )
        
        print(f"Result Upload: {result}")
        print(f"Secure URL File: {result['secure_url']}")
        print(f"Resource Type: {result.get('resource_type', 'unknown')}")
        print(f"Access Mode: {result.get('access_mode', 'non spécifié')}")

        # Déterminer le type de fichier pour la base de données
        if resource_type == 'pdf' or content_type == 'application/pdf':
            file_type = 'pdf'
        else:
            file_type = result.get('format', uploaded_file.content_type.split('/')[-1])

        attachment = Attachment.objects.create(
            file_url=result['secure_url'], 
            file_type=file_type,  
            request=purchase_request,
            uploaded_by=request.user,
            description=request.data.get('description', ''),
          
        )

        logger.info(f"Fichier uploadé avec succès sur Cloudinary: {result['secure_url']}")
        return Response(AttachmentSerializer(attachment).data, status=201)

    except Exception as e:
        logger.error(f"Erreur Cloudinary: {str(e)}")
        # Fallback vers le stockage local en cas d'erreur Cloudinary
        print("Erreur Cloudinary, fallback vers le stockage local...")
        return handle_local_upload(request, uploaded_file, purchase_request)


def handle_local_upload(request, uploaded_file, purchase_request):
    """Gestion de l'upload en stockage local"""
    try:
        request_id = str(purchase_request.id)
        file_type = request.data.get('file_type', 'other')
        description = request.data.get('description', '')
        
        # Créer le dossier de destination
        upload_dir = os.path.join(settings.MEDIA_ROOT, 'attachments', request_id)
        os.makedirs(upload_dir, exist_ok=True)
        
        # Générer un nom de fichier unique
        original_name = uploaded_file.name
        file_extension = os.path.splitext(original_name)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        file_path = os.path.join(upload_dir, unique_filename)
        
        # Sauvegarder le fichier
        with open(file_path, 'wb+') as destination:
            for chunk in uploaded_file.chunks():
                destination.write(chunk)
        
        # URL relative pour le frontend
        relative_url = f"/media/attachments/{request_id}/{unique_filename}"
        
        # Déterminer le type de fichier pour le stockage local
        content_type = uploaded_file.content_type
        if content_type == 'application/pdf':
            file_type_display = 'pdf'
        elif content_type.startswith('image/'):
            file_type_display = content_type.split('/')[1]  # jpeg, png, etc.
        else:
            file_type_display = 'other'
        
        attachment = Attachment.objects.create(
            file_url=relative_url,
            file_type=file_type_display,
            request=purchase_request,
            uploaded_by=request.user,
            description=description
        )
        
        logger.info(f"Fichier uploadé localement: {file_path}")
        print(f"Fichier sauvegardé localement: {file_path}")
        print(f"URL relative: {relative_url}")
        
        return Response(AttachmentSerializer(attachment).data, status=201)
        
    except Exception as e:
        logger.error(f"Erreur upload local: {str(e)}", exc_info=True)
        return Response(
            {'error': f'Échec de l\'upload local: {str(e)}'}, 
            status=500
        )
@api_view(['DELETE'])
@permission_classes([IsAuthenticated])
def attachment_delete(request, pk):
    """Supprimer une pièce jointe"""
    attachment = get_object_or_404(Attachment, pk=pk)
    
    can_delete = False
    
    if (attachment.request.user == request.user and 
        attachment.uploaded_by == request.user and 
        attachment.request.status not in ['rejected', 'director_approved']):
        can_delete = True
    
    elif (request.user.role == 'mg' and 
          attachment.request.status in ['pending', 'mg_approved']):
        can_delete = True
    
    elif request.user.is_staff:
        can_delete = True
    
    if not can_delete:
        return Response(
            {'error': 'Vous ne pouvez pas supprimer cette pièce jointe à cette étape'}, 
            status=status.HTTP_403_FORBIDDEN
        )
    
    attachment.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def dashboard(request):
    """Données pour le tableau de bord avec logique corrigée par rôle"""
    user_role = request.user.role
    user_id = request.user.id
    
    all_requests = PurchaseRequest.objects.select_related('user', 'rejected_by').all()
    
    # def get_period_stats(months_offset=0, user_filter=None):
    #     """Calculer les stats pour une période donnée avec offset et filtre utilisateur optionnel"""
    #     now = timezone.now()
    #     start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    #     start_date = start_date - timedelta(days=30 * months_offset)
        
    #     if months_offset > 0:
    #         end_date = start_date.replace(day=1) + timedelta(days=32)
    #         end_date = end_date.replace(day=1) - timedelta(seconds=1)
    #     else:
    #         end_date = now
            
    #     if user_filter:
    #         period_requests = user_filter.filter(
    #             created_at__gte=start_date,
    #             created_at__lte=end_date
    #         )
    #     else:
    #         period_requests = all_requests.filter(
    #             created_at__gte=start_date,
    #             created_at__lte=end_date
    #         )
    
    def get_period_stats(months_offset=0, user_filter=None):
        now = timezone.now()
        start_date = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - relativedelta(months=months_offset)
        if months_offset > 0:
            end_date = start_date + relativedelta(months=1) - timedelta(seconds=1)
        else:
            end_date = now

        if user_filter:
            period_requests = user_filter.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            )
        else:
            period_requests = all_requests.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            )
            
        logger.info(f"Calculating stats for period: {start_date} to {end_date}")


        
        approved_queryset = period_requests.filter(status='director_approved')
        
        total_amount = approved_queryset.annotate(
            cost_to_use = Case(
            When(final_cost__isnull=False, then=F('final_cost')),  # Priorité au final_cost
            When(final_cost__isnull=True, estimated_cost__isnull=False, then=F('estimated_cost')),
            default=Value(0),
            output_field=DecimalField(max_digits=12, decimal_places=2)
        )
        ).aggregate(total=Sum('cost_to_use'))['total'] or 0
        
        approved_count = approved_queryset.count()
        total_requests = period_requests.count()
        
        
        
        logger.info(f"Total amount {total_amount}")
        logger.info(f"Approved requests count: {approved_count}")
        logger.info(list(approved_queryset.values("id", "final_cost", "estimated_cost")))
        
        
        
        return {
            'total_requests': total_requests,
            'approved_requests': approved_count,
            'in_progress': period_requests.filter(
                status__in=['mg_approved', 'accounting_reviewed']
            ).count(),
            # 'total_amount': approved_requests.aggregate(
            #     total=Sum('estimated_cost')
            # )['total'] or 0,
            'total_amount': total_amount,
            'validation_rate': (
                approved_count / total_requests * 100
                if total_requests > 0 else 0
            )
        }
    
    def calculate_trend(current, previous):
        """Calculer la tendance en pourcentage avec gestion des cas limites"""
        if previous == 0 and current == 0:
            return {'value': 0, 'direction': 'neutral'}
        elif previous == 0:
            return {'value': 100, 'direction': 'up'}
        
        percent_change = ((current - previous) / previous) * 100
        rounded_change = round(percent_change)
        
        if rounded_change == 0 and current != previous:
            rounded_change = 1 if percent_change > 0 else -1
        
        return {
            'value': abs(rounded_change),
            'direction': 'up' if rounded_change > 0 else 'down' if rounded_change < 0 else 'neutral'
        }
    
    def calculate_processing_delays():
        """Calculer les délais moyens de traitement"""
        approved_requests = all_requests.filter(status='director_approved')
        
        if not approved_requests.exists():
            return {
                'average': 0,
                'mg_validation': 0,
                'accounting_review': 0,
                'director_approval': 0
            }
        
        delays = []
        for req in approved_requests:
            if req.updated_at and req.created_at:
                delta = req.updated_at - req.created_at
                delays.append(delta.days)
        
        if delays:
            avg_delay = sum(delays) / len(delays)
            return {
                'average': round(avg_delay, 1),
                'mg_validation': round(avg_delay * 0.3, 1),
                'accounting_review': round(avg_delay * 0.4, 1),
                'director_approval': round(avg_delay * 0.3, 1)
            }
        
        return {
            'average': 0,
            'mg_validation': 0,
            'accounting_review': 0,
            'director_approval': 0
        }
    
    def get_department_stats():
        """Obtenir les statistiques par département avec fallback"""
        try:
            dept_stats = all_requests.values('user__department').annotate(
                count=Count('id')
            ).exclude(user__department__isnull=True).exclude(user__department='').order_by('-count')
            
            result = []
            for stat in dept_stats:
                dept_name = stat.get('user__department') or 'Département inconnu'
                if dept_name and dept_name.strip():
                    result.append({
                        'department': dept_name,
                        'requests_count': stat['count']
                    })
            
            if not result:
                user_stats = all_requests.values('user__first_name', 'user__last_name').annotate(
                    count=Count('id')
                ).order_by('-count')[:5]
                
                for stat in user_stats:
                    full_name = f"{stat['user__first_name'] or ''} {stat['user__last_name'] or ''}".strip()
                    if not full_name:
                        full_name = "Utilisateur inconnu"
                    
                    result.append({
                        'department': full_name,
                        'requests_count': stat['count']
                    })
            
            return result[:5]  
            
        except Exception as e:
            print(f"Erreur dans get_department_stats: {e}")
            return [{
                'department': 'Données indisponibles',
                'requests_count': all_requests.count()
            }]

    
    def get_role_specific_requests(requests, role, user_id):
        """Filtrer les demandes selon le niveau de responsabilité"""
        if role == 'employee':
            return requests.filter(user_id=user_id)
            
        elif role == 'mg':
            return requests.filter(
                Q(status__in=['pending', 'mg_approved', 'accounting_reviewed', 'director_approved']) |
                Q(status='rejected', rejected_by_role='mg')
            )
            
        elif role == 'accounting':
            return requests.filter(
                Q(status__in=['mg_approved', 'accounting_reviewed', 'director_approved']) |
                Q(status='rejected', rejected_by_role='accounting')
            )
            
        elif role == 'director':
            return requests.filter(
                Q(status__in=['accounting_reviewed', 'director_approved']) |
                Q(status='rejected', rejected_by_role='director')
            )
        
        return requests.none()
    
    
    
    if user_role == 'employee':
        user_requests = all_requests.filter(user_id=user_id)
        
        current_period = get_period_stats(0, user_requests)
        previous_period = get_period_stats(1, user_requests)
        
        data = {
            'total_requests': user_requests.count(),
            'pending_requests': user_requests.filter(status='pending').count(),
            'in_progress_requests': user_requests.filter(
                status__in=['mg_approved', 'accounting_reviewed']
            ).count(),
            'approved_requests': user_requests.filter(status='director_approved').count(),
            'rejected_requests': user_requests.filter(status='rejected').count(),
            
            'trends': {
                'requests': calculate_trend(
                    current_period['total_requests'], 
                    previous_period['total_requests']
                ),
                'approved': calculate_trend(
                    current_period['approved_requests'], 
                    previous_period['approved_requests']
                )
            },
            
            'recent_requests': PurchaseRequestListSerializer(
                user_requests.order_by('-created_at')[:10], many=True
            ).data,
            'all_requests': PurchaseRequestListSerializer(
                user_requests.order_by('-created_at'), many=True
            ).data,
            
            'current_period_stats': current_period,
            'previous_period_stats': previous_period,
        }
        
    elif user_role == 'mg':
        mg_requests = get_role_specific_requests(all_requests, 'mg', user_id)
        
        mes_demandes = mg_requests.count()  
        en_cours = all_requests.filter(status='pending').count()  
        acceptees = mg_requests.filter(
            Q(status__in=['mg_approved', 'accounting_reviewed', 'director_approved'])
        ).count()  
        refusees = mg_requests.filter(
            status='rejected', rejected_by_role='mg'
        ).count()  
        
        current_period = get_period_stats(0, mg_requests)
        previous_period = get_period_stats(1, mg_requests)
        
        global_current_period = get_period_stats(0)  
        global_previous_period = get_period_stats(1)  
        
        data = {
            'mes_demandes': mes_demandes,
            'en_cours': en_cours,
            'acceptees': acceptees,
            'refusees': refusees,
            
            'total_requests': all_requests.count(),
            'in_progress_requests': all_requests.filter(
                status__in=['pending', 'mg_approved', 'accounting_reviewed']
            ).count(),
            'approved_requests': all_requests.filter(status='director_approved').count(),
            'rejected_requests': all_requests.filter(status='rejected').count(),
            
            'recent_requests': PurchaseRequestListSerializer(
                mg_requests.order_by('-created_at')[:10], many=True
            ).data,
            
            'all_requests': PurchaseRequestListSerializer(
                all_requests.order_by('-created_at'), many=True
            ).data,
            
            'trends': {
                'requests': calculate_trend(
                    current_period['total_requests'],
                    previous_period['total_requests']
                ),
                'approved': calculate_trend(
                    current_period['approved_requests'],
                    previous_period['approved_requests']
                ),
                'amount': calculate_trend(
                    global_current_period['total_amount'],
                    global_previous_period['total_amount']
                )
            },
            
            'current_period_stats': current_period,
            'previous_period_stats': previous_period,
            
            'validation_rate': round(global_current_period['validation_rate']),
            'processing_delays': calculate_processing_delays(),
            'department_stats': get_department_stats(),
        }
        
    elif user_role == 'accounting':
        accounting_requests = get_role_specific_requests(all_requests, 'accounting', user_id)
        
        mes_demandes = accounting_requests.count()  
        en_cours = all_requests.filter(status='mg_approved').count()  
        acceptees = accounting_requests.filter(
            Q(status__in=['accounting_reviewed', 'director_approved'])
        ).count()  
        refusees = accounting_requests.filter(
            status='rejected', rejected_by_role='accounting'
        ).count()  
        
        current_period = get_period_stats(0, accounting_requests)
        previous_period = get_period_stats(1, accounting_requests)
        
        data = {
            'mes_demandes': mes_demandes,
            'en_cours': en_cours, 
            'acceptees': acceptees,
            'refusees': refusees,
            
            'trends': {
                'requests': calculate_trend(
                    current_period['total_requests'],
                    previous_period['total_requests']
                ),
                'approved': calculate_trend(
                    current_period['approved_requests'],
                    previous_period['approved_requests']
                )
            },
            
            'recent_requests': PurchaseRequestListSerializer(
                accounting_requests.order_by('-created_at')[:10], many=True
            ).data,
            'all_requests': PurchaseRequestListSerializer(
                accounting_requests.order_by('-created_at'), many=True
            ).data,
            
            'current_period_stats': current_period,
            'previous_period_stats': previous_period,
        }
        
    elif user_role == 'director':
        director_requests = get_role_specific_requests(all_requests, 'director', user_id)
        
        mes_demandes = director_requests.count()  
        en_cours = all_requests.filter(status='accounting_reviewed').count()  
        acceptees = director_requests.filter(status='director_approved').count()  
        refusees = director_requests.filter(
            status='rejected', rejected_by_role='director'
        ).count()  
        
        current_period = get_period_stats(0, director_requests)  
        previous_period = get_period_stats(1, director_requests)
        
        data = {
            'mes_demandes': mes_demandes,
            'en_cours': en_cours,
            'acceptees': acceptees,
            'refusees': refusees,
            
            'total_requests': all_requests.count(),
            'in_progress_requests': all_requests.filter(
                status__in=['pending', 'mg_approved', 'accounting_reviewed']
            ).count(),
            'approved_requests': all_requests.filter(status='director_approved').count(),
            'rejected_requests': all_requests.filter(status='rejected').count(),

            
            'recent_requests': PurchaseRequestListSerializer(
                director_requests.order_by('-created_at')[:10], many=True
            ).data,

            'all_requests': PurchaseRequestListSerializer(
                all_requests.order_by('-created_at'), many=True
            ).data,
            
            'current_period_stats': current_period,
            'previous_period_stats': previous_period,
            
            'validation_rate': round(current_period['validation_rate']),
            'processing_delays': calculate_processing_delays(),
            'department_stats': get_department_stats(),

            'trends': {
                'requests': calculate_trend(
                    current_period['total_requests'], 
                    previous_period['total_requests']
                ),
                'approved': calculate_trend(
                    current_period['approved_requests'], 
                    previous_period['approved_requests']
                ),
                'amount': calculate_trend(
                    current_period['total_amount'], 
                    previous_period['total_amount']
                )
            },
        }

    else:
        data = {
            'mes_demandes': 0,
            'en_cours': 0,
            'acceptees': 0,
            'refusees': 0,
            'recent_requests': [],
            'all_requests': [],
            'trends': {},
            'current_period_stats': {'total_requests': 0, 'approved_requests': 0, 'total_amount': 0},
            'previous_period_stats': {'total_requests': 0, 'approved_requests': 0, 'total_amount': 0}
        }
    
    data['user_requests_count'] = all_requests.filter(user=request.user).count()
    data['processing_delays'] = calculate_processing_delays()
    data['department_stats'] = get_department_stats()
    
    def get_monthly_stats():
        """Calculer les statistiques mensuelles des 6 derniers mois"""
        monthly_stats = []
        for i in range(6):
            date = timezone.now() - timedelta(days=30*i)
            month_start = date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(seconds=1)
            
            if user_role == 'employee':
                month_count = all_requests.filter(
                    user=request.user,
                    created_at__gte=month_start,
                    created_at__lte=month_end
                ).count()
            else:
                month_count = all_requests.filter(
                    created_at__gte=month_start,
                    created_at__lte=month_end
                ).count()
            
            monthly_stats.append({
                'month': date.strftime('%B %Y'),
                'count': month_count
            })
        
        monthly_stats.reverse()
        return monthly_stats
    
    data['monthly_stats'] = get_monthly_stats()
    
    if user_role == 'employee':
        user_requests = all_requests.filter(user=request.user)
        requests_by_status = {
            'pending': user_requests.filter(status='pending').count(),
            'mg_approved': user_requests.filter(status='mg_approved').count(),
            'accounting_reviewed': user_requests.filter(status='accounting_reviewed').count(),
            'director_approved': user_requests.filter(status='director_approved').count(),
            'rejected': user_requests.filter(status='rejected').count()
        }
    else:
        requests_by_status = {
            'pending': all_requests.filter(status='pending').count(),
            'mg_approved': all_requests.filter(status='mg_approved').count(),
            'accounting_reviewed': all_requests.filter(status='accounting_reviewed').count(),
            'director_approved': all_requests.filter(status='director_approved').count(),
            'rejected': all_requests.filter(status='rejected').count()
        }
    
    data['requests_by_status'] = requests_by_status
    
    print(f"Dashboard data for {user_role} (ID: {user_id}):")
    print(f"Total requests: {data.get('total_requests', data.get('mes_demandes', 0))}")
    print(f"Department stats: {data.get('department_stats', [])}")
    if 'trends' in data:
        print(f"Trends data: {data['trends']}")
    if user_role == 'mg':
        print(f"Mes demandes: {data.get('mes_demandes', 0)}")
        print(f"En cours: {data.get('en_cours', 0)}")
        print(f"Acceptées: {data.get('acceptees', 0)}")
        print(f"Refusées: {data.get('refusees', 0)}")
    elif user_role == 'accounting':
        print(f"Mes demandes: {data.get('mes_demandes', 0)}")
        print(f"En cours: {data.get('en_cours', 0)}")  
        print(f"Acceptées: {data.get('acceptees', 0)}")
        print(f"Refusées: {data.get('refusees', 0)}")
    elif user_role == 'director':
        print(f"Mes demandes: {data.get('mes_demandes', 0)}")
        print(f"En cours: {data.get('en_cours', 0)}")
        print(f"Acceptées: {data.get('acceptees', 0)}")  
        print(f"Refusées: {data.get('refusees', 0)}")
    
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def debug_auth(request):
    """Vue de debug pour tester l'authentification"""
    
    debug_info = {
        'user': {
            'id': request.user.id,
            'username': request.user.username,
            'email': request.user.email,
            'is_authenticated': request.user.is_authenticated,
        },
        'cookies_received': dict(request.COOKIES),
        'headers': {
            'authorization': request.META.get('HTTP_AUTHORIZATION', 'Non trouvé'),
            'user_agent': request.META.get('HTTP_USER_AGENT', 'Non trouvé'),
        },
        'method': request.method,
        'path': request.path,
    }
    
    print("=== DEBUG AUTH ===")
    print(f"User: {request.user}")
    print(f"Cookies: {request.COOKIES}")
    print(f"Authorization header: {request.META.get('HTTP_AUTHORIZATION')}")
    print("==================")
    
    return Response(debug_info, status=status.HTTP_200_OK)

from rest_framework_simplejwt.tokens import UntypedToken
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError

@api_view(['GET'])
@permission_classes([AllowAny])  
def test_cookies(request):
    """Vue de test pour diagnostiquer les cookies"""
    
    cookies = dict(request.COOKIES)
    access_token = request.COOKIES.get('access_token')
    refresh_token = request.COOKIES.get('refresh_token')
    
    result = {
        'cookies_count': len(cookies),
        'all_cookies': cookies,
        'has_access_token': bool(access_token),
        'has_refresh_token': bool(refresh_token),
        'authorization_header': request.META.get('HTTP_AUTHORIZATION', 'Absent'),
        'user_agent': request.META.get('HTTP_USER_AGENT', 'Non trouvé'),
        'host': request.META.get('HTTP_HOST', 'Non trouvé'),
        'origin': request.META.get('HTTP_ORIGIN', 'Non trouvé'),
        'referer': request.META.get('HTTP_REFERER', 'Non trouvé'),
    }
    
    if access_token:
        try:
            validated_token = UntypedToken(access_token)
            user_id = validated_token.get('user_id')
            user = User.objects.get(id=user_id)
            
            result['token_valid'] = True
            result['token_user'] = {
                'id': user.id,
                'username': user.username,
                'email': user.email
            }
            result['token_claims'] = dict(validated_token.payload)
            
        except (TokenError, InvalidToken, User.DoesNotExist) as e:
            result['token_valid'] = False
            result['token_error'] = str(e)
            result['access_token_preview'] = access_token[:50] + "..." if len(access_token) > 50 else access_token
    else:
        result['token_valid'] = False
        result['token_error'] = "Pas de token access_token dans les cookies"
    
    print("=== TEST COOKIES ===")
    print(f"Cookies reçus: {cookies}")
    print(f"Access token présent: {bool(access_token)}")
    print(f"Refresh token présent: {bool(refresh_token)}")
    if access_token:
        print(f"Access token (50 premiers chars): {access_token[:50]}...")
    print("====================")
    
    return Response(result, status=status.HTTP_200_OK)

@api_view(['GET'])
@permission_classes([AllowAny])
def test_auth_simple(request):
    """Test simple d'authentification"""
    
    access_token = request.COOKIES.get('access_token')
    
    if not access_token:
        return Response({
            'authenticated': False,
            'error': 'Pas de token dans les cookies',
            'cookies': dict(request.COOKIES)
        })
    
    try:
        from rest_framework_simplejwt.tokens import UntypedToken
        validated_token = UntypedToken(access_token)
        user_id = validated_token.get('user_id')
        user = User.objects.get(id=user_id)
        
        return Response({
            'authenticated': True,
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name
            }
        })
        
    except Exception as e:
        return Response({
            'authenticated': False,
            'error': str(e),
            'token_preview': access_token[:50] + "..."
        })

@api_view(['GET'])
@permission_classes([AllowAny])
def test_set_cookie(request):
    """Vue de test pour vérifier si les cookies peuvent être définis"""
    
    response = Response({
        'message': 'Test cookie set',
        'timestamp': str(request.META.get('HTTP_HOST', 'unknown')),
        'origin': request.META.get('HTTP_ORIGIN', 'No origin'),
        'user_agent': request.META.get('HTTP_USER_AGENT', 'No user agent')[:100],
    })
    
    response.set_cookie(
        'test_cookie_simple',
        'simple_value',
        max_age=300
    )
    
    response.set_cookie(
        'test_cookie_httponly',
        'httponly_value',
        max_age=300,
        httponly=True
    )
    
    response.set_cookie(
        'test_cookie_full',
        'full_config_value',
        max_age=300,
        httponly=True,
        secure=False,
        samesite='Lax',
        path='/'
    )
    
    print("=== TEST SET COOKIE ===")
    print(f"Origin: {request.META.get('HTTP_ORIGIN', 'None')}")
    print(f"Host: {request.META.get('HTTP_HOST', 'None')}")
    print(f"User-Agent: {request.META.get('HTTP_USER_AGENT', 'None')[:50]}...")
    print("Cookies de test définis")
    print("=======================")
    
    return response

@api_view(['GET'])
@permission_classes([AllowAny])
def test_get_cookies(request):
    """Vue pour lire les cookies reçus"""
    
    cookies = dict(request.COOKIES)
    
    print("=== TEST GET COOKIES ===")
    print(f"Cookies reçus: {cookies}")
    print("========================")
    
    return Response({
        'cookies_received': cookies,
        'cookies_count': len(cookies),
        'has_test_cookies': {
            'simple': 'test_cookie_simple' in cookies,
            'httponly': 'test_cookie_httponly' in cookies,
            'full': 'test_cookie_full' in cookies,
        }
    })
