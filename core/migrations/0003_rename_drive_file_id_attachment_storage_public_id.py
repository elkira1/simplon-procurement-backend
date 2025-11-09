from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_attachment_drive_fields'),
    ]

    operations = [
        migrations.RenameField(
            model_name='attachment',
            old_name='drive_file_id',
            new_name='storage_public_id',
        ),
    ]
