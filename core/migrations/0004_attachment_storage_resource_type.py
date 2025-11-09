from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_rename_drive_file_id_attachment_storage_public_id"),
    ]

    operations = [
        migrations.AddField(
            model_name="attachment",
            name="storage_resource_type",
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]
