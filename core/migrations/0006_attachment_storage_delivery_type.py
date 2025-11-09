from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0005_alter_attachment_file_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="attachment",
            name="storage_delivery_type",
            field=models.CharField(blank=True, max_length=20, null=True),
        ),
    ]
