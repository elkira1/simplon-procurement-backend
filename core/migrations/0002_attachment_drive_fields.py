from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='attachment',
            name='drive_file_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='attachment',
            name='file_size',
            field=models.BigIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='attachment',
            name='mime_type',
            field=models.CharField(blank=True, max_length=120, null=True),
        ),
    ]
