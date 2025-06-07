from django.db import models
import os

class Signature(models.Model):
    signer_name = models.CharField(max_length=255)
    document_path = models.CharField(max_length=255)
    signature_data = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Signature by {self.signer_name} on {os.path.basename(self.document_path)}"

class KeyPair(models.Model):
    signer_name = models.CharField(max_length=255, unique=True)
    public_key_file = models.CharField(max_length=255)
    private_key_file = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Key pair for {self.signer_name}"
