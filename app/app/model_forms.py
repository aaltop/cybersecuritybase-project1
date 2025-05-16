from django.forms import ModelForm
import app.models as models


class NoteForm(ModelForm):
    class Meta:
        model = models.Note
        fields = ["text"]
