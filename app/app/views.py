from django.shortcuts import render, redirect
from django.http import (
    HttpResponse,
    JsonResponse,
    HttpRequest,
)
from django.urls import reverse

from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth import logout as django_logout

import app.models as models
import app.model_forms as model_forms
from utils.django import get_or_handle_exception

import logging

logger = logging.getLogger(__name__)

# Create your views here.


def _create_invalid_method_response():
    # could technically be 405, but don't know exactly whether
    # the case will be a recognised method
    return JsonResponse(data=dict(error="Invalid method"), status=400)


@login_required
def index(request):
    notes = request.user.note_set.all()

    context = dict(notes=notes, form=model_forms.NoteForm())
    return render(request, "app/index.html", context)


@login_required
def create_note(request: HttpRequest):
    match request.method:
        case "POST":
            text = request.POST.get("text", None)
            if text is None:
                return JsonResponse(data=dict(error="text is required"), status=400)
            note_form = model_forms.NoteForm(dict(text=text))
            note_form.full_clean()
            if note_form.errors:
                return render(request, reverse("app:index"), dict(form=note_form))

            request.user.note_set.create(text=text)
            return redirect(reverse("app:index"))

        case _:
            return _create_invalid_method_response()


@login_required
def delete_note(request: HttpRequest, pk):

    # this is for allowing a delete note form to be submitted
    # from different locations (for example), and for then allowing
    # different redirect locations. Mainly prevents using
    # a different port as Django already prevents a number of problems
    allowed_redirects = ("/",)

    match request.method:
        case "POST":
            possible_model = get_or_handle_exception(
                models.Note, dict(pk=pk, user=request.user)
            )
            if not isinstance(possible_model, models.Note):
                return possible_model
            else:
                possible_model.delete()
                redirect_to = request.POST.get("next", False)
                if not (redirect_to and redirect_to in allowed_redirects):
                    return redirect(reverse("app:index"))
                else:
                    return redirect(request.build_absolute_uri(redirect_to))
        case _:
            return _create_invalid_method_response()


# TODO: see FormView?
def signup(request):
    match request.method:
        case "GET":
            context = dict(form=UserCreationForm())
            return render(request, "app/signup.html", context)
        case "POST":
            username = request.POST.get("username", None)
            password1 = request.POST.get("password1", None)
            password2 = request.POST.get("password2", None)
            if username is None or password1 is None or password2 is None:
                return HttpResponse(status=400, reason="username and password required")

            user_data = dict(
                username=username, password1=password1, password2=password2
            )
            form = UserCreationForm(user_data)
            form.full_clean()
            if form.errors:
                return render(request, "app/signup.html", dict(form=form))
            form.save()
            return redirect(reverse("app:index"))
        case _:
            return _create_invalid_method_response()


def logout(request):
    django_logout(request)
    return redirect(reverse("app:index"))
