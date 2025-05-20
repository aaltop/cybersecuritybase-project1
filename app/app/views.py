from django.shortcuts import render, redirect
from django.http import (
    HttpResponse,
    JsonResponse,
    HttpRequest,
    Http404,
)
from django.urls import reverse

from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import logout as django_logout
from django.contrib.auth import views as auth_views

import app.models as models
import app.model_forms as model_forms
from utils.django.models import get_or_handle_exception

import logging

logger = logging.getLogger(__name__)

# Create your views here.


def _create_json_error_response(reason: str, status):
    return JsonResponse(data=dict(reason=reason), status=status)


def _create_invalid_method_response():
    # could technically be 405, but don't know exactly whether
    # the case will be a recognised method
    return _create_json_error_response("Invalid method", 400)


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

# FLAW: Broken Access Control
# ---------------------------
# Here, the only difference is supplying the logged-in user to the
# object fetching method. In both cases, a user needs to be logged in,
# but only in the proper case is the object matched to the logged-in
# user. As a result, it is possible to delete other user's note by,
# for example, changing the delete's action to point to some other
# resource in the browser. See `get_kwargs` in both versions for
# the difference.

# PROPER VERSION
# --------------


# @login_required
# def delete_note(request: HttpRequest, pk):

#     # this is for allowing a delete note form to be submitted
#     # from different locations (for example), and for then allowing
#     # different redirect locations. Mainly prevents using
#     # a different port as Django already prevents a number of problems
#     allowed_redirects = ("/",)

#     match request.method:
#         case "POST":
#             # so, this will return 404 if it can't match the pk AND
#             # user, even though the resource may exist.
#             # However, using 403 might unnecessarily give away information,
#             # which this does not: don't let unauthorised users even
#             # know about the existence of certain resources.
#             get_kwargs = dict(pk=pk, user=request.user)
#             possible_model = get_or_handle_exception(models.Note, get_kwargs)
#             if not isinstance(possible_model, models.Note):
#                 # seriously, why is it an exception?
#                 if type(possible_model) is Http404:
#                     raise possible_model
#                 return possible_model
#             else:
#                 possible_model.delete()
#                 redirect_to = request.POST.get("next", False)
#                 if not (redirect_to and redirect_to in allowed_redirects):
#                     return redirect(reverse("app:index"))
#                 else:
#                     return redirect(request.build_absolute_uri(redirect_to))
#         case _:
#             return _create_invalid_method_response()


# PROPER VERSION
# ==============


# FLAWED VERSION
# --------------


@login_required
def delete_note(request: HttpRequest, pk):

    # this is for allowing a delete note form to be submitted
    # from different locations (for example), and for then allowing
    # different redirect locations. Mainly prevents using
    # a different port as Django already prevents a number of problems
    allowed_redirects = ("/",)

    match request.method:
        case "POST":
            get_kwargs = dict(pk=pk)
            possible_model = get_or_handle_exception(models.Note, get_kwargs)
            if not isinstance(possible_model, models.Note):
                # seriously, why is it an exception?
                if type(possible_model) is Http404:
                    raise possible_model
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


# FLAWED VERSION
# ==============


# FLAW: Broken Access Control
# ===========================

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


# FLAW: Security Logging and Monitoring Failures
# ----------------------------------------------
# Difference is whether login attempts, successful or not, are logged.
# Important for potentially tracing malicious activity, for example.


# PROPER VERSION
# --------------

# def login(request):

#     login_view = auth_views.LoginView.as_view(template_name="app/login.html")
#     match request.method:
#         case "GET":
#             return login_view(request)
#         case "POST":
#             username = request.POST.get("username", None)
#             if username is None:
#                 return _create_json_error_response("username is required", 400)
#             logger.info("Login attempt for user %s" % username)

#             # test first, because it returns 200 regardless otherwise
#             form_params = dict(
#                 username=username, password=request.POST.get("password", None)
#             )
#             auth_form = auth_views.LoginView.form_class(data=form_params)
#             response = login_view(request)
#             auth_form.full_clean()
#             if auth_form.is_valid():
#                 logger.info("Successful login for user %s" % username)
#             else:
#                 logger.warning("Unsuccessful login for user %s" % username)

#             return response
#         case _:
#             return _create_invalid_method_response()

# PROPER VERSION
# ==============


# FLAWED VERSION
# --------------

def login(request):

    login_view = auth_views.LoginView.as_view(template_name="app/login.html")
    return login_view(request)

# FLAWED VERSION
# ==============


# FLAW: Security Logging and Monitoring Failures
# ----------------------------------------------


def logout(request):
    django_logout(request)
    return redirect(reverse("app:index"))
