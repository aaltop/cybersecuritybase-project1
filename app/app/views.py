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

from django.core.cache import cache

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
def index(request: HttpRequest):
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


# FLAW: Security Logging and Monitoring Failures AND Identification and Authentication Failures
# ---------------------------------------------------------------------------------------------
# Security Logging and Monitoring Failures:
# Difference is whether login attempts, successful or not, are logged.
# Important for potentially tracing malicious activity, for example.
#
# Identification and Authentication Failures:
# Difference is the use of brute force prevention. The brute force
# prevention functionality is facilitated by the BruteForcePrevention
# class, but the login function gives a good idea of how it works.
# NOTE: the settings for the BruteForcePrevention class are
# a little silly, but it's like that for testing purposes. Not very
# fun to test if it needs ten attempts at first, then requires
# waiting for ten minutes.


# PROPER VERSION
# --------------


# class BruteForcePrevention:

#     def __init__(self, request: HttpRequest):
#         self.ip = request.META["REMOTE_ADDR"]
#         self.key = f"login_attempts:{self.ip}"
#         self.timeout = 20
#         self.attempt_threshold = 1

#     @property
#     def attempts(self) -> int:
#         return cache.get(self.key, 0)

#     def increment_attempts(self):
#         cache.set(self.key, self.attempts + 1, timeout=self.timeout)

#     def is_too_many(self):
#         """
#         Whether the number of attempts exceeds the threshold.
#         """
#         return self.attempts > self.attempt_threshold

#     def test_and_increment(self):
#         """
#         Test whether the number is too many, and if not, increment.
#         Return the result of the test.
#         """
#         is_too_many = self.is_too_many()
#         if is_too_many:
#             return is_too_many
#         else:
#             self.increment_attempts()
#             return is_too_many

#     def clear_cache(self):
#         return cache.delete(self.key)


# def login(request: HttpRequest):

#     login_view = auth_views.LoginView.as_view(template_name="app/login.html")
#     match request.method:
#         case "GET":
#             return login_view(request)
#         case "POST":

#             username = request.POST.get("username", None)
#             if username is None:
#                 return _create_json_error_response("username is required", 400)

#             # test the form first, because it returns 200 regardless otherwise
#             form_params = dict(
#                 username=username, password=request.POST.get("password", None)
#             )
#             auth_form = auth_views.LoginView.form_class(data=form_params)
#             auth_form.full_clean()
#             ip = request.META["REMOTE_ADDR"]
#             brute_force_prevention = BruteForcePrevention(request)
#             if auth_form.is_valid():
#                 logger.info("Successful login for user %s from %s", username, ip)
#             else:
#                 login_attempts = request.session.get("login_attempts", 0)
#                 login_attempts += 1
#                 request.session["login_attempts"] = login_attempts
#                 logger.warning(
#                     "Unsuccessful login attempt for user %s from %s, %s attempts",
#                     username,
#                     ip,
#                     login_attempts,
#                 )
#                 if brute_force_prevention.test_and_increment():
#                     logger.warning("Too many login attempts from %s", ip)
#                     return HttpResponse(
#                         "Too many login attempts. Try again later.", status=429
#                     )

#             return login_view(request)
#         case _:
#             return _create_invalid_method_response()


# PROPER VERSION
# ==============


# FLAWED VERSION
# --------------


def login(request: HttpRequest):

    login_view = auth_views.LoginView.as_view(template_name="app/login.html")
    return login_view(request)


# FLAWED VERSION
# ==============


# FLAW: Security Logging and Monitoring Failures AND Identification and Authentication Failures
# =============================================================================================


def logout(request):
    django_logout(request)
    return redirect(reverse("app:index"))
