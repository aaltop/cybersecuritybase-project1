from django.db.models import Model
from django.http import Http404, HttpResponseServerError

from typing import Protocol
import logging

from ..exceptions import Never

logger = logging.getLogger(__name__)


class Handler[T](Protocol):
    def __call__(self, model: type[Model], get_kwargs: dict) -> T: ...


def handle_does_not_exist(model: type[Model], get_kwargs: dict):
    # could expose too much information in the kwargs?
    logger.info(
        "Single model %s not found using .get with kwargs %s" % (model, get_kwargs)
    )
    return Http404()


def handle_multiple_objects_returned(model: type[Model], get_kwargs: dict):
    # either wrong fields were used to get (ones which are not guaranteed composite unique)
    # or there is somehow more than one item that matches the fields
    # either way, this is at the very least a concern
    logger.warning(
        "Multiple models %s found during .get with kwargs %s" % (model, get_kwargs)
    )
    return HttpResponseServerError()


def get_or_handle_exception[dne_T, mor_T](
    model: type[Model],
    get_kwargs: dict,
    *,
    dne_handler: Handler[dne_T] = handle_does_not_exist,
    mor_handler: Handler[mor_T] = handle_multiple_objects_returned,
):
    """
    Given a django model `model`, try to `.get()` an instance, passing `get_kwargs`
    to `.get()`.
    If no object is found, return the result of `dne_handler`. If multiple
    are found, return the result of `mor_handler`. Both take `model` and
    `get_kwargs`. By default, the handlers return relevant HTTP responses.

    """
    try:
        obj = model.objects.get(**get_kwargs)
        return obj
    except (model.DoesNotExist, model.MultipleObjectsReturned) as exc:
        match type(exc):
            case model.DoesNotExist:
                return dne_handler(model, get_kwargs)
            case model.MultipleObjectsReturned:
                return mor_handler(model, get_kwargs)
            case _:
                raise Never()
