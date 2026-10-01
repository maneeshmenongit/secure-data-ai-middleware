import sys

import pytest

from datasec.errors import DataSecError
from datasec.presidio import PresidioRedactor


def test_missing_libraries_is_a_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "presidio_analyzer", None)
    with pytest.raises(DataSecError, match="datasec\\[presidio\\]"):
        PresidioRedactor()


def test_missing_model_is_a_clear_error():
    with pytest.raises(DataSecError, match="spacy download"):
        PresidioRedactor(model="xx_no_such_model_sm")


def test_entities_as_bare_string_rejected():
    with pytest.raises(TypeError):
        PresidioRedactor(entities="PERSON")
