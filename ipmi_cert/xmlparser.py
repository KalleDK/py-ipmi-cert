import typing
import xml.etree.ElementTree as ET
from types import NoneType, UnionType
from typing import TYPE_CHECKING, Any, Mapping, Self

import pydantic
import pydantic.fields

if TYPE_CHECKING:
    from lxml.etree import _Element as Element
else:
    Element = object


# region XML parsing


class XMLDict(dict[str, Any]):
    attrib: dict[str, str]
    children: dict[str, list[ET.Element]]

    def __init__(self, attrib: dict[str, str], children: dict[str, list[ET.Element]]):
        self.attrib = attrib
        self.children = children
        super().__init__()


def xml_to_dict(element: ET.Element) -> XMLDict:
    children: dict[str, list[ET.Element]] = {}
    for child in element:
        children.setdefault(child.tag, []).append(child)

    return XMLDict(
        attrib=element.attrib,
        children=children,
    )


def to_one(items: list[ET.Element], is_list: bool) -> Any:
    if not is_list and len(items) == 1:
        return xml_to_dict(items[0])
    return [xml_to_dict(item) for item in items]


def _is_list_type(field: Any) -> bool:
    origin = typing.get_origin(field)
    if origin is UnionType:
        args = typing.get_args(field)
        args = [arg for arg in args if arg is not NoneType]
        return any(_is_list_type(arg) for arg in args)

    return origin is list


def is_list_type(field: pydantic.fields.FieldInfo) -> bool:
    return _is_list_type(field.annotation)


def to_pyd_dict(
    value: XMLDict, info: pydantic.ValidationInfo, fields: dict[str, pydantic.fields.FieldInfo]
) -> dict[str, Any]:
    allow_field_name = False if info.config is None else info.config.get("populate_by_name", False)
    result = {}
    if allow_field_name:
        lower_attribs = {k.lower(): v for k, v in value.attrib.items()}
        lower_children = {k.lower(): v for k, v in value.children.items()}
    else:
        lower_attribs = {}
        lower_children = {}

    for name, field in fields.items():
        is_list = is_list_type(field)
        if allow_field_name and name in value.attrib:
            result[name] = value.attrib[name]
        elif allow_field_name and name in lower_attribs:
            result[name] = lower_attribs[name]
        elif field.validation_alias in value.attrib:
            result[field.validation_alias] = value.attrib[field.validation_alias]
        elif field.alias in value.attrib:
            result[field.alias] = value.attrib[field.alias]
        elif allow_field_name and name in value.children:
            result[name] = to_one(value.children[name], is_list)
        elif allow_field_name and name in lower_children:
            result[name] = to_one(lower_children[name], is_list)
        elif field.validation_alias in value.children:
            result[field.validation_alias] = to_one(value.children[field.validation_alias], is_list)
        elif field.alias in value.children:
            result[field.alias] = to_one(value.children[field.alias], is_list)
    return result


# endregion


class BaseXML(pydantic.BaseModel):
    model_config = pydantic.ConfigDict(populate_by_name=True)

    @pydantic.model_validator(mode="before")
    @classmethod
    def _from_xml(cls, value: Mapping[str, Any] | XMLDict, info: pydantic.ValidationInfo):
        if isinstance(value, XMLDict):
            return to_pyd_dict(value, info, cls.model_fields)
        return value

    @classmethod
    def model_validate_xml(
        cls,
        obj: str,
        *,
        strict: bool | None = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
    ) -> Self:
        return cls.model_validate(
            xml_to_dict(ET.fromstring(obj)), strict=strict, from_attributes=from_attributes, context=context
        )
