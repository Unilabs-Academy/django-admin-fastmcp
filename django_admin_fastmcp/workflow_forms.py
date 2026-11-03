"""Describe native HTML forms without returning scripts, cookies or CSRF tokens."""

from html.parser import HTMLParser

from django_admin_fastmcp import exposure


class AdminPage(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.links = []
        self.title = ""
        self._title = False
        self.form = None
        self.field = None
        self.option = None
        self.link = None
        self.textarea = False
        self.ignore = 0
        self.errors = []
        self.error_depth = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in {"script", "style"}:
            self.ignore += 1
        if self.ignore:
            return
        if self.error_depth and tag not in {"input", "br", "img", "hr", "meta", "link"}:
            self.error_depth += 1
        elif "errorlist" in a.get("class", "").split() or "errornote" in a.get("class", "").split():
            self.error_depth = 1
        if tag == "title":
            self._title = True
        if tag == "a" and a.get("href"):
            self.link = {"url": a["href"], "label": ""}
            self.links.append(self.link)
        if tag == "form":
            self.form = {
                "action": a.get("action", ""),
                "method": a.get("method", "get").lower(),
                "id": a.get("id", ""),
                "fields": [],
            }
            self.forms.append(self.form)
        if (
            self.form is not None
            and tag in {"input", "select", "textarea", "button"}
            and a.get("name")
        ):
            self.field = {
                "name": a["name"],
                "type": a.get("type", "submit" if tag == "button" else tag),
                "required": "required" in a,
                "disabled": "disabled" in a,
                "value": a.get("value", "on" if a.get("type") in {"checkbox", "radio"} else ""),
            }
            if tag == "select":
                self.field.update(choices=[], multiple="multiple" in a)
            if self.field["type"] in {"checkbox", "radio"}:
                self.field["checked"] = "checked" in a
            self.form["fields"].append(self.field)
            self.textarea = tag == "textarea"
        if tag == "option" and self.field is not None and "choices" in self.field:
            self.option = {"value": a.get("value"), "label": "", "selected": "selected" in a}
            self.field["choices"].append(self.option)

    def handle_data(self, data):
        if self.ignore:
            return
        if self._title:
            self.title += data
        if self.link is not None:
            self.link["label"] += data
        if self.option is not None:
            self.option["label"] += data
        if self.textarea and self.field is not None:
            self.field["value"] += data
        if self.error_depth and data.strip():
            self.errors.append(data.strip())

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.ignore:
            self.ignore -= 1
            return
        if self.ignore:
            return
        if self.error_depth:
            self.error_depth -= 1
        if tag == "title":
            self._title = False
        if tag == "a":
            self.link = None
        if tag == "form":
            self.form = None
        if tag == "option":
            if self.option is not None and self.option["value"] is None:
                self.option["value"] = self.option["label"]
            self.option = None
        if tag in {"select", "textarea", "button"}:
            self.field = None
            self.textarea = False


def public_fields(fields):
    result = []
    for field in fields:
        if field["name"] == "csrfmiddlewaretoken":
            continue
        field = dict(field)
        if field["type"] == "password" or exposure.is_redacted(field["name"]):
            field.pop("value", None)
            field.pop("choices", None)
            field["redacted"] = True
        result.append(field)
    return result


def initial_data(fields):
    data = {}
    for f in fields:
        name, kind = f["name"], f["type"]
        if (
            f["disabled"]
            or "__prefix__" in name
            or "-empty-" in name
            or kind in {"submit", "button", "reset", "file", "password"}
            or (kind in {"checkbox", "radio"} and not f["checked"])
        ):
            continue
        if kind == "select":
            choices = f["choices"]
            values = [c["value"] for c in choices if c["selected"]]
            if not values and not f["multiple"] and choices:
                values = [choices[0]["value"]]
        else:
            values = [f["value"]]
        data.setdefault(name, []).extend(values)
    return data
