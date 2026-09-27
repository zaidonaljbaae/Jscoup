# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Zaidon Aljbaae. Licensed under the MIT License; see the LICENSE file.
"""Final per-instance sanitization boundary; hooks cannot bypass it."""
from dataclasses import fields,is_dataclass
import copy,re
from itertools import islice
from urllib.parse import urlsplit,urlunsplit,parse_qsl,urlencode

_SQL_LITERAL = re.compile(r"'(?:''|\\.|[^'\\])*'|\$\$[\s\S]*?\$\$|\$([A-Za-z_][A-Za-z_0-9]*)\$[\s\S]*?\$\1\$|\b\d+(?:\.\d+)?\b")
_SQL_COMMENT = re.compile(r'/\*[\s\S]*?\*/|--[^\n]*')
def sql_shape(sql):
    sql = re.sub(r'"(?:""|[^"\\]|\\.)*"', '?', str(sql))
    return _SQL_LITERAL.sub('?', _SQL_COMMENT.sub(' ', sql))[:4000]

class EventSanitizer:
    def __init__(self,redactor):self.redactor=redactor
    def clean(self,value,depth=0):
        if depth>12:return '[truncated]'
        if is_dataclass(value):
            result=copy.copy(value)
            for f in fields(value):setattr(result,f.name,self.clean(getattr(value,f.name),depth+1))
            if type(value).__name__=='QueryRecord':
                result.sql=sql_shape(value.sql)
                result.params_preview=self.redactor.mask if value.params_preview else None
            return result
        if isinstance(value,dict):
            return {str(k):self.redactor.mask if self.redactor.is_sensitive(k) else self.clean(v,depth+1) for k,v in islice(value.items(),100)}
        if isinstance(value,(list,tuple,set)):return [self.clean(v,depth+1) for v in islice(value,1000)]
        if isinstance(value,str):
            if '://' in value and not any(c.isspace() for c in value):
                try:
                    u=urlsplit(value)
                    if u.scheme and u.netloc:
                        query=urlencode([(k,self.redactor.mask if self.redactor.is_sensitive(k) else self.redactor.scrub_text(v)) for k,v in parse_qsl(u.query,keep_blank_values=True)])
                        host=u.netloc.rsplit('@',1)[-1]
                        value=urlunsplit((u.scheme,host,u.path,query,''))
                except ValueError:return '[invalid URL]'
            return self.redactor.scrub_body(value,20000)
        if value is None or isinstance(value,(bool,int,float)):return value
        return self.redactor.scrub(value)
